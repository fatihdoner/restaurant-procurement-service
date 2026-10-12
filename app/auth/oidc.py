"""AO-01 / A0: bagimsiz OIDC erisim-token'i (JWT) dogrulayicisi.

KAPSAM: yalniz token DOGRULAMA. Bu modul hicbir rotaya, ara yazilima, DB'ye, ortam degiskenine veya
agdaki gercek bir kimlik saglayiciya bagli degildir; yapilandirma acik parametredir. `jwt` (PyJWT) yalniz
imza dogrulamasi icin kullanilir; tum talep (claim) kontrolleri bu modulde, enjekte edilebilir saatle yapilir.

KURALLAR (fail-closed):
  * Acikca tanimli TEK issuer ve TEK audience; tam metin eslesmesi, normallestirme yok.
  * Yalniz RS256 / ES256. `none`, HS*, PS*, RS384... reddedilir. Anahtar turu algoritmayla eslesmek zorundadir.
  * Anahtar yalniz yapilandirilmis, guvenilen JWKS adresinden gelir; token basliklarindaki `jku`, `x5u`,
    `jwk`, `x5c`, `crit`, `zip` reddedilir. Discovery yoktur. JWKS yonlendirmesi (redirect) izlenmez.
  * `kid` zorunlu; bilinmeyen `kid` sinirli bir yenilemeyi tetikler; yenileme basarisizsa ret (503), asla gecis.
  * Saat sapmasi <= 60 sn. Token omru ust sinirlidir. Erisim token'i zorunlu (`typ`), kimlik token'i reddedilir.
  * Token, imza, ozel anahtar ve talep degerleri HICBIR yerde loglanmaz; hata nesneleri yalniz kararli bir kod tasir.
  * Token'daki `role`, `organization`, `tenant`, `plan`, `scope`, `groups`... gibi talepler YETKI KAYNAGI DEGILDIR:
    `VerifiedPrincipal` bunlari tasimaz. Yetki kararlari (uyelik, rol, plan) bu modulun disinda ve sunucu
    tarafindadir (G0-R1).

BILEREK YAPILMAYANLAR: kullanici kaydi/girisi, oturum, iptal listesi, MFA politikasi, uyelik/rol/plan cozumu,
DB, ortam degiskeni okuma, rota. AO-01'in acik kararlari (IdP secimi, `typ` degerleri, token omru politikasi,
MFA, iptal stratejisi) ve AO-02 (DB operatoru MFA) bu modulle KAPANMAZ.
"""

import base64
import dataclasses
import ipaddress
import json
import logging
import math
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, NamedTuple, Optional, Protocol, Tuple

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

log = logging.getLogger("app.auth.oidc")

ALLOWED_ALGS = ("RS256", "ES256")
FORBIDDEN_HEADER_PARAMS = frozenset({"jku", "x5u", "jwk", "x5c", "crit", "zip"})
MAX_CLOCK_SKEW_SECONDS = 60
_MAX_EPOCH = 4102444800  # 2100-01-01
_MAX_MONOTONIC = 2 ** 53  # tam gosterilebilir tam sayi siniri
_B64URL = re.compile(r"[A-Za-z0-9_-]*")  # her kullanim fullmatch: `$` sondaki satir sonunu kabul eder
_KID = re.compile(r"[A-Za-z0-9._:~-]{1,128}")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_ID_TOKEN_MARKERS = ("nonce", "at_hash", "c_hash")

ERROR_CODES = frozenset({
    "TOKEN_MISSING", "TOKEN_TOO_LARGE", "TOKEN_MALFORMED", "TOKEN_ALG_NOT_ALLOWED", "TOKEN_HEADER_UNSAFE",
    "TOKEN_HEADER_INVALID", "TOKEN_TYPE_NOT_ACCESS", "TOKEN_KID_MISSING", "TOKEN_KID_UNKNOWN", "TOKEN_KEY_MISMATCH",
    "TOKEN_SIGNATURE_INVALID", "TOKEN_CLAIM_MISSING", "TOKEN_CLAIM_INVALID", "TOKEN_ISSUER_INVALID",
    "TOKEN_AUDIENCE_INVALID", "TOKEN_EXPIRED", "TOKEN_NOT_YET_VALID", "TOKEN_LIFETIME_EXCEEDED",
    "JWKS_UNAVAILABLE", "VERIFIER_CLOCK_INVALID", "VERIFIER_INTERNAL_ERROR",
})


class ConfigError(ValueError):
    """Gecersiz/guvensiz yapilandirma. Mesaj degeri icermez."""


class TokenError(Exception):
    """Fail-closed dogrulama hatasi. `str(e)` yalniz kararli kodu verir; token verisi tasimaz.
    http_status: 401 (token sorunu) veya 503 (dogrulayici/JWKS kullanilamiyor)."""

    def __init__(self, code: str, http_status: int = 401):
        super().__init__(code)
        self.code = code
        self.http_status = http_status

    def __repr__(self):
        return "TokenError(%r)" % self.code


class JwksFetchError(Exception):
    """JWKS getirilemedi. Ayrinti tasimaz."""


class JwksFetcher(Protocol):
    def fetch(self, uri: str, *, timeout: float, max_bytes: int) -> bytes:  # pragma: no cover - arayuz
        ...


# --------------------------------------------------------------------------- yapilandirma
def _check_text(value: Any, name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ConfigError("invalid %s" % name)
    if value != value.strip() or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ConfigError("invalid %s" % name)
    return value


def _check_int(value: Any, name: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not (lo <= value <= hi) or value != int(value):
        raise ConfigError("invalid %s" % name)
    return int(value)


def _split_url(value: str, name: str, allow_loopback_http: bool):
    parsed = urllib.parse.urlsplit(value)
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ConfigError("invalid %s" % name) from None
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http" and allow_loopback_http and host in _LOOPBACK_HOSTS:
        pass
    else:
        raise ConfigError("invalid %s" % name)
    if not host or parsed.username is not None or parsed.password is not None or parsed.fragment or "\\" in value:
        raise ConfigError("invalid %s" % name)
    return parsed, host.lower(), port


@dataclasses.dataclass(frozen=True)
class OidcConfig:
    issuer: str
    audience: str
    jwks_uri: str
    trusted_jwks_hosts: Tuple[str, ...]
    clock_skew_seconds: int = 60
    max_token_bytes: int = 8192
    max_token_lifetime_seconds: int = 3600
    require_nbf: bool = False
    accepted_typ: Tuple[str, ...] = ("at+jwt", "application/at+jwt")
    jwks_ttl_seconds: int = 3600
    jwks_stale_if_error_seconds: int = 0
    jwks_min_refresh_interval_seconds: int = 30
    jwks_failure_backoff_seconds: int = 15
    jwks_max_keys: int = 20
    jwks_max_bytes: int = 65536
    jwks_fetch_timeout_seconds: float = 3.0
    allow_insecure_loopback: bool = False  # YALNIZ TEST: loopback uzerinde http'ye izin verir

    def __post_init__(self):
        loop = self.allow_insecure_loopback is True
        if not isinstance(self.allow_insecure_loopback, bool):
            raise ConfigError("invalid allow_insecure_loopback")
        _check_text(self.audience, "audience", 256)
        _check_text(self.issuer, "issuer", 512)
        parsed_iss, _, _ = _split_url(self.issuer, "issuer", loop)
        if parsed_iss.query:
            raise ConfigError("invalid issuer")
        _check_text(self.jwks_uri, "jwks_uri", 512)
        parsed, host, port = _split_url(self.jwks_uri, "jwks_uri", loop)
        path = parsed.path
        if parsed.query or not path.startswith("/") or len(path) > 256 or ".." in path or "%" in path or "//" in path:
            raise ConfigError("invalid jwks_uri")
        if not isinstance(self.trusted_jwks_hosts, tuple) or not self.trusted_jwks_hosts:
            raise ConfigError("invalid trusted_jwks_hosts")
        trusted = set()
        for h in self.trusted_jwks_hosts:
            if not isinstance(h, str) or h != h.lower() or not h.isascii() or not (_HOST.fullmatch(h) or h in _LOOPBACK_HOSTS):
                raise ConfigError("invalid trusted_jwks_hosts")
            trusted.add(h)
        if host not in trusted:
            raise ConfigError("jwks host is not trusted")
        if host in _LOOPBACK_HOSTS:
            if not loop:
                raise ConfigError("loopback jwks host requires allow_insecure_loopback")
        else:
            is_ip = True
            try:
                ipaddress.ip_address(host)
            except ValueError:
                is_ip = False
            if is_ip:
                raise ConfigError("ip literal jwks host not allowed")
            if "." not in host or port not in (None, 443):
                raise ConfigError("invalid jwks_uri")
        _check_int(self.clock_skew_seconds, "clock_skew_seconds", 0, MAX_CLOCK_SKEW_SECONDS)
        _check_int(self.max_token_bytes, "max_token_bytes", 256, 16384)
        _check_int(self.max_token_lifetime_seconds, "max_token_lifetime_seconds", 60, 86400)
        _check_int(self.jwks_ttl_seconds, "jwks_ttl_seconds", 60, 86400)
        _check_int(self.jwks_stale_if_error_seconds, "jwks_stale_if_error_seconds", 0, 86400)
        _check_int(self.jwks_min_refresh_interval_seconds, "jwks_min_refresh_interval_seconds", 1, 3600)
        _check_int(self.jwks_failure_backoff_seconds, "jwks_failure_backoff_seconds", 1, 300)
        _check_int(self.jwks_max_keys, "jwks_max_keys", 1, 50)
        _check_int(self.jwks_max_bytes, "jwks_max_bytes", 1024, 262144)
        if isinstance(self.jwks_fetch_timeout_seconds, bool) or not isinstance(self.jwks_fetch_timeout_seconds, (int, float)) \
                or not (0.1 <= self.jwks_fetch_timeout_seconds <= 10):
            raise ConfigError("invalid jwks_fetch_timeout_seconds")
        if not isinstance(self.require_nbf, bool):
            raise ConfigError("invalid require_nbf")
        if not isinstance(self.accepted_typ, tuple) or not self.accepted_typ or any(
                not isinstance(t, str) or not t or t != t.lower() or len(t) > 64 or " " in t for t in self.accepted_typ):
            raise ConfigError("invalid accepted_typ")


# --------------------------------------------------------------------------- varsayilan JWKS getirici
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # yonlendirme izlenmez -> HTTPError


class HttpsJwksFetcher:
    """Standart kutuphane getiricisi: yonlendirme yok, ortam proxy'si yok, zaman asimi ve boyut siniri var.
    Testler bunun yerine sahte getirici enjekte eder; gercek agda cagrilmaz."""

    def __init__(self, allow_insecure_loopback: bool = False):
        self._allow_http = bool(allow_insecure_loopback)
        opener = urllib.request.OpenerDirector()
        opener.add_handler(urllib.request.ProxyHandler({}))
        opener.add_handler(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        if self._allow_http:
            opener.add_handler(urllib.request.HTTPHandler())
        opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
        opener.add_handler(_NoRedirect())
        opener.add_handler(urllib.request.HTTPErrorProcessor())
        self._opener = opener

    def fetch(self, uri: str, *, timeout: float, max_bytes: int) -> bytes:
        try:
            scheme = urllib.parse.urlsplit(uri).scheme
            if scheme != "https" and not (scheme == "http" and self._allow_http):
                raise JwksFetchError("scheme")
            req = urllib.request.Request(uri, headers={"Accept": "application/json", "User-Agent": "mirpua-oidc-verifier/a0"}, method="GET")
            with self._opener.open(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise JwksFetchError("status")
                ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if ctype not in ("application/json", "application/jwk-set+json"):
                    raise JwksFetchError("content-type")
                clen = resp.headers.get("Content-Length")
                if clen is not None and (not clen.isdigit() or int(clen) > max_bytes):
                    raise JwksFetchError("size")
                data = resp.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise JwksFetchError("size")
                return data
        except JwksFetchError:
            raise
        except Exception:
            raise JwksFetchError("fetch failed") from None


# --------------------------------------------------------------------------- JWKS ayristirma
class _Key(NamedTuple):
    alg: str
    key: Any


class _JwksInvalid(Exception):
    pass


_PRIVATE_JWK_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


def _parse_jwks(raw: Any, cfg: OidcConfig) -> Dict[str, _Key]:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > cfg.jwks_max_bytes:
        raise _JwksInvalid("size")
    try:
        doc = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, RecursionError):
        raise _JwksInvalid("json") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list) or len(doc["keys"]) > cfg.jwks_max_keys:
        raise _JwksInvalid("shape")
    keys: Dict[str, _Key] = {}
    for jwk in doc["keys"]:
        if not isinstance(jwk, dict):
            raise _JwksInvalid("entry")
        if _PRIVATE_JWK_PARAMS & set(jwk):
            raise _JwksInvalid("private material")  # JWKS ozel anahtar tasiyamaz: tum belge reddedilir
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not _KID.fullmatch(kid):
            continue
        if kid in keys:
            raise _JwksInvalid("duplicate kid")
        use, ops, kty = jwk.get("use"), jwk.get("key_ops"), jwk.get("kty")
        if use is not None and use != "sig":
            continue
        if ops is not None and (not isinstance(ops, list) or "verify" not in ops):
            continue
        try:
            if kty == "RSA":
                if jwk.get("alg") not in (None, "RS256"):
                    continue
                public = RSAAlgorithm.from_jwk(json.dumps(jwk))
                if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
                    continue
                keys[kid] = _Key("RS256", public)
            elif kty == "EC":
                if jwk.get("alg") not in (None, "ES256") or jwk.get("crv") != "P-256":
                    continue
                public = ECAlgorithm.from_jwk(json.dumps(jwk))
                if not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != "secp256r1":
                    continue
                keys[kid] = _Key("ES256", public)
        except Exception:
            continue  # kullanilamayan tek anahtar atlanir; hic kullanilabilir anahtar yoksa belge reddedilir
    if not keys:
        raise _JwksInvalid("no usable key")
    return keys


# --------------------------------------------------------------------------- sonuc nesnesi
@dataclasses.dataclass(frozen=True)
class VerifiedPrincipal:
    """Yalnizca KIMLIK ve kimlik-dogrulama baglami olgulari. Yetki (rol/kurum/tenant/plan) icermez."""

    issuer: str
    subject: str
    audience: Tuple[str, ...]
    issued_at: float
    expires_at: float
    not_before: Optional[float] = None
    token_id: Optional[str] = None
    session_id: Optional[str] = None
    auth_time: Optional[float] = None
    acr: Optional[str] = None
    amr: Tuple[str, ...] = ()

    def __repr__(self):  # `subject`, `token_id`, `session_id` bilerek yazilmaz
        return "VerifiedPrincipal(issuer=%r, expires_at=%r)" % (self.issuer, self.expires_at)


def extract_bearer_token(authorization_header: Optional[str], max_bytes: int = 8192) -> str:
    """`Authorization: Bearer <token>` -> token. Katidir: tek bosluk, bosluksuz token."""
    if authorization_header is None or authorization_header == "":
        raise TokenError("TOKEN_MISSING")
    if not isinstance(authorization_header, str):
        raise TokenError("TOKEN_MALFORMED")
    if len(authorization_header) > max_bytes + 7:
        raise TokenError("TOKEN_TOO_LARGE")
    scheme, sep, token = authorization_header.partition(" ")
    if sep != " " or scheme.lower() != "bearer" or not token or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token):
        raise TokenError("TOKEN_MALFORMED")
    return token


# --------------------------------------------------------------------------- dogrulayici
def _decode_header(h64: str) -> dict:
    """Baslik kendi kodumuzla cozulur: hata kodlari PyJWT'nin on-dogrulamalarina bagli kalmaz. RecursionError
    (asiri ic ice JSON) verify() icinde TOKEN_MALFORMED'a cevrilir."""
    try:
        header = json.loads(base64.urlsafe_b64decode(h64 + "=" * (-len(h64) % 4)).decode("utf-8"))
    except (ValueError, UnicodeError):  # binascii.Error ve JSONDecodeError dahil
        raise TokenError("TOKEN_MALFORMED") from None
    if not isinstance(header, dict):
        raise TokenError("TOKEN_MALFORMED")
    return header


def _num(value: Any) -> float:
    """NumericDate. Aralik, float'a CEVIRMEDEN once denetlenir: `float(10**400)` OverflowError verirdi (bu bir veri hatasidir, 401)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TokenError("TOKEN_CLAIM_INVALID")
    if isinstance(value, float) and not math.isfinite(value):
        raise TokenError("TOKEN_CLAIM_INVALID")
    if value < 0 or value > _MAX_EPOCH:  # int/float karsilastirmasi tam ve tasmasizdir
        raise TokenError("TOKEN_CLAIM_INVALID")
    return float(value)


def _reading(read: Callable[[], Any], lo: float, hi: float) -> float:
    """Enjekte edilen saatin okumasi. Guvenilmez saat (NaN/Inf, aralik disi, sayi olmayan, istisna) = dogrulayici sorunu:
    karsilastirmalar NaN ile hep False olup suresi dolmus jetonu kabul ettirirdi. Hata kodu sabittir; deger/jeton icermez."""
    try:
        v = read()
    except Exception:
        raise TokenError("VERIFIER_CLOCK_INVALID", 503) from None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)) or v < lo or v > hi:
        raise TokenError("VERIFIER_CLOCK_INVALID", 503)
    return float(v)


def _opt_str(payload: dict, name: str, max_len: int) -> Optional[str]:
    if name not in payload:
        return None
    v = payload[name]
    if not isinstance(v, str) or not v or len(v) > max_len or not v.isprintable():
        raise TokenError("TOKEN_CLAIM_INVALID")
    return v


class OidcAccessTokenVerifier:
    def __init__(self, config: OidcConfig, fetcher: Optional[JwksFetcher] = None,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(config, OidcConfig):
            raise ConfigError("invalid config")
        self._cfg = config
        self._fetcher = fetcher if fetcher is not None else HttpsJwksFetcher(config.allow_insecure_loopback)
        self._clock = clock
        self._mono = monotonic
        self._lock = threading.Lock()
        self._keys: Dict[str, _Key] = {}
        self._loaded_at: Optional[float] = None
        self._next_attempt_at = 0.0
        self._consecutive_failures = 0

    def __repr__(self):
        return "OidcAccessTokenVerifier(<%d cached keys>)" % len(self._keys)

    # ---- genel arayuz
    def verify(self, token: str) -> VerifiedPrincipal:
        try:
            return self._verify(token)
        except TokenError as exc:
            log.info("oidc_verify_denied code=%s", exc.code)
            raise
        except (RecursionError, ValueError, UnicodeError):
            log.info("oidc_verify_denied code=TOKEN_MALFORMED")
            raise TokenError("TOKEN_MALFORMED") from None
        except Exception:
            log.error("oidc_verify_internal_error")
            raise TokenError("VERIFIER_INTERNAL_ERROR", 503) from None

    # ---- adimlar
    def _verify(self, token: str) -> VerifiedPrincipal:
        cfg = self._cfg
        header = self._parse_header(token)
        alg, kid = header["alg"], header["kid"]
        entry = self._get_key(kid)
        if entry.alg != alg:
            raise TokenError("TOKEN_KEY_MISMATCH")
        try:
            payload = jwt.decode(token, entry.key, algorithms=[alg], options={
                "verify_signature": True, "verify_exp": False, "verify_nbf": False, "verify_iat": False,
                "verify_aud": False, "verify_iss": False, "verify_sub": False, "verify_jti": False,
                "require": [], "enforce_minimum_key_length": True})
        except jwt.InvalidAlgorithmError:
            raise TokenError("TOKEN_ALG_NOT_ALLOWED") from None
        except jwt.InvalidSignatureError:  # DecodeError'in alt sinifidir: once o yakalanmali
            raise TokenError("TOKEN_SIGNATURE_INVALID") from None
        except jwt.DecodeError:
            raise TokenError("TOKEN_MALFORMED") from None
        except jwt.PyJWTError:
            raise TokenError("TOKEN_SIGNATURE_INVALID") from None
        return self._validate_claims(payload, _reading(self._clock, 0, _MAX_EPOCH))

    def _parse_header(self, token: Any) -> dict:
        cfg = self._cfg
        if not isinstance(token, str):
            raise TokenError("TOKEN_MALFORMED")
        if not token:
            raise TokenError("TOKEN_MISSING")
        if len(token) > cfg.max_token_bytes:
            raise TokenError("TOKEN_TOO_LARGE")
        if not token.isascii() or token.count(".") != 2:
            raise TokenError("TOKEN_MALFORMED")
        h64, p64, s64 = token.split(".")
        if not (_B64URL.fullmatch(h64) and _B64URL.fullmatch(p64) and _B64URL.fullmatch(s64)) or len(h64) < 2 or len(p64) < 2:
            raise TokenError("TOKEN_MALFORMED")
        header = _decode_header(h64)
        if FORBIDDEN_HEADER_PARAMS & set(header):
            raise TokenError("TOKEN_HEADER_UNSAFE")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in ALLOWED_ALGS:
            raise TokenError("TOKEN_ALG_NOT_ALLOWED")
        if not s64:
            raise TokenError("TOKEN_MALFORMED")
        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower() not in cfg.accepted_typ:
            raise TokenError("TOKEN_TYPE_NOT_ACCESS")
        if "kid" not in header or header["kid"] is None:
            raise TokenError("TOKEN_KID_MISSING")
        kid = header["kid"]
        if not isinstance(kid, str) or not _KID.fullmatch(kid):
            raise TokenError("TOKEN_HEADER_INVALID")
        return header

    def _validate_claims(self, payload: Any, now: float) -> VerifiedPrincipal:
        cfg = self._cfg
        skew = cfg.clock_skew_seconds
        if not isinstance(payload, dict):
            raise TokenError("TOKEN_MALFORMED")
        for name in ("iss", "sub", "aud", "exp", "iat"):
            if name not in payload or payload[name] is None:
                raise TokenError("TOKEN_CLAIM_MISSING")
        if cfg.require_nbf and payload.get("nbf") is None:
            raise TokenError("TOKEN_CLAIM_MISSING")
        iss = payload["iss"]
        if not isinstance(iss, str):
            raise TokenError("TOKEN_CLAIM_INVALID")
        if iss != cfg.issuer:
            raise TokenError("TOKEN_ISSUER_INVALID")
        aud = payload["aud"]
        if isinstance(aud, str):
            auds: Tuple[str, ...] = (aud,)
        elif isinstance(aud, list) and 0 < len(aud) <= 8 and all(isinstance(a, str) and 0 < len(a) <= 256 for a in aud):
            auds = tuple(aud)
        else:
            raise TokenError("TOKEN_CLAIM_INVALID")
        if cfg.audience not in auds:
            raise TokenError("TOKEN_AUDIENCE_INVALID")
        sub = payload["sub"]
        if not isinstance(sub, str) or not (0 < len(sub) <= 255) or not sub.isascii() or not sub.isprintable() or any(c.isspace() for c in sub):
            raise TokenError("TOKEN_CLAIM_INVALID")
        exp, iat = _num(payload["exp"]), _num(payload["iat"])
        nbf = _num(payload["nbf"]) if payload.get("nbf") is not None else None
        if exp <= iat:
            raise TokenError("TOKEN_CLAIM_INVALID")
        if exp - iat > cfg.max_token_lifetime_seconds:
            raise TokenError("TOKEN_LIFETIME_EXCEEDED")
        if exp <= now - skew:
            raise TokenError("TOKEN_EXPIRED")
        if iat > now + skew or (nbf is not None and nbf > now + skew):
            raise TokenError("TOKEN_NOT_YET_VALID")
        for marker in _ID_TOKEN_MARKERS:
            if marker in payload:
                raise TokenError("TOKEN_TYPE_NOT_ACCESS")
        if "token_use" in payload and payload["token_use"] != "access":
            raise TokenError("TOKEN_TYPE_NOT_ACCESS")
        auth_time = _num(payload["auth_time"]) if payload.get("auth_time") is not None else None
        if auth_time is not None and auth_time > now + skew:
            raise TokenError("TOKEN_NOT_YET_VALID")
        amr_raw = payload.get("amr")
        if amr_raw is None:
            amr: Tuple[str, ...] = ()
        elif isinstance(amr_raw, list) and len(amr_raw) <= 16 and all(isinstance(a, str) and 0 < len(a) <= 64 and a.isprintable() for a in amr_raw):
            amr = tuple(amr_raw)
        else:
            raise TokenError("TOKEN_CLAIM_INVALID")
        return VerifiedPrincipal(
            issuer=iss, subject=sub, audience=auds, issued_at=iat, expires_at=exp, not_before=nbf,
            token_id=_opt_str(payload, "jti", 256), session_id=_opt_str(payload, "sid", 256),
            auth_time=auth_time, acr=_opt_str(payload, "acr", 128), amr=amr)

    # ---- JWKS onbellegi
    def _get_key(self, kid: str) -> _Key:
        cfg = self._cfg
        with self._lock:
            now = _reading(self._mono, 0, _MAX_MONOTONIC)
            age = None if self._loaded_at is None else now - self._loaded_at
            fresh = age is not None and age <= cfg.jwks_ttl_seconds
            if fresh:
                hit = self._keys.get(kid)
                if hit is not None:
                    return hit
            may_serve_stale = age is not None and age <= cfg.jwks_ttl_seconds + cfg.jwks_stale_if_error_seconds
            if now < self._next_attempt_at:  # yenileme denemesi yasak (aralik veya basarisizlik geri cekilmesi): ag yok
                if fresh:
                    raise TokenError("TOKEN_KID_UNKNOWN")
                if may_serve_stale and kid in self._keys:
                    return self._keys[kid]
                raise TokenError("JWKS_UNAVAILABLE", 503)
            if self._refresh_locked(now):
                hit = self._keys.get(kid)
                if hit is not None:
                    return hit
                raise TokenError("TOKEN_KID_UNKNOWN")
            if may_serve_stale and kid in self._keys:
                return self._keys[kid]
            raise TokenError("JWKS_UNAVAILABLE", 503)

    def _refresh_locked(self, now: float) -> bool:
        cfg = self._cfg
        try:
            raw = self._fetcher.fetch(cfg.jwks_uri, timeout=cfg.jwks_fetch_timeout_seconds, max_bytes=cfg.jwks_max_bytes)
            keys = _parse_jwks(raw, cfg)
        except _JwksInvalid:
            return self._refresh_failed(now, "invalid")
        except Exception:
            return self._refresh_failed(now, "fetch")
        self._keys = keys
        self._loaded_at = now
        self._consecutive_failures = 0
        self._next_attempt_at = now + cfg.jwks_min_refresh_interval_seconds
        log.info("oidc_jwks_refreshed keys=%d", len(keys))
        return True

    def _refresh_failed(self, now: float, reason: str) -> bool:
        cfg = self._cfg
        self._consecutive_failures += 1
        delay = min(cfg.jwks_failure_backoff_seconds * (2 ** (self._consecutive_failures - 1)), 300)
        self._next_attempt_at = now + delay
        log.warning("oidc_jwks_refresh_failed reason=%s failures=%d", reason, self._consecutive_failures)
        return False
