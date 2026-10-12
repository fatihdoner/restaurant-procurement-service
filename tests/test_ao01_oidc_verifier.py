"""AO-01 / A0 -- OIDC erisim-token'i dogrulayici testleri.

Hicbir gercek kimlik saglayiciya, internete, DB'ye veya Railway'e baglanmaz. Anahtarlar test icin uretilir;
JWKS sahte getirici ile verilir; saat sahte saattir. Varsayilan HTTP getiricisi yalnizca 127.0.0.1 uzerindeki
gecici bir yerel sunucuya karsi sinanir.

Calistirma (repo kokunden, PyJWT[crypto] kurulu izole venv ile):  python -m unittest tests.test_ao01_oidc_verifier -v
"""

import base64
import contextlib
import dataclasses
import hashlib
import hmac
import http.server
import io
import json
import logging
import os
import sys
import threading
import time
import traceback
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import jwt  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from jwt.algorithms import ECAlgorithm, RSAAlgorithm  # noqa: E402

from app.auth import oidc  # noqa: E402

ISS = "https://idp.example.test/"
AUD = "api://mirpua-test"
HOST = "idp.example.test"
JWKS_URI = "https://idp.example.test/.well-known/jwks.json"
T0 = 1_800_000_000.0
DEL = object()

BASE_CFG = dict(issuer=ISS, audience=AUD, jwks_uri=JWKS_URI, trusted_jwks_hosts=(HOST,))


# --------------------------------------------------------------------------- anahtarlar ve belirteclerin uretimi
def gen_rsa(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


RSA_A, RSA_B, ROGUE = gen_rsa(), gen_rsa(), gen_rsa()
EC_A, EC_B = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())


def jwk_rsa(pub, kid, **extra):
    d = json.loads(RSAAlgorithm.to_jwk(pub))
    d.update({"kid": kid, "use": "sig", "alg": "RS256"})
    d.update(extra)
    return {k: v for k, v in d.items() if v is not DEL}


def jwk_ec(pub, kid, **extra):
    d = json.loads(ECAlgorithm.to_jwk(pub))
    d.update({"kid": kid, "use": "sig", "alg": "ES256"})
    d.update(extra)
    return {k: v for k, v in d.items() if v is not DEL}


def default_doc():
    return {"keys": [jwk_rsa(RSA_A.public_key(), "rsa-a"), jwk_ec(EC_A.public_key(), "ec-a")]}


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(alg, key, data):
    if alg == "RS256":
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if alg == "ES256":
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise AssertionError("test helper: unsupported alg")


def claims(now=T0, **over):
    c = {"iss": ISS, "sub": "user-123", "aud": AUD, "iat": now - 10, "exp": now + 300, "nbf": now - 10, "jti": "jti-1"}
    c.update(over)
    return {k: v for k, v in c.items() if v is not DEL}


def forge(header, payload, key=None, alg=None, sig=None):
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode())
    if sig is None:
        sig = b64u(sign(alg or header["alg"], key, (h + "." + p).encode()))
    return h + "." + p + "." + sig


def mint(key=RSA_A, alg="RS256", kid="rsa-a", now=T0, headers=None, **over):
    header = {"alg": alg, "typ": "at+jwt", "kid": kid}
    header.update(headers or {})
    header = {k: v for k, v in header.items() if v is not DEL}
    return forge(header, claims(now, **over), key, alg)


class Clk:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeFetcher:
    def __init__(self, doc=None):
        self.doc = default_doc() if doc is None else doc
        self.calls = 0
        self.uris = []
        self.fail = None
        self.delay = 0.0
        self._lock = threading.Lock()

    def fetch(self, uri, *, timeout, max_bytes):
        with self._lock:
            self.calls += 1
            self.uris.append(uri)
        if self.delay:
            time.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        d = self.doc
        if isinstance(d, (bytes, bytearray)) or not isinstance(d, (dict, list)):
            return d
        return json.dumps(d).encode()


def make(doc=None, **cfg):
    clk = Clk()
    fetcher = FakeFetcher(doc)
    verifier = oidc.OidcAccessTokenVerifier(oidc.OidcConfig(**{**BASE_CFG, **cfg}), fetcher=fetcher, clock=clk, monotonic=clk)
    return verifier, clk, fetcher


class Base(unittest.TestCase):
    def deny(self, verifier, token, code, status=401):
        with self.assertRaises(oidc.TokenError) as cm:
            verifier.verify(token)
        self.assertEqual(cm.exception.code, code)
        self.assertEqual(cm.exception.http_status, status)
        self.assertEqual(str(cm.exception), code)
        self.assertIn(code, oidc.ERROR_CODES)
        return cm.exception


# --------------------------------------------------------------------------- C1: yapilandirma
class C1_Config(Base):
    def cfg(self, **over):
        return oidc.OidcConfig(**{**BASE_CFG, **over})

    def test_valid_and_frozen(self):
        c = self.cfg()
        self.assertEqual((c.clock_skew_seconds, c.jwks_stale_if_error_seconds, c.allow_insecure_loopback), (60, 0, False))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.issuer = "https://evil.test/"

    def test_issuer_must_be_a_plain_https_url(self):
        for bad in ("", "idp.example.test", "http://idp.example.test/", "https://idp.example.test/?x=1", "https://u@idp.example.test/",
                    " https://idp.example.test/", "https://idp.example.test/ ", "https://idp.example.test/#a", "https://" + "a" * 600 + "/", None, 5):
            with self.subTest(issuer=bad), self.assertRaises(oidc.ConfigError):
                self.cfg(issuer=bad)

    def test_audience_must_be_a_single_clean_string(self):
        for bad in ("", " x", "a b", "x" * 300, None, ["a"], 5, "a\nb"):
            with self.subTest(audience=bad), self.assertRaises(oidc.ConfigError):
                self.cfg(audience=bad)

    def test_untrusted_or_unsafe_jwks_addresses_are_refused(self):
        bad = ["http://idp.example.test/jwks.json", "https://evil.example/jwks.json", "https://203.0.113.5/jwks.json",
               "https://u:p@idp.example.test/jwks.json", "https://idp.example.test/jwks.json#f", "https://idp.example.test/jwks.json?a=1",
               "https://idp.example.test:8443/jwks.json", "https://idp.example.test/../jwks.json", "https://idp.example.test/%2e%2e/jwks.json",
               "https://idp.example.test//jwks.json", "ftp://idp.example.test/jwks.json", "https:///jwks.json", "https://localhost/jwks.json",
               "https://127.0.0.1/jwks.json", "https://idp.example.test\\@evil.test/jwks.json", "javascript:alert(1)", "idp.example.test/jwks.json", "",
               "https://idp.example.test/" + "a" * 300]
        for uri in bad:
            with self.subTest(uri=uri), self.assertRaises(oidc.ConfigError):
                self.cfg(jwks_uri=uri, trusted_jwks_hosts=(HOST, "203.0.113.5", "localhost", "127.0.0.1"))

    def test_trusted_hosts_shape(self):
        for bad in ((), [HOST], ("IDP.example.test",), ("https://idp.example.test",), ("idp.example.test/x",), (5,), ("",)):
            with self.subTest(hosts=bad), self.assertRaises(oidc.ConfigError):
                self.cfg(trusted_jwks_hosts=bad)

    def test_numeric_limits_are_enforced(self):
        bad = dict(clock_skew_seconds=(61, -1, True, 1.5, "60"), max_token_bytes=(100, 20000), max_token_lifetime_seconds=(0, 90000),
                   jwks_ttl_seconds=(10, 90000), jwks_stale_if_error_seconds=(-1, 90000), jwks_min_refresh_interval_seconds=(0, 4000),
                   jwks_failure_backoff_seconds=(0, 301), jwks_max_keys=(0, 51), jwks_max_bytes=(100, 300000), jwks_fetch_timeout_seconds=(0, 11, True))
        for name, values in bad.items():
            for v in values:
                with self.subTest(name=name, value=v), self.assertRaises(oidc.ConfigError):
                    self.cfg(**{name: v})
        self.cfg(clock_skew_seconds=0)
        self.cfg(clock_skew_seconds=60)

    def test_accepted_typ_shape(self):
        for bad in ((), ("AT+JWT",), ("a b",), "at+jwt", (5,)):
            with self.subTest(typ=bad), self.assertRaises(oidc.ConfigError):
                self.cfg(accepted_typ=bad)

    def test_loopback_http_only_with_the_explicit_test_flag(self):
        uri = "http://127.0.0.1:8765/jwks.json"
        with self.assertRaises(oidc.ConfigError):
            self.cfg(jwks_uri=uri, trusted_jwks_hosts=("127.0.0.1",))
        c = self.cfg(jwks_uri=uri, trusted_jwks_hosts=("127.0.0.1",), allow_insecure_loopback=True)
        self.assertTrue(c.allow_insecure_loopback)
        with self.assertRaises(oidc.ConfigError):  # bayrak loopback disina http acmaz
            self.cfg(jwks_uri="http://idp.example.test/jwks.json", allow_insecure_loopback=True)
        with self.assertRaises(oidc.ConfigError):
            self.cfg(allow_insecure_loopback="yes")

    def test_verifier_requires_a_config_object(self):
        with self.assertRaises(oidc.ConfigError):
            oidc.OidcAccessTokenVerifier({"issuer": ISS})


# --------------------------------------------------------------------------- V1: olumlu yol
class V1_HappyPath(Base):
    def test_rs256_and_es256_verify_and_expose_only_identity_facts(self):
        v, clk, f = make()
        p = v.verify(mint(sid="sid-1", auth_time=T0 - 60, acr="urn:mfa", amr=["pwd", "otp"]))
        self.assertEqual((p.issuer, p.subject, p.audience, p.issued_at, p.expires_at, p.not_before), (ISS, "user-123", (AUD,), T0 - 10, T0 + 300, T0 - 10))
        self.assertEqual((p.token_id, p.session_id, p.auth_time, p.acr, p.amr), ("jti-1", "sid-1", T0 - 60, "urn:mfa", ("pwd", "otp")))
        e = v.verify(mint(EC_A, "ES256", "ec-a", sub="user-es"))
        self.assertEqual(e.subject, "user-es")

    def test_interoperates_with_tokens_minted_by_pyjwt_itself(self):
        v, clk, f = make()
        tok = jwt.encode(claims(), RSA_A, algorithm="RS256", headers={"kid": "rsa-a", "typ": "at+jwt"})
        self.assertEqual(v.verify(tok).subject, "user-123")
        tok = jwt.encode(claims(), EC_A, algorithm="ES256", headers={"kid": "ec-a", "typ": "at+jwt"})
        self.assertEqual(v.verify(tok).subject, "user-123")

    def test_audience_list_containing_ours_is_accepted(self):
        v, clk, f = make()
        self.assertEqual(v.verify(mint(aud=["other", AUD])).audience, ("other", AUD))

    def test_nbf_optional_unless_required(self):
        v, clk, f = make()
        self.assertIsNone(v.verify(mint(nbf=DEL)).not_before)
        v2, _, _ = make(require_nbf=True)
        self.deny(v2, mint(nbf=DEL), "TOKEN_CLAIM_MISSING")
        self.assertEqual(v2.verify(mint()).subject, "user-123")

    def test_typ_comparison_is_case_insensitive_and_accepts_the_rfc9068_forms(self):
        v, clk, f = make()
        for typ in ("at+jwt", "AT+JWT", "application/at+jwt"):
            self.assertEqual(v.verify(mint(headers={"typ": typ})).subject, "user-123", typ)

    def test_kid_selects_the_right_key_among_several(self):
        doc = {"keys": [jwk_rsa(RSA_A.public_key(), "rsa-a"), jwk_rsa(RSA_B.public_key(), "rsa-b"), jwk_ec(EC_A.public_key(), "ec-a"), jwk_ec(EC_B.public_key(), "ec-b")]}
        v, clk, f = make(doc)
        for key, alg, kid in ((RSA_A, "RS256", "rsa-a"), (RSA_B, "RS256", "rsa-b"), (EC_A, "ES256", "ec-a"), (EC_B, "ES256", "ec-b")):
            self.assertEqual(v.verify(mint(key, alg, kid)).subject, "user-123", kid)
        self.deny(v, mint(RSA_B, "RS256", "rsa-a"), "TOKEN_SIGNATURE_INVALID")

    def test_principal_is_immutable_and_its_repr_hides_the_subject(self):
        v, clk, f = make()
        p = v.verify(mint(sub="SENSITIVE-SUBJECT-1", sid="SENSITIVE-SID", jti="SENSITIVE-JTI"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            p.subject = "x"
        for secret in ("SENSITIVE-SUBJECT-1", "SENSITIVE-SID", "SENSITIVE-JTI"):
            self.assertNotIn(secret, repr(p))
            self.assertNotIn(secret, str(p))


# --------------------------------------------------------------------------- V2: baslik saldirilari
class V2_HeaderAttacks(Base):
    def setUp(self):
        self.v, self.clk, self.f = make()

    def test_alg_none_in_every_spelling(self):
        for alg in ("none", "None", "NONE", "nOnE"):
            for sig in ("", "AAAA", b64u(b"x" * 64)):
                tok = forge({"alg": alg, "typ": "at+jwt", "kid": "rsa-a"}, claims(), sig=sig)
                with self.subTest(alg=alg, sig=sig):
                    self.deny(self.v, tok, "TOKEN_ALG_NOT_ALLOWED")

    def test_hs_rs_key_confusion_using_the_public_key_as_hmac_secret(self):
        pem = RSA_A.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        for alg, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
            h = b64u(json.dumps({"alg": alg, "typ": "at+jwt", "kid": "rsa-a"}).encode())
            p = b64u(json.dumps(claims()).encode())
            tok = h + "." + p + "." + b64u(hmac.new(pem, (h + "." + p).encode(), digest).digest())
            with self.subTest(alg=alg):
                self.deny(self.v, tok, "TOKEN_ALG_NOT_ALLOWED")

    def test_every_other_algorithm_is_refused(self):
        for alg in ("RS384", "RS512", "PS256", "PS384", "ES384", "ES512", "ES256K", "EdDSA", "rs256", "es256", "RS256 ", "", None, 123, ["RS256"]):
            tok = forge({"alg": alg, "typ": "at+jwt", "kid": "rsa-a"}, claims(), sig="AAAA")
            with self.subTest(alg=alg):
                self.deny(self.v, tok, "TOKEN_ALG_NOT_ALLOWED")
        self.deny(self.v, forge({"typ": "at+jwt", "kid": "rsa-a"}, claims(), sig="AAAA"), "TOKEN_ALG_NOT_ALLOWED")

    def test_key_type_must_match_the_algorithm(self):
        self.deny(self.v, mint(EC_A, "ES256", "rsa-a"), "TOKEN_KEY_MISMATCH")
        self.deny(self.v, mint(RSA_A, "RS256", "ec-a"), "TOKEN_KEY_MISMATCH")

    def test_kid_is_mandatory_and_must_be_well_formed(self):
        self.deny(self.v, mint(headers={"kid": DEL}), "TOKEN_KID_MISSING")
        self.deny(self.v, mint(headers={"kid": None}), "TOKEN_KID_MISSING")
        for bad in (1, ["rsa-a"], "../x", "a b", "a" * 129, "", "kid\n"):
            with self.subTest(kid=bad):
                self.deny(self.v, mint(headers={"kid": bad}), "TOKEN_HEADER_INVALID")

    def test_url_and_embedded_key_headers_are_never_followed(self):
        attacker = gen_rsa()
        attacker_jwk = json.loads(RSAAlgorithm.to_jwk(attacker.public_key()))
        cases = {"jku": "https://evil.example/jwks.json", "x5u": "https://evil.example/cert.pem", "jwk": attacker_jwk,
                 "x5c": ["MIIB"], "crit": ["exp"], "zip": "DEF"}
        for name, value in cases.items():
            tok = forge({"alg": "RS256", "typ": "at+jwt", "kid": "rsa-a", name: value}, claims(), attacker, "RS256")
            with self.subTest(header=name):
                self.deny(self.v, tok, "TOKEN_HEADER_UNSAFE")
        self.assertEqual(self.f.calls, 0)  # reddedildi, hicbir getirme yapilmadi
        self.assertEqual(set(self.f.uris), set())

    def test_a_token_signed_by_an_attacker_with_an_embedded_jwk_never_reaches_signature_verification(self):
        attacker = gen_rsa()
        tok = forge({"alg": "RS256", "typ": "at+jwt", "kid": "evil", "jwk": json.loads(RSAAlgorithm.to_jwk(attacker.public_key()))}, claims(), attacker, "RS256")
        self.deny(self.v, tok, "TOKEN_HEADER_UNSAFE")

    def test_only_access_tokens_pass_typ(self):
        self.deny(self.v, mint(headers={"typ": DEL}), "TOKEN_TYPE_NOT_ACCESS")
        for typ in ("JWT", "id+jwt", "jwt", "", None, 5, "at+jwt ", "application/jwt"):
            with self.subTest(typ=typ):
                self.deny(self.v, mint(headers={"typ": typ}), "TOKEN_TYPE_NOT_ACCESS")

    def test_wrong_segment_counts_are_malformed(self):
        good = mint()
        h, p, s = good.split(".")
        for tok in (h, h + "." + p, h + "." + p + "." + s + "." + s, h + "." + p + "." + s + "." + s + "." + s, "." + p + "." + s, h + "..", ".."):
            with self.subTest(tok=tok[:20]):
                self.deny(self.v, tok, "TOKEN_MALFORMED")


# --------------------------------------------------------------------------- V3: imza
class V3_Signature(Base):
    def setUp(self):
        self.v, self.clk, self.f = make()

    def test_tampered_signature_payload_or_signer(self):
        h, p, s = mint().split(".")
        flipped = ("A" if s[0] != "A" else "B") + s[1:]
        self.deny(self.v, h + "." + p + "." + flipped, "TOKEN_SIGNATURE_INVALID")
        p2 = b64u(json.dumps(claims(sub="admin")).encode())
        self.deny(self.v, h + "." + p2 + "." + s, "TOKEN_SIGNATURE_INVALID")
        self.deny(self.v, mint(ROGUE, "RS256", "rsa-a"), "TOKEN_SIGNATURE_INVALID")  # ayni kid, baska anahtar
        self.deny(self.v, mint(EC_B, "ES256", "ec-a"), "TOKEN_SIGNATURE_INVALID")

    def test_truncated_and_empty_signatures(self):
        h, p, s = mint().split(".")
        for cut in (len(s) // 2, 10, 1):  # kirpilmis Base64: dolgu gecersizse MALFORMED, cozulurse imza hatasi (anahtara bagli)
            with self.assertRaises(oidc.TokenError) as cm:
                self.v.verify(h + "." + p + "." + s[:cut])
            self.assertIn(cm.exception.code, ("TOKEN_SIGNATURE_INVALID", "TOKEN_MALFORMED"))
            self.assertEqual(cm.exception.http_status, 401)
        self.deny(self.v, h + "." + p + ".", "TOKEN_MALFORMED")

    def test_es256_signature_must_be_the_raw_form_not_der(self):
        h = {"alg": "ES256", "typ": "at+jwt", "kid": "ec-a"}
        hh, pp = b64u(json.dumps(h).encode()), b64u(json.dumps(claims()).encode())
        der = EC_A.sign((hh + "." + pp).encode(), ec.ECDSA(hashes.SHA256()))
        self.deny(self.v, hh + "." + pp + "." + b64u(der), "TOKEN_SIGNATURE_INVALID")

    def test_signature_is_checked_before_any_claim_is_trusted(self):
        h, p, s = mint(exp=T0 - 99999).split(".")  # suresi cok gecmis
        self.deny(self.v, h + "." + p + "." + ("A" if s[0] != "A" else "B") + s[1:], "TOKEN_SIGNATURE_INVALID")
        bad_iss = forge({"alg": "RS256", "typ": "at+jwt", "kid": "rsa-a"}, claims(iss="https://evil.test/"), ROGUE, "RS256")
        self.deny(self.v, bad_iss, "TOKEN_SIGNATURE_INVALID")  # yanlis issuer degil, once imza reddedilir


# --------------------------------------------------------------------------- V4: talepler
class V4_Claims(Base):
    def setUp(self):
        self.v, self.clk, self.f = make()

    def test_issuer_must_match_exactly(self):
        for iss in ("https://idp.example.test", "HTTPS://IDP.EXAMPLE.TEST/", "https://idp.example.test/x", "https://evil.test/", "", " https://idp.example.test/"):
            with self.subTest(iss=iss):
                self.deny(self.v, mint(iss=iss), "TOKEN_ISSUER_INVALID")
        for iss in (123, ["https://idp.example.test/"], {"a": 1}, True):
            with self.subTest(iss=iss):
                self.deny(self.v, mint(iss=iss), "TOKEN_CLAIM_INVALID")

    def test_audience_must_contain_ours_exactly(self):
        for aud in ("other", ["other"], ["a", "b"], AUD + "-extra", AUD.upper(), AUD + " ", ""):
            with self.subTest(aud=aud):
                self.deny(self.v, mint(aud=aud), "TOKEN_AUDIENCE_INVALID")
        for aud in ([], {}, 5, [1], [AUD] + ["x"] * 8, [AUD, 5], True):
            with self.subTest(aud=aud):
                self.deny(self.v, mint(aud=aud), "TOKEN_CLAIM_INVALID")

    def test_required_claims_missing_or_null(self):
        for name in ("iss", "sub", "aud", "exp", "iat"):
            for val in (DEL, None):
                with self.subTest(claim=name, value=val):
                    self.deny(self.v, mint(**{name: val}), "TOKEN_CLAIM_MISSING")

    def test_subject_shape(self):
        for sub in ("", "x" * 256, "a b", "café", "a\n", "a\tb", 5, ["x"], True):
            with self.subTest(sub=sub):
                self.deny(self.v, mint(sub=sub), "TOKEN_CLAIM_INVALID")
        self.assertEqual(self.v.verify(mint(sub="auth0|abc.DEF-123_x")).subject, "auth0|abc.DEF-123_x")
        self.assertEqual(self.v.verify(mint(sub="x" * 255)).subject, "x" * 255)

    def test_time_claim_types_and_ranges(self):
        for val in ("123", True, [], {}, float("nan"), float("inf"), -1, 10 ** 20, "1.5e9"):
            for name in ("exp", "iat", "nbf"):
                with self.subTest(claim=name, value=repr(val)[:20]):
                    self.deny(self.v, mint(**{name: val}), "TOKEN_CLAIM_INVALID")

    def test_expiry_boundary_with_the_60_second_skew(self):
        self.deny(self.v, mint(iat=T0 - 400, exp=T0 - 60), "TOKEN_EXPIRED")  # exp == now - skew
        self.assertEqual(self.v.verify(mint(iat=T0 - 400, exp=T0 - 59)).subject, "user-123")
        self.deny(self.v, mint(iat=T0 - 4000, exp=T0 - 3600), "TOKEN_EXPIRED")

    def test_not_before_and_issued_at_in_the_future(self):
        self.deny(self.v, mint(nbf=T0 + 61), "TOKEN_NOT_YET_VALID")
        self.assertEqual(self.v.verify(mint(nbf=T0 + 60)).subject, "user-123")
        self.deny(self.v, mint(iat=T0 + 61, exp=T0 + 361), "TOKEN_NOT_YET_VALID")
        self.assertEqual(self.v.verify(mint(iat=T0 + 60, exp=T0 + 360)).subject, "user-123")

    def test_exp_must_follow_iat_and_lifetime_is_capped(self):
        self.deny(self.v, mint(iat=T0, exp=T0), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(iat=T0, exp=T0 - 5), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(iat=T0 - 10, exp=T0 - 10 + 3601), "TOKEN_LIFETIME_EXCEEDED")
        self.assertEqual(self.v.verify(mint(iat=T0 - 10, exp=T0 - 10 + 3600)).subject, "user-123")

    def test_id_tokens_are_not_access_tokens(self):
        for extra in ({"nonce": "n"}, {"at_hash": "h"}, {"c_hash": "h"}, {"token_use": "id"}, {"token_use": 5}):
            with self.subTest(extra=extra):
                self.deny(self.v, mint(**extra), "TOKEN_TYPE_NOT_ACCESS")
        self.assertEqual(self.v.verify(mint(token_use="access")).subject, "user-123")

    def test_optional_claims_are_validated_when_present(self):
        self.deny(self.v, mint(auth_time=T0 + 100), "TOKEN_NOT_YET_VALID")
        self.deny(self.v, mint(auth_time="x"), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(amr=["x"] * 17), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(amr="otp"), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(jti=5), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(sid=""), "TOKEN_CLAIM_INVALID")
        self.deny(self.v, mint(acr="a" * 200), "TOKEN_CLAIM_INVALID")

    def test_skew_zero_is_strict_and_the_clock_is_injectable(self):
        v, clk, f = make(clock_skew_seconds=0)
        self.deny(v, mint(iat=T0 - 400, exp=T0), "TOKEN_EXPIRED")  # exp == now
        self.assertEqual(v.verify(mint(iat=T0 - 400, exp=T0 + 1)).subject, "user-123")
        self.deny(v, mint(iat=T0 + 1, exp=T0 + 100), "TOKEN_NOT_YET_VALID")
        tok = mint()
        self.assertEqual(v.verify(tok).subject, "user-123")
        clk.advance(301)
        self.deny(v, tok, "TOKEN_EXPIRED")  # ayni token, sahte saat ilerleyince

    def test_a_longer_lifetime_can_be_allowed_by_config_only(self):
        v, clk, f = make(max_token_lifetime_seconds=7200)
        self.assertEqual(v.verify(mint(iat=T0 - 10, exp=T0 + 7000)).subject, "user-123")


# --------------------------------------------------------------------------- V5: JWKS onbellegi ve yenileme
class V5_Jwks(Base):
    def test_one_fetch_serves_many_verifications_and_only_the_configured_uri_is_used(self):
        v, clk, f = make()
        tok = mint()
        for _ in range(50):
            v.verify(tok)
        self.assertEqual(f.calls, 1)
        self.assertEqual(set(f.uris), {JWKS_URI})

    def test_ttl_expiry_triggers_exactly_one_refresh(self):
        v, clk, f = make()
        v.verify(mint())
        clk.advance(3600)
        v.verify(mint(now=clk.t))
        self.assertEqual(f.calls, 1)  # tam 3600 sn: hala taze (<=)
        clk.advance(1)
        v.verify(mint(now=clk.t))
        self.assertEqual(f.calls, 2)

    def test_unknown_kid_refreshes_at_most_once_per_interval(self):
        v, clk, f = make()
        v.verify(mint())
        clk.advance(5)
        self.deny(v, mint(kid="nope-1"), "TOKEN_KID_UNKNOWN")
        self.assertEqual(f.calls, 1)  # aralik dolmadi: ag yok
        clk.advance(30)
        self.deny(v, mint(kid="nope-2"), "TOKEN_KID_UNKNOWN")
        self.assertEqual(f.calls, 2)  # aralik doldu: tek yenileme
        self.deny(v, mint(kid="nope-3"), "TOKEN_KID_UNKNOWN")
        self.assertEqual(f.calls, 2)

    def test_unknown_kid_storm_is_bounded(self):
        v, clk, f = make()
        v.verify(mint())
        for i in range(600):
            clk.advance(0.2)  # 120 sn boyunca saniyede 5 istek
            self.deny(v, mint(kid="storm-%d" % i), "TOKEN_KID_UNKNOWN")
        self.assertLessEqual(f.calls, 1 + 120 // 30 + 1)

    def test_rotation_adds_the_new_key_and_retires_the_old_one_only_after_a_refresh(self):
        v, clk, f = make()
        old = mint(RSA_A, "RS256", "rsa-a")
        self.assertEqual(v.verify(old).subject, "user-123")
        f.doc = {"keys": [jwk_rsa(RSA_B.public_key(), "rsa-b")]}  # IdP dondurdu: yalniz yeni anahtar
        self.assertEqual(v.verify(old).subject, "user-123")  # onbellek hala eski anahtari tutuyor
        clk.advance(31)
        self.assertEqual(v.verify(mint(RSA_B, "RS256", "rsa-b", now=clk.t)).subject, "user-123")  # yeni kid yenilemeyi tetikledi
        self.deny(v, mint(RSA_A, "RS256", "rsa-a", now=clk.t), "TOKEN_KID_UNKNOWN")  # eski anahtar artik yok

    def test_rotation_failure_new_kid_never_published(self):
        v, clk, f = make()
        v.verify(mint())
        clk.advance(31)
        self.deny(v, mint(RSA_B, "RS256", "rsa-b", now=clk.t), "TOKEN_KID_UNKNOWN")  # yenileme basarili ama kid yok
        self.assertEqual(v.verify(mint(now=clk.t)).subject, "user-123")  # eski anahtar calismaya devam eder

    def test_failed_refresh_keeps_the_cache_until_ttl_and_then_fails_closed(self):
        v, clk, f = make()
        v.verify(mint())
        f.doc = {"keys": []}  # gecersiz/bos belge = basarisiz yenileme
        clk.advance(31)
        self.deny(v, mint(kid="new", now=clk.t), "JWKS_UNAVAILABLE", 503)
        self.assertEqual(v.verify(mint(now=clk.t)).subject, "user-123")  # TTL icinde eski anahtar
        clk.advance(3600)  # TTL doldu, yenileme hala basarisiz
        self.deny(v, mint(now=clk.t), "JWKS_UNAVAILABLE", 503)

    def test_stale_if_error_is_opt_in_and_bounded(self):
        v, clk, f = make(jwks_stale_if_error_seconds=600)
        v.verify(mint())
        f.fail = OSError("down")
        clk.advance(3600 + 100)
        self.assertEqual(v.verify(mint(now=clk.t)).subject, "user-123")  # TTL + 100 <= TTL + 600
        clk.advance(600)
        self.deny(v, mint(now=clk.t), "JWKS_UNAVAILABLE", 503)  # ust sinir asildi

    def test_cold_start_with_an_unavailable_jwks_is_denied_with_503(self):
        v, clk, f = make()
        f.fail = OSError("connection refused")
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)

    def test_failure_backoff_is_exponential_capped_and_makes_no_network_calls_while_waiting(self):
        v, clk, f = make()
        f.fail = TimeoutError("slow")
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        self.assertEqual(f.calls, 1)
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        self.assertEqual(f.calls, 1)  # geri cekilme: ag yok
        clk.advance(15)
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        self.assertEqual(f.calls, 2)
        clk.advance(29)
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        self.assertEqual(f.calls, 2)  # ikinci basarisizlikta bekleme 30 sn
        clk.advance(1)
        f.fail = None
        self.assertEqual(v.verify(mint(now=clk.t)).subject, "user-123")  # iyilesti
        self.assertEqual(f.calls, 3)
        f.fail = OSError("again")
        before = f.calls
        for _ in range(400):  # tavan: bekleme hicbir zaman 300 sn'yi asmaz
            clk.advance(301)
            with contextlib.suppress(oidc.TokenError):
                v.verify(mint(kid="x", now=clk.t))
        self.assertEqual(f.calls - before, 400)  # bekleme (<=300) 301 sn'lik adimdan hep kisa: her adimda bir deneme

    def test_every_kind_of_fetcher_failure_is_a_503_never_a_pass(self):
        errors = [OSError("x"), TimeoutError("x"), RuntimeError("x"), ValueError("x"), KeyError("x"), oidc.JwksFetchError("x"), Exception("x")]
        for exc in errors:
            v, clk, f = make()
            f.fail = exc
            with self.subTest(exc=type(exc).__name__):
                self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)

    def test_garbage_jwks_documents_are_refused(self):
        docs = [b"null", "text", 5, b"", b"not json", b"[]", b'{"keys":"x"}', b'{"keys":[1]}', b'{"keys":[{"kty":"oct"}]}', b'{"nokeys":[]}',
                b"\xff\xfe", b"{" * 5000, b'{"keys":[' + b'{"kty":"RSA"},' * 3 + b"{}]}"]
        for doc in docs:
            v, clk, f = make(doc)
            with self.subTest(doc=repr(doc)[:30]):
                self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)

    def test_dangerous_or_unusable_keys_are_not_accepted(self):
        small = gen_rsa(1024)
        p384 = ec.generate_private_key(ec.SECP384R1())
        priv = json.loads(RSAAlgorithm.to_jwk(RSA_A))  # ozel anahtar parametreleri tasir
        priv.update({"kid": "rsa-a", "use": "sig"})
        cases = {
            "private material": [priv],
            "rsa 1024": [jwk_rsa(small.public_key(), "rsa-a")],
            "ec p-384": [json.loads(ECAlgorithm.to_jwk(p384.public_key())) | {"kid": "ec-a", "use": "sig"}],
            "oct secret": [{"kty": "oct", "kid": "rsa-a", "k": "c2VjcmV0", "use": "sig"}],
            "use enc": [jwk_rsa(RSA_A.public_key(), "rsa-a", use="enc")],
            "key_ops sign": [jwk_rsa(RSA_A.public_key(), "rsa-a", key_ops=["sign"])],
            "alg mismatch": [jwk_rsa(RSA_A.public_key(), "rsa-a", alg="RS512")],
            "duplicate kid": [jwk_rsa(RSA_A.public_key(), "rsa-a"), jwk_rsa(RSA_B.public_key(), "rsa-a")],
            "bad kid": [jwk_rsa(RSA_A.public_key(), "../x")],
            "too many keys": [jwk_rsa(RSA_A.public_key(), "k%d" % i) for i in range(21)],
        }
        for name, keys in cases.items():
            v, clk, f = make({"keys": keys})
            with self.subTest(case=name):
                self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)

    def test_private_key_material_anywhere_rejects_the_whole_document_without_partial_acceptance(self):
        priv = json.loads(RSAAlgorithm.to_jwk(RSA_B))
        priv.update({"kid": "rsa-b", "use": "sig"})
        v, clk, f = make({"keys": [jwk_rsa(RSA_A.public_key(), "rsa-a"), priv]})  # gecerli anahtar yaninda ozel anahtar
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        self.assertEqual(v._keys, {})

    def test_document_size_limit_applies_even_to_valid_json(self):
        padded = json.dumps(default_doc()).encode() + b" " * 70000
        v, clk, f = make(padded)
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        v2, _, _ = make(json.dumps(default_doc()).encode() + b" " * 100)
        self.assertEqual(v2.verify(mint()).subject, "user-123")

    def test_unusable_entries_are_skipped_but_a_usable_key_still_loads(self):
        p384 = ec.generate_private_key(ec.SECP384R1())
        doc = {"keys": [jwk_rsa(RSA_A.public_key(), "rsa-a"), jwk_rsa(RSA_B.public_key(), "enc-b", use="enc"),
                        json.loads(ECAlgorithm.to_jwk(p384.public_key())) | {"kid": "p384", "use": "sig"}, {"kty": "OKP", "kid": "okp", "crv": "Ed25519", "x": "AAAA"}]}
        v, clk, f = make(doc)
        self.assertEqual(v.verify(mint()).subject, "user-123")
        self.assertEqual(sorted(v._keys), ["rsa-a"])
        self.deny(v, mint(RSA_B, "RS256", "enc-b"), "TOKEN_KID_UNKNOWN")

    def test_oversize_document_and_key_count_are_bounded(self):
        v, clk, f = make(b" " * 70000)
        self.deny(v, mint(), "JWKS_UNAVAILABLE", 503)
        keys = [jwk_rsa(RSA_A.public_key(), "k%d" % i) for i in range(20)]
        v, clk, f = make({"keys": keys})
        self.assertEqual(v.verify(mint(kid="k0")).subject, "user-123")
        self.assertEqual(len(v._keys), 20)

    def test_the_jwks_address_never_comes_from_the_token(self):
        v, clk, f = make()
        tok = forge({"alg": "RS256", "typ": "at+jwt", "kid": "rsa-a", "jku": "https://evil.example/j"}, claims(iss="https://evil.example/"), RSA_A, "RS256")
        self.deny(v, tok, "TOKEN_HEADER_UNSAFE")
        self.deny(v, mint(iss="https://evil.example/"), "TOKEN_ISSUER_INVALID")
        self.assertEqual(set(f.uris), {JWKS_URI})

    def test_concurrent_cold_start_is_single_flight(self):
        v, clk, f = make()
        f.delay = 0.2
        tok, results, barrier = mint(), [], threading.Barrier(16)

        def work():
            barrier.wait()
            try:
                results.append(v.verify(tok).subject)
            except oidc.TokenError as exc:
                results.append(exc.code)

        ts = [threading.Thread(target=work) for _ in range(16)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(results, ["user-123"] * 16)
        self.assertEqual(f.calls, 1)

    def test_concurrent_unknown_kid_storm_is_bounded(self):
        v, clk, f = make()
        v.verify(mint())
        results, barrier = [], threading.Barrier(16)

        def work(i):
            barrier.wait()
            for j in range(20):
                try:
                    v.verify(mint(kid="storm-%d-%d" % (i, j)))
                except oidc.TokenError as exc:
                    results.append(exc.code)

        ts = [threading.Thread(target=work, args=(i,)) for i in range(16)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(set(results), {"TOKEN_KID_UNKNOWN"})
        self.assertEqual(len(results), 320)
        self.assertEqual(f.calls, 1)  # saat sabit: aralik hic dolmadi


# --------------------------------------------------------------------------- V6: girdi sinirlari
class V6_InputBounds(Base):
    def setUp(self):
        self.v, self.clk, self.f = make()

    def test_non_string_inputs_and_empty(self):
        for bad in (None, b"abc", 5, ["a"], object()):
            self.deny(self.v, bad, "TOKEN_MALFORMED")
        self.deny(self.v, "", "TOKEN_MISSING")
        self.assertEqual(self.f.calls, 0)

    def test_oversized_token_is_refused_before_any_work(self):
        self.deny(self.v, "a" * 8193, "TOKEN_TOO_LARGE")
        self.deny(self.v, mint() + "A" * 9000, "TOKEN_TOO_LARGE")
        self.assertEqual(self.f.calls, 0)
        self.assertEqual(self.v.verify(mint()).subject, "user-123")  # 8192 siniri icindeki normal token

    def test_whitespace_control_and_non_ascii_inside_the_token(self):
        good = mint()
        for tok in (" " + good, good + " ", good + "\n", good.replace(".", " .", 1), good[:10] + "\x00" + good[10:], good + "é", "Bearer " + good,
                    good.replace("-", "+") if "-" in good else good + "+", good + "="):
            with self.subTest(tok=tok[:12].encode("unicode_escape")):
                self.deny(self.v, tok, "TOKEN_MALFORMED")

    def test_characters_outside_the_base64url_alphabet_inside_any_segment_are_refused(self):
        # Gevsek base64 cozuculer alfabe disi karakterleri sessizce atar: ayni imza/baslik/govde baytlarina cozulen
        # "bozulmus" bir jeton (imza esnekligi) kabul edilmemeli. Karakter segmentin ORTASINA girer, sona degil.
        good = mint()
        self.assertEqual(self.v.verify(good).subject, "user-123")
        segs = good.split(".")
        for idx in range(3):
            for junk in ("!", "*", "~", "#", "@", "%", "$", "+", "/", "'", "\\", "="):
                s = segs[idx]
                mid = len(s) // 2
                bad = list(segs)
                bad[idx] = s[:mid] + junk + s[mid:]
                with self.subTest(segment=idx, junk=junk):
                    self.deny(self.v, ".".join(bad), "TOKEN_MALFORMED")
                    # PyJWT de bunu reddeder; ama koruma PyJWT'nin sikiligina BAGLI kalmamali: yapisal on-kontrol tek basina reddetmeli
                    with self.assertRaises(oidc.TokenError) as cm:
                        self.v._parse_header(".".join(bad))
                    self.assertEqual(cm.exception.code, "TOKEN_MALFORMED")

    def test_deeply_nested_header_and_payload_do_not_crash(self):
        deep = b"[" * 3000 + b"]" * 3000
        tok = b64u(deep) + "." + b64u(b"{}") + "." + b64u(b"x")
        self.deny(self.v, tok, "TOKEN_MALFORMED")
        header = {"alg": "RS256", "typ": "at+jwt", "kid": "rsa-a"}
        signed_deep = forge(header, b"[" * 2000 + b"]" * 2000, RSA_A)  # gecerli imza, ama govde asiri ic ice (8 KiB sinirinin altinda)
        self.deny(self.v, signed_deep, "TOKEN_MALFORMED")
        self.deny(self.v, forge(header, b'"just a string"', RSA_A), "TOKEN_MALFORMED")
        self.deny(self.v, forge(header, b"[1,2]", RSA_A), "TOKEN_MALFORMED")

    def test_bearer_header_extraction_is_strict(self):
        tok = mint()
        self.assertEqual(oidc.extract_bearer_token("Bearer " + tok), tok)
        self.assertEqual(oidc.extract_bearer_token("bearer " + tok), tok)
        self.assertEqual(oidc.extract_bearer_token("BEARER " + tok), tok)
        for missing in (None, ""):
            with self.assertRaises(oidc.TokenError) as cm:
                oidc.extract_bearer_token(missing)
            self.assertEqual(cm.exception.code, "TOKEN_MISSING")
        for bad in ("Bearer", "Bearer ", "Bearer  x", "Basic abc", "Bearer a b", "Bearer a\tb", "Bearer\tabc", tok, "Bearer é", 5, b"Bearer x"):
            with self.subTest(bad=repr(bad)[:20]), self.assertRaises(oidc.TokenError) as cm:
                oidc.extract_bearer_token(bad)
            self.assertEqual(cm.exception.code, "TOKEN_MALFORMED")
        with self.assertRaises(oidc.TokenError) as cm:
            oidc.extract_bearer_token("Bearer " + "a" * 9000)
        self.assertEqual(cm.exception.code, "TOKEN_TOO_LARGE")


# --------------------------------------------------------------------------- V7: gizli bilgi sizintisi yok
class V7_NoSecretLeakage(Base):
    SECRETS = ("SENSITIVE-SUB-XYZ", "kid-secret-1", "FETCHER-SECRET-TEXT", "SENSITIVE-JTI-777")

    def test_nothing_sensitive_reaches_logs_stdout_stderr_or_error_text(self):
        records = []

        class H(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler, logger = H(level=logging.DEBUG), logging.getLogger()
        old_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        out, err = io.StringIO(), io.StringIO()
        texts, tokens = [], []
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                v, clk, f = make()
                good = mint(sub="SENSITIVE-SUB-XYZ", jti="SENSITIVE-JTI-777")
                h, p, s = good.split(".")
                tokens += [good, h, p, s]
                bad_sig = h + "." + p + "." + ("A" if s[0] != "A" else "B") + s[1:]
                expired = mint(sub="SENSITIVE-SUB-XYZ", iat=T0 - 9000, exp=T0 - 8000)
                unknown = mint(kid="kid-secret-1", sub="SENSITIVE-SUB-XYZ")
                tokens += [bad_sig, expired, unknown]
                for tok in (good, bad_sig, expired, unknown, good + "x", "garbage"):
                    try:
                        v.verify(tok)
                    except oidc.TokenError as exc:
                        texts += [str(exc), repr(exc), "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))]
                v2, clk2, f2 = make()
                f2.fail = OSError("FETCHER-SECRET-TEXT")
                try:
                    v2.verify(good)
                except oidc.TokenError as exc:
                    texts += [str(exc), repr(exc), "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))]
                texts += [repr(v), repr(v2), repr(v.verify(good)), repr(v._cfg)]
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logged = [r.getMessage() + " " + repr(r.args) + " " + (r.exc_text or "") + " " + str(r.exc_info) for r in records]
        blob = "\n".join(logged + texts + [out.getvalue(), err.getvalue()])
        self.assertTrue(any("oidc_verify_denied" in m for m in logged))  # loglar gercekten uretildi
        for secret in self.SECRETS + tuple(tokens):
            self.assertNotIn(secret, blob, "sensitive value leaked: " + secret[:12])
        pem = RSA_A.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        self.assertNotIn(pem.splitlines()[1], blob)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_log_lines_carry_only_fixed_codes_and_counts(self):
        v, clk, f = make()
        with self.assertLogs("app.auth.oidc", level="DEBUG") as cm:
            v.verify(mint())
            with self.assertRaises(oidc.TokenError):
                v.verify(mint(kid="nope"))
        for line in cm.output:
            self.assertRegex(line.split(":", 2)[2], r"^oidc_(jwks_refreshed keys=\d+|verify_denied code=[A-Z_]+|jwks_refresh_failed reason=\w+ failures=\d+)$")


# --------------------------------------------------------------------------- V8: yetki talepleri kaynak degildir
class V8_AuthorityClaimsAreNotAuthority(Base):
    EXTRA = {"role": "TENANT_OWNER", "roles": ["PLATFORM_DATA_STEWARD"], "organization": "org-1", "org_id": "o-9", "tenant": "t-1", "tenant_id": "t-2",
             "plan": "ENTERPRISE", "tier": "PRO", "scope": "admin write", "scp": ["write"], "groups": ["admins"], "permissions": ["*"], "is_admin": True,
             "email": "a@b.example", "email_verified": True, "entitlements": {"catalog.ai_ocr_allowed": True}, "admin_approved": True,
             "https://mirpua.example/roles": ["admin"]}

    def test_principal_is_identical_with_or_without_such_claims(self):
        v, clk, f = make()
        plain = v.verify(mint())
        loaded = v.verify(mint(**self.EXTRA))
        self.assertEqual(plain, loaded)
        self.assertEqual(dataclasses.asdict(plain), dataclasses.asdict(loaded))

    def test_principal_has_no_authority_shaped_fields_or_values(self):
        names = {f.name for f in dataclasses.fields(oidc.VerifiedPrincipal)}
        self.assertEqual(names, {"issuer", "subject", "audience", "issued_at", "expires_at", "not_before", "token_id", "session_id", "auth_time", "acr", "amr"})
        v, clk, f = make()
        p = v.verify(mint(**self.EXTRA))
        blob = repr(p) + repr(dataclasses.asdict(p))
        for value in ("TENANT_OWNER", "PLATFORM_DATA_STEWARD", "org-1", "t-1", "ENTERPRISE", "admin", "a@b.example"):
            self.assertNotIn(value, blob)
        for attr in ("role", "roles", "organization", "tenant", "tenant_id", "plan", "email", "permissions", "scope", "groups"):
            self.assertFalse(hasattr(p, attr), attr)

    def test_authority_claims_cannot_repair_an_invalid_token(self):
        v, clk, f = make()
        self.deny(v, mint(exp=T0 - 9999, iat=T0 - 10000, **self.EXTRA), "TOKEN_EXPIRED")
        self.deny(v, mint(aud="other", **self.EXTRA), "TOKEN_AUDIENCE_INVALID")


# --------------------------------------------------------------------------- V9: varsayilan HTTP getirici (yalniz yerel sunucu)
class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # istemci erken kapatinca gelen gurultuyu bastir
        pass


class _Server:
    def __init__(self, handler_cls):
        self.httpd = _QuietServer(("127.0.0.1", 0), handler_cls)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def handler(doc_bytes=None, status=200, ctype="application/json", location=None, delay=0.0, extra_len=None, no_length=False):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if delay:
                time.sleep(delay)
            if self.path == "/redirected":
                body = json.dumps(default_doc()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = doc_bytes if doc_bytes is not None else json.dumps(default_doc()).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            if location:
                self.send_header("Location", location)
            if not no_length:
                self.send_header("Content-Length", str(extra_len if extra_len is not None else len(body)))
            self.end_headers()
            self.wfile.write(body)

    return H


class V9_DefaultFetcher(Base):
    def run_fetch(self, server, **kw):
        f = oidc.HttpsJwksFetcher(allow_insecure_loopback=True)
        return f.fetch("http://127.0.0.1:%d/jwks.json" % server.port, timeout=kw.get("timeout", 2.0), max_bytes=kw.get("max_bytes", 65536))

    def test_success_end_to_end_through_the_real_fetcher(self):
        srv = _Server(handler())
        try:
            cfg = oidc.OidcConfig(issuer=ISS, audience=AUD, jwks_uri="http://127.0.0.1:%d/jwks.json" % srv.port, trusted_jwks_hosts=("127.0.0.1",),
                                  allow_insecure_loopback=True)
            clk = Clk()
            v = oidc.OidcAccessTokenVerifier(cfg, clock=clk, monotonic=clk)
            self.assertEqual(v.verify(mint()).subject, "user-123")
        finally:
            srv.close()

    def test_redirects_are_not_followed(self):
        srv = _Server(handler(status=302, location="/redirected"))
        try:
            with self.assertRaises(oidc.JwksFetchError):
                self.run_fetch(srv)
        finally:
            srv.close()

    def test_oversize_wrong_type_and_error_statuses_are_refused(self):
        big = b"x" * 5000
        cases = [("oversize body", handler(doc_bytes=big), dict(max_bytes=1000)), ("oversize body, no declared length", handler(doc_bytes=big, no_length=True), dict(max_bytes=1000)), ("declared length too big", handler(extra_len=10 ** 9), {}),
                 ("html content type", handler(ctype="text/html"), {}), ("404", handler(status=404), {}), ("500", handler(status=500), {}),
                 ("204-like empty ok? json required", handler(doc_bytes=b"", ctype="text/plain"), {})]
        for name, h, kw in cases:
            srv = _Server(h)
            try:
                with self.subTest(case=name), self.assertRaises(oidc.JwksFetchError):
                    self.run_fetch(srv, **kw)
            finally:
                srv.close()

    def test_slow_server_times_out_and_closed_port_fails(self):
        srv = _Server(handler(delay=2.0))
        try:
            t0 = time.time()
            with self.assertRaises(oidc.JwksFetchError):
                self.run_fetch(srv, timeout=0.3)
            self.assertLess(time.time() - t0, 1.8)
        finally:
            srv.close()
        with self.assertRaises(oidc.JwksFetchError):
            oidc.HttpsJwksFetcher(True).fetch("http://127.0.0.1:%d/jwks.json" % srv.port, timeout=0.5, max_bytes=1000)

    def test_plain_http_and_foreign_schemes_are_refused_without_connecting(self):
        f = oidc.HttpsJwksFetcher(allow_insecure_loopback=False)
        for uri in ("http://127.0.0.1:9/jwks.json", "ftp://idp.example.test/x", "file:///etc/passwd", "gopher://x/", "data:text/plain,hi"):
            with self.subTest(uri=uri), self.assertRaises(oidc.JwksFetchError):
                f.fetch(uri, timeout=0.5, max_bytes=1000)

    def test_environment_proxies_are_ignored(self):
        srv = _Server(handler())
        try:
            with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1", "all_proxy": "http://127.0.0.1:1"}):
                self.assertIn(b"keys", self.run_fetch(srv))
        finally:
            srv.close()


# --------------------------------------------------------------------------- V10: R1 -- gecersiz saat (F-01) ve asiri buyuk NumericDate (F-02)
def _verifier_with_clocks(clock, monotonic=None):
    fetcher = FakeFetcher()
    mono = Clk() if monotonic is None else monotonic
    v = oidc.OidcAccessTokenVerifier(oidc.OidcConfig(**BASE_CFG), fetcher=fetcher, clock=clock, monotonic=mono)
    return v, fetcher


class V10_UntrustworthyClock(Base):
    """F-01: NaN/Infinity/gecersiz saat ile, imzasi gecerli SURESI GECMIS jeton kabul ediliyordu (karsilastirmalar hep False).
    Saat guvenilir degilse hicbir VerifiedPrincipal uretilmez; sabit kod VERIFIER_CLOCK_INVALID, HTTP 503 (jeton degil, dogrulayici sorunu)."""
    BAD_VALUES = (float("nan"), float("inf"), float("-inf"), -1, -1.5, 0 - 10 ** 12, 4102444801, 1e300, 10 ** 400, True, False, None, "1800000000", "nan",
                  b"1800000000", [T0], (T0,), {"t": T0}, complex(T0, 0), object())

    def expired(self):
        return mint(iat=T0 - 4000, exp=T0 - 3500)  # gecerli imza, 3500 sn once suresi dolmus (60 sn toleransin cok disinda)

    def test_an_expired_validly_signed_token_is_not_accepted_under_any_invalid_wall_clock(self):
        for bad in self.BAD_VALUES:
            v, fetcher = _verifier_with_clocks(lambda bad=bad: bad)
            with self.subTest(clock=repr(bad)[:24]):
                self.deny(v, self.expired(), "VERIFIER_CLOCK_INVALID", 503)

    def test_a_fresh_validly_signed_token_is_also_not_accepted_under_an_invalid_wall_clock(self):
        for bad in self.BAD_VALUES:
            v, fetcher = _verifier_with_clocks(lambda bad=bad: bad)
            with self.subTest(clock=repr(bad)[:24]):
                self.deny(v, mint(), "VERIFIER_CLOCK_INVALID", 503)

    def test_a_clock_that_raises_fails_closed_with_the_same_code(self):
        for exc in (RuntimeError("boom"), ValueError("x"), OverflowError("x"), TypeError("x"), OSError("x")):
            def clock(exc=exc):
                raise exc
            v, fetcher = _verifier_with_clocks(clock)
            with self.subTest(exc=type(exc).__name__):
                self.deny(v, mint(), "VERIFIER_CLOCK_INVALID", 503)

    def test_the_clock_failure_is_a_known_code_and_is_logged_without_any_token_data(self):
        self.assertIn("VERIFIER_CLOCK_INVALID", oidc.ERROR_CODES)
        tok = mint(sub="SENSITIVE-SUB-XYZ", jti="SENSITIVE-JTI-777")
        v, fetcher = _verifier_with_clocks(lambda: float("nan"))
        with self.assertLogs("app.auth.oidc", level="DEBUG") as cm:
            self.deny(v, tok, "VERIFIER_CLOCK_INVALID", 503)
        text = "\n".join(cm.output)
        self.assertIn("VERIFIER_CLOCK_INVALID", text)
        for secret in (tok, tok.split(".")[0], tok.split(".")[1], tok.split(".")[2], "SENSITIVE-SUB-XYZ", "SENSITIVE-JTI-777"):
            self.assertNotIn(secret, text)

    def test_a_bad_clock_does_not_hide_an_ordinary_token_error(self):
        v, fetcher = _verifier_with_clocks(lambda: float("nan"))
        self.deny(v, "not-a-token", "TOKEN_MALFORMED")
        self.deny(v, mint(headers={"typ": "JWT"}), "TOKEN_TYPE_NOT_ACCESS")
        self.deny(v, mint()[:-4] + "AAAA", "TOKEN_SIGNATURE_INVALID")

    def test_a_valid_clock_behaves_exactly_as_before_int_float_and_the_60_second_boundary(self):
        for clock_value in (T0, int(T0), T0 + 0.25):
            v, fetcher = _verifier_with_clocks(lambda c=clock_value: c)
            with self.subTest(clock=clock_value):
                self.assertEqual(v.verify(mint()).subject, "user-123")
                self.deny(v, mint(iat=T0 - 400, exp=T0 - 100), "TOKEN_EXPIRED")
        v, _ = _verifier_with_clocks(lambda: T0)
        self.deny(v, mint(iat=T0 - 400, exp=T0 - 60), "TOKEN_EXPIRED")
        self.assertEqual(v.verify(mint(iat=T0 - 400, exp=T0 - 59)).subject, "user-123")
        self.deny(v, mint(nbf=T0 + 61), "TOKEN_NOT_YET_VALID")
        self.assertEqual(v.verify(mint(nbf=T0 + 60)).subject, "user-123")

    def test_a_clock_at_the_edges_of_the_accepted_range_is_still_a_clock(self):
        for edge in (0, 0.0, 4102444800, 4102444800.0):
            v, _ = _verifier_with_clocks(lambda e=edge: e)
            with self.subTest(clock=edge):
                try:
                    v.verify(mint())
                except oidc.TokenError as exc:
                    self.assertNotEqual(exc.code, "VERIFIER_CLOCK_INVALID")  # gecerli saat: jeton baska bir nedenle reddedilebilir

    def test_an_untrustworthy_monotonic_clock_cannot_defeat_the_jwks_refresh_bounds(self):
        # NaN/inf monotonik saat "yenileme araligi" ve "geri cekilme" karsilastirmalarini hep False yapar -> sinirsiz getirme.
        for bad in (float("nan"), float("inf"), float("-inf"), -1, -0.5, 2 ** 54, True, None, "5", 10 ** 400, -(10 ** 400)):
            fetcher = FakeFetcher()
            v = oidc.OidcAccessTokenVerifier(oidc.OidcConfig(**BASE_CFG), fetcher=fetcher, clock=Clk(), monotonic=lambda bad=bad: bad)
            with self.subTest(monotonic=repr(bad)[:24]):
                for _ in range(5):
                    self.deny(v, mint(), "VERIFIER_CLOCK_INVALID", 503)
                self.assertEqual(fetcher.calls, 0)

    def test_a_monotonic_clock_that_raises_fails_closed(self):
        def mono():
            raise RuntimeError("boom")
        fetcher = FakeFetcher()
        v = oidc.OidcAccessTokenVerifier(oidc.OidcConfig(**BASE_CFG), fetcher=fetcher, clock=Clk(), monotonic=mono)
        self.deny(v, mint(), "VERIFIER_CLOCK_INVALID", 503)
        self.assertEqual(fetcher.calls, 0)


class _Raw(str):
    """Test yardimcisi: JSON metnine oldugu gibi yazilacak sayi bicimi."""


class V11_OversizedNumericDates(Base):
    """F-02: exp/iat/nbf = 10**400 -> float() OverflowError -> VERIFIER_INTERNAL_ERROR/503. Veri hatasidir: TOKEN_CLAIM_INVALID/401."""

    def setUp(self):
        self.v, self.clk, self.f = make()

    @staticmethod
    def raw_payload(**fields):
        """json.dumps'in yazmayacagi sayi bicimlerini (1e400, -1e400, NaN) dogrudan metin olarak kurar."""
        base = claims()
        parts = []
        for k, val in {**base, **fields}.items():
            parts.append('"%s":%s' % (k, val if isinstance(val, _Raw) else json.dumps(val)))
        return ("{" + ",".join(parts) + "}").encode()

    def test_huge_integers_are_claim_errors_not_internal_errors(self):
        for val in (10 ** 400, -(10 ** 400), 10 ** 309, 10 ** 1000, 2 ** 1024, 2 ** 63, 2 ** 64, 10 ** 20, 4102444801):
            for name in ("exp", "iat", "nbf"):
                with self.subTest(claim=name, digits=len(str(abs(val)))):
                    self.deny(self.v, mint(**{name: val}), "TOKEN_CLAIM_INVALID")

    def test_the_overflow_is_not_reported_as_a_verifier_outage(self):
        with self.assertRaises(oidc.TokenError) as cm:
            self.v.verify(mint(exp=10 ** 400))
        self.assertEqual(cm.exception.http_status, 401)
        self.assertNotEqual(cm.exception.code, "VERIFIER_INTERNAL_ERROR")

    def test_float_overflow_spellings_in_the_json_text_are_claim_errors(self):
        for text in ("1e400", "-1e400", "1E999", "1.0e309", "NaN", "Infinity", "-Infinity", "1e308", "-0.0000001"):
            for name in ("exp", "iat", "nbf"):
                tok = forge({"alg": "RS256", "typ": "at+jwt", "kid": "rsa-a"}, self.raw_payload(**{name: _Raw(text)}), RSA_A)
                with self.subTest(claim=name, text=text):
                    self.deny(self.v, tok, "TOKEN_CLAIM_INVALID")

    def test_auth_time_uses_the_same_numeric_rules(self):
        for val in (10 ** 400, -(10 ** 400), 4102444801, float("nan"), -1):
            with self.subTest(auth_time=repr(val)[:20]):
                self.deny(self.v, mint(auth_time=val), "TOKEN_CLAIM_INVALID")

    def test_integer_strings_longer_than_pythons_digit_limit_are_a_401_data_error(self):
        # CPython (>= 3.11) 4300 haneden uzun tam sayi metnini cevirmeyi reddeder: yanit 401 kalir (503 degil).
        tok = forge({"alg": "RS256", "typ": "at+jwt", "kid": "rsa-a"}, self.raw_payload(exp=_Raw("9" * 5000)), RSA_A)
        with self.assertRaises(oidc.TokenError) as cm:
            self.v.verify(tok)
        self.assertEqual(cm.exception.http_status, 401)
        self.assertIn(cm.exception.code, ("TOKEN_MALFORMED", "TOKEN_CLAIM_INVALID"))

    def test_valid_numeric_dates_and_the_60_second_tolerance_are_unchanged(self):
        self.assertEqual(self.v.verify(mint(iat=int(T0) - 10, exp=int(T0) + 300, nbf=int(T0) - 10)).subject, "user-123")  # tam sayi
        self.assertEqual(self.v.verify(mint(iat=T0 - 10.5, exp=T0 + 300.25, nbf=T0 - 10.5)).subject, "user-123")  # kesirli
        self.deny(self.v, mint(iat=T0 - 400, exp=T0 - 60), "TOKEN_EXPIRED")
        self.assertEqual(self.v.verify(mint(iat=T0 - 400, exp=T0 - 59)).subject, "user-123")
        self.deny(self.v, mint(nbf=T0 + 61), "TOKEN_NOT_YET_VALID")
        self.assertEqual(self.v.verify(mint(nbf=T0 + 60)).subject, "user-123")
        self.assertEqual(self.v.verify(mint(iat=T0 + 60, exp=T0 + 360)).subject, "user-123")

    def test_numeric_date_ceiling_is_exactly_the_documented_one(self):
        self.assertEqual(oidc._num(4102444800), 4102444800.0)
        self.assertEqual(oidc._num(0), 0.0)
        self.assertEqual(oidc._num(1.5), 1.5)
        for bad in (4102444801, 4102444800.5, -1, -0.5, 10 ** 400, float("nan"), float("inf"), True, "1", None):
            with self.subTest(value=repr(bad)[:20]), self.assertRaises(oidc.TokenError) as cm:
                oidc._num(bad)
            self.assertEqual(cm.exception.code, "TOKEN_CLAIM_INVALID")
            self.assertEqual(cm.exception.http_status, 401)


if __name__ == "__main__":
    unittest.main()
