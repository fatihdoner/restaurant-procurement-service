"""RG-0 / T-20 (R0): yazma uclari fail-closed.

Gercek bir kimlik saglayicisi (IdP) olmadigi icin GET, HEAD ve OPTIONS disindaki
HTTP yontemleri, hangi yola gittigine bakilmaksizin 403 ile reddedilir. Ret, istek
govdesi okunmadan, rota/DB/dosya katmanina ulasmadan verilir. Ortak API anahtari
yoktur ve ortam degiskeniyle bu kapiyi acmak mumkun degildir; yeniden acmak yeni kod
ve yeni bir owner karari gerektirir.

CORS ayri bir katmandir ve kimlik dogrulamanin yerine gecmez: izinli bir origin'den
gelen POST da reddedilir.
"""

import re

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_BODY = b'{"detail":"write_endpoints_closed"}'
_HEADERS = [
    (b"content-type", b"application/json"),
    (b"content-length", str(len(_BODY)).encode("ascii")),
    (b"cache-control", b"no-store"),
    (b"connection", b"close"),
]

_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


class WriteGuardMiddleware:
    """Saf ASGI katmani. Yalniz 'http' kapsamini yonetir; lifespan, websocket vb.
    diger kapsamlar oldugu gibi gecer."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or str(scope.get("method", "")).upper() in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        await send({"type": "http.response.start", "status": 403, "headers": _HEADERS})
        await send({"type": "http.response.body", "body": _BODY})


def parse_allowed_origins(raw):
    """CORS_ALLOWED_ORIGINS (virgullu) -> liste. Bos/tanimsiz = []. Joker, 'null', yol
    iceren veya bicimi bozuk her girdi ValueError verir: yanlis yapilandirma sessizce
    genisletmez, servis acilmaz."""
    if not raw:
        return []
    origins = []
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        if not _ORIGIN_RE.match(item):
            raise ValueError("CORS_ALLOWED_ORIGINS: gecersiz origin girdisi")
        if item not in origins:
            origins.append(item)
    return origins
