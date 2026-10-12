"""RG-0 / T-20 (R1): ASGI duzeyinde, bagimliliksiz, sinirli-bellekli hiz siniri.

Kapsam ve tasarim:
  * Yalniz GET ve HEAD sayilir. OPTIONS, `/health` ve tum diger yontemler muaftir/gecer.
    (Yazma yontemleri zaten WriteGuardMiddleware tarafindan, bu katmana ulasmadan 403 alir;
    bu katman guard'in ICINDE durur, boylece limit dolsa bile yazma 403'u degismez.)
  * Sabit iki rota grubu: `/reports` ve `/reports/*` -> 30 istek / 60 sn; digerleri -> 120 istek / 60 sn.
    Gruplar birbirinden bagimsizdir.
  * Kayan pencere gunlugu (sliding-window log): grup basina en fazla `limit` zaman damgasi
    (30 + 120 float). Reddedilen istek sayac tuketmez ve kilidi uzatmaz. Bellek istek sayisindan
    bagimsiz, sabittir. Saat `time.monotonic` (testte enjekte edilebilir); kilit ile atomik.
  * Asim: HTTP 429, `Retry-After` (>=1 tam sayi sn), `Cache-Control: no-store`, sabit JSON govde.

BILEREK YAPILMAYANLAR (kapsam disi):
  * Istemci kimligi YOK. Kimlik dogrulama ve guvenilir istemci kimligi bulunmadigi icin
    `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, cerez veya `client` adresine GUVENILMEZ; limit
    grup basina kuresel tek kovadir. Sonuc: tek bir kotuye niyetli/yogun istemci grubun tum
    kotasini tuketebilir ve baska istemciler 429 alabilir. Istemci basina adil kota YOKTUR.
  * Tek surec / tek replika varsayimi: sayaclar surec belleginde tutulur. Coklu replika veya
    cok-isci (workers>1) dagitiminda her surecin kendi kovasi olur (etkin limit carpilir);
    Redis/DB gibi paylasimli depo kullanilmaz. Yeniden baslatma sayaclari sifirlar.
  * `/health` ve OPTIONS sinirsizdir (sahip karari).
"""

import math
import threading
import time
from collections import deque

WINDOW_SECONDS = 60.0
REPORTS_LIMIT = 30
DEFAULT_LIMIT = 120
EXEMPT_PATH = "/health"
COUNTED_METHODS = frozenset({"GET", "HEAD"})

_BODY = b'{"detail":"rate_limit_exceeded"}'


def _monotonic():
    return time.monotonic()


def classify(path):
    """Yol -> sabit grup: None (muaf), 'reports' veya 'default'. Yalniz ASGI `path` (cozulmus,
    normalize edilmemis) kullanilir; yonlendirici ayni degeri esler."""
    if path == EXEMPT_PATH:
        return None
    if path == "/reports" or path.startswith("/reports/"):
        return "reports"
    return "default"


class _Window:
    __slots__ = ("limit", "window", "hits")

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self.hits = deque(maxlen=limit)  # asla `limit`'ten fazla eleman tutmaz

    def acquire(self, now):
        """Izinliyse 0.0 doner ve istegi kaydeder; degilse beklenmesi gereken sureyi (sn, >0) doner."""
        hits = self.hits
        cutoff = now - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) < self.limit:
            hits.append(now)
            return 0.0
        return hits[0] + self.window - now


class RateLimitMiddleware:
    """Saf ASGI katmani; 'http' disindaki kapsamlar ve sayilmayan yontemler oldugu gibi gecer."""

    def __init__(self, app, limits=None, window=WINDOW_SECONDS, clock=None):
        self.app = app
        limits = limits or {"reports": REPORTS_LIMIT, "default": DEFAULT_LIMIT}
        self._windows = {group: _Window(n, window) for group, n in limits.items()}
        self._lock = threading.Lock()
        self._clock = clock

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = str(scope.get("method", "")).upper()
        group = classify(scope.get("path", "")) if method in COUNTED_METHODS else None
        if group is None:
            await self.app(scope, receive, send)
            return
        with self._lock:
            wait = self._windows[group].acquire((self._clock or _monotonic)())
        if wait <= 0:
            await self.app(scope, receive, send)
            return
        retry_after = max(1, math.ceil(wait))
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_BODY)).encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"retry-after", str(retry_after).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": 429, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if method == "HEAD" else _BODY})
