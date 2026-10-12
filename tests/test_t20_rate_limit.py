"""RG-0 / T-20 (R1) -- GET hiz siniri testleri.

Veritabani GEREKTIRMEZ: birim testleri sahte saatle `app.rate_limit` katmanini dogrudan surer; entegrasyon
testleri gercek `app/main.py` yiginini ALT SUREC icinde (sahte oturum, gecersiz/baglanilmayan DB URL'si,
`WORKER_ENABLED=false`) calistirir, boylece `app.db` ve ortam degiskenleri diger test modulunden etkilenmez.

Calistirma (repo kokunden):  python3 -m unittest tests.test_t20_rate_limit -v
Gereksinim: requirements.txt + httpx (Starlette TestClient icin; uretim imajina eklenmez).

Kapsam disi (bkz. app/rate_limit.py): istemci basina adil kota, coklu replika/cok-isci, kimlik dogrulama.
Bu testler T-20'yi TAM PASS yapmaz; yazma uclari kapali kalir (R0) ve hiz siniri yalnizca GET/HEAD icindir.
"""

import asyncio
import copy
import gc
import json
import os
import subprocess
import sys
import tempfile
import threading
import tracemalloc
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from app import rate_limit as rl  # noqa: E402  (yalniz standart kutuphane kullanir)

T0 = 1000.0
INNER_BODY = b'{"ok":1}'


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make(limits=None, clock=None):
    clk = clock or Clock()
    calls = []

    async def inner(scope, receive, send):
        if scope["type"] != "http":
            calls.append((scope["type"], None))
            return
        calls.append((scope["method"], scope["path"]))
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json"), (b"x-inner", b"1")]})
        await send({"type": "http.response.body", "body": INNER_BODY})

    return rl.RateLimitMiddleware(inner, limits=limits, clock=clk), clk, calls, inner


def scope_for(method, path, headers=(), client=("203.0.113.1", 5000)):
    return {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http", "path": path,
            "raw_path": path.encode(), "query_string": b"", "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
            "client": client, "server": ("testserver", 80)}


async def hit(app, method, path, headers=(), client=("203.0.113.1", 5000)):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    await app(scope_for(method, path, headers, client), receive, send)
    start = sent[0]
    body = b"".join(m.get("body", b"") for m in sent[1:])
    return start["status"], {k.decode(): v.decode() for k, v in start["headers"]}, body, sent


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def burst(app, n, method="GET", path="/reports/x", **kw):
    return [(await hit(app, method, path, **kw))[0] for _ in range(n)]


class RL1_Limits(unittest.TestCase):
    def test_pinned_defaults(self):
        self.assertEqual((rl.WINDOW_SECONDS, rl.REPORTS_LIMIT, rl.DEFAULT_LIMIT), (60.0, 30, 120))
        self.assertEqual(rl.EXEMPT_PATH, "/health")
        self.assertEqual(rl.COUNTED_METHODS, frozenset({"GET", "HEAD"}))

    def test_reports_30_per_60s_then_429_with_required_headers(self):
        mw, clk, calls, _ = make()
        st = run(burst(mw, 31, path="/reports/ingredient-frequency"))
        self.assertEqual(st, [200] * 30 + [429])
        self.assertEqual(len(calls), 30)  # 429 istegi uygulamaya ulasmadi
        status, h, body, _ = run(hit(mw, "GET", "/reports/ingredient-frequency"))
        self.assertEqual(status, 429)
        self.assertEqual(h["cache-control"], "no-store")
        self.assertEqual(h["retry-after"], "60")
        self.assertEqual(h["content-type"], "application/json")
        self.assertEqual(json.loads(body), {"detail": "rate_limit_exceeded"})
        self.assertEqual(int(h["content-length"]), len(body))

    def test_other_get_120_per_60s(self):
        mw, clk, calls, _ = make()
        self.assertEqual(run(burst(mw, 121, path="/products")), [200] * 120 + [429])
        self.assertEqual(run(burst(mw, 5, path="/restaurants")), [429] * 5)  # ayni 'default' kovasi
        self.assertEqual(run(burst(mw, 3, path="/docs")), [429] * 3)
        self.assertEqual(run(burst(mw, 3, path="/no-such-route")), [429] * 3)  # bilinmeyen yol da sayilir

    def test_groups_are_independent(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 30, path="/reports/a"))
        self.assertEqual(run(burst(mw, 1, path="/reports/a")), [429])
        self.assertEqual(run(burst(mw, 120, path="/products")), [200] * 120)  # reports dolu, default etkilenmez
        self.assertEqual(run(burst(mw, 1, path="/products")), [429])
        mw2, *_ = make()
        run(burst(mw2, 120, path="/products"))
        self.assertEqual(run(burst(mw2, 30, path="/reports/b")), [200] * 30)  # default dolu, reports etkilenmez

    def test_health_is_exempt_and_never_counted(self):
        mw, clk, calls, _ = make()
        self.assertEqual(run(burst(mw, 1000, path="/health")), [200] * 1000)
        self.assertEqual(len(mw._windows["default"].hits) + len(mw._windows["reports"].hits), 0)
        run(burst(mw, 30, path="/reports/a")), run(burst(mw, 120, path="/products"))
        self.assertEqual(run(burst(mw, 50, path="/health")), [200] * 50)  # kovalar doluyken de 200

    def test_options_exempt_head_counted(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 30, path="/reports/a"))
        self.assertEqual(run(burst(mw, 200, method="OPTIONS", path="/reports/a")), [200] * 200)  # muaf; uygulamaya gecer
        status, h, body, _ = run(hit(mw, "HEAD", "/reports/a"))
        self.assertEqual((status, body), (429, b""))  # HEAD sayilir; 429 govdesiz
        mw2, *_ = make()
        run(burst(mw2, 30, method="HEAD", path="/reports/a"))
        self.assertEqual(run(burst(mw2, 1, method="GET", path="/reports/a")), [429])  # HEAD ve GET ayni kovayi paylasir


class RL2_WindowSemantics(unittest.TestCase):
    def test_exact_renewal_boundary(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 30, path="/reports/a"))
        clk.t = T0 + 59.999
        self.assertEqual(run(hit(mw, "GET", "/reports/a"))[0], 429)
        clk.t = T0 + 60.0  # tam 60.000 sn: en eski kayit suresi doldu
        self.assertEqual(run(burst(mw, 31, path="/reports/a")), [200] * 30 + [429])

    def test_partial_sliding_renewal(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 10, path="/reports/a"))
        clk.advance(30)
        run(burst(mw, 20, path="/reports/a"))
        clk.advance(29)  # t=59: kova dolu
        st, h, *_ = run(hit(mw, "GET", "/reports/a"))
        self.assertEqual((st, h["retry-after"]), (429, "1"))
        clk.advance(1)  # t=60: ilk 10 kayit dustu
        self.assertEqual(run(burst(mw, 11, path="/reports/a")), [200] * 10 + [429])
        st, h, *_ = run(hit(mw, "GET", "/reports/a"))
        self.assertEqual((st, h["retry-after"]), (429, "30"))  # sirada t=30 kayitlari

    def test_retry_after_is_ceiled_and_at_least_one(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 30, path="/reports/a"))
        for dt, expected in ((0.2, "60"), (10.0, "50"), (49.5, "11"), (59.6, "1")):  # bekleme = 60 - dt, yukari yuvarlanir
            clk.t = T0 + dt
            st, h, *_ = run(hit(mw, "GET", "/reports/a"))
            self.assertEqual((st, h["retry-after"]), (429, expected), dt)
        for v in range(0, 600):
            clk.t = T0 + v * 0.0999
            st, h, *_ = run(hit(mw, "GET", "/reports/a"))
            if st == 429:
                self.assertTrue(1 <= int(h["retry-after"]) <= 60)

    def test_rejected_requests_do_not_consume_or_extend_the_lockout(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 30, path="/reports/a"))
        for i in range(1, 50):
            clk.t = T0 + i
            run(burst(mw, 50, path="/reports/a"))  # kilit sirasinda saldiri
        self.assertEqual(len(mw._windows["reports"].hits), 30)
        clk.t = T0 + 60
        self.assertEqual(run(burst(mw, 31, path="/reports/a")), [200] * 30 + [429])

    def test_default_clock_is_the_monotonic_clock_and_is_patchable(self):
        fake = Clock()
        orig = rl._monotonic
        rl._monotonic = fake
        try:
            mw = rl.RateLimitMiddleware(make()[3])  # saat verilmedi -> modul saati
            run(burst(mw, 30, path="/reports/a"))
            self.assertEqual(run(burst(mw, 1, path="/reports/a")), [429])
            fake.advance(60)
            self.assertEqual(run(burst(mw, 1, path="/reports/a")), [200])
        finally:
            rl._monotonic = orig
        import time
        self.assertLess(abs(rl._monotonic() - time.monotonic()), 5.0)


class RL3_ClientIdentityIsNeverTrusted(unittest.TestCase):
    def test_changing_clients_and_forwarding_headers_cannot_buy_extra_quota(self):
        mw, clk, calls, _ = make()
        st = []
        for i in range(40):
            hdrs = [("X-Forwarded-For", "198.51.100.%d" % i), ("X-Real-IP", "198.51.100.%d" % i), ("Forwarded", "for=192.0.2.%d" % i),
                    ("Authorization", "Bearer t%d" % i), ("Cookie", "s=%d" % i), ("User-Agent", "ua-%d" % i), ("X-Api-Key", "k%d" % i)]
            st.append(run(hit(mw, "GET", "/reports/a", headers=hdrs, client=("10.0.%d.%d" % (i, i), 4000 + i)))[0])
        self.assertEqual(st, [200] * 30 + [429] * 10)


class RL4_Classification(unittest.TestCase):
    def test_path_groups(self):
        for p in ("/reports", "/reports/", "/reports/ingredient-frequency", "/reports/product-matching", "/reports/x/y", "/reports/../health"):
            self.assertEqual(rl.classify(p), "reports", p)
        self.assertIsNone(rl.classify("/health"))
        for p in ("/", "/products", "/products/brands", "/restaurants", "/menus/x/status", "/docs", "/openapi.json", "/redoc", "/reportsX",
                  "/report/x", "//reports/x", "/Reports/x", "/REPORTS/x", "/health/", "/healthz", "/HEALTH", "//health", "/health/x", "", "/%72eports/x"):
            self.assertEqual(rl.classify(p), "default", p)

    def test_health_variants_are_not_free_riders(self):
        mw, clk, calls, _ = make()
        run(burst(mw, 120, path="/products"))
        for p in ("/health/", "//health", "/Health", "/healthz"):
            self.assertEqual(run(burst(mw, 1, path=p)), [429], p)
        self.assertEqual(run(burst(mw, 1, path="/health")), [200])


class RL5_PassThroughAndPriority(unittest.TestCase):
    def test_allowed_responses_are_forwarded_untouched(self):
        mw, clk, calls, inner = make()
        _, _, _, via_limiter = run(hit(mw, "GET", "/products"))
        _, _, _, direct = run(hit(inner, "GET", "/products"))
        self.assertEqual(via_limiter, direct)  # ayni mesajlar: ekstra baslik/govde degisikligi yok
        self.assertEqual(copy.deepcopy(via_limiter)[1]["body"], INNER_BODY)
        self.assertNotIn(b"x-ratelimit", b"".join(k for k, _ in via_limiter[0]["headers"]).lower())

    def test_non_http_scopes_pass_through_and_touch_no_counters(self):
        mw, clk, calls, _ = make()

        async def go():
            async def rcv():
                return {}

            async def snd(m):
                raise AssertionError("limiter must not send for non-http scopes")

            for t in ("lifespan", "websocket"):
                await mw({"type": t, "asgi": {"version": "3.0"}}, rcv, snd)

        run(go())
        self.assertEqual(calls, [("lifespan", None), ("websocket", None)])
        self.assertEqual(sum(len(w.hits) for w in mw._windows.values()), 0)

    def test_write_methods_pass_through_this_layer_and_never_consume_quota(self):
        mw, clk, calls, _ = make()
        for m in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "FOO"):
            self.assertEqual(run(burst(mw, 100, method=m, path="/reports/a")), [200] * 100, m)
        self.assertEqual(sum(len(w.hits) for w in mw._windows.values()), 0)  # yazma kotadan yemez
        self.assertEqual(run(burst(mw, 31, path="/reports/a")), [200] * 30 + [429])  # GET kotasi hala tam


class RL6_ConcurrencyAndMemory(unittest.TestCase):
    def test_threads_never_exceed_the_limit(self):
        mw, clk, calls, _ = make()
        results, barrier = [], threading.Barrier(8)

        def worker():
            barrier.wait()
            r = run(burst(mw, 100, path="/reports/a"))
            results.extend(r)

        ts = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(results), 800)
        self.assertEqual(results.count(200), 30)
        self.assertEqual(results.count(429), 770)

    def test_threads_with_aggressive_switching_never_exceed_the_limit(self):
        """Kilidin gercekten gerekli oldugunu zorlar: cok kisa thread-gecis araligi, cok tur."""
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            for rnd in range(30):
                mw, clk, calls, _ = make()
                results, barrier = [], threading.Barrier(16)

                def worker():
                    barrier.wait()
                    results.extend(run(burst(mw, 40, path="/reports/a")))

                ts = [threading.Thread(target=worker) for _ in range(16)]
                [t.start() for t in ts]
                [t.join() for t in ts]
                self.assertEqual(results.count(200), 30, "round %d: limit exceeded or under-served" % rnd)
                self.assertLessEqual(len(mw._windows["reports"].hits), 30)
        finally:
            sys.setswitchinterval(old)

    def test_asyncio_gather_never_exceeds_the_limit(self):
        mw, clk, calls, _ = make()

        async def go():
            return await asyncio.gather(*[hit(mw, "GET", "/products") for _ in range(500)])

        st = [r[0] for r in run(go())]
        self.assertEqual((st.count(200), st.count(429)), (120, 380))

    def test_state_and_memory_are_bounded_regardless_of_request_volume(self):
        mw, clk, calls, _ = make()
        self.assertEqual(sorted(mw.__dict__), ["_clock", "_lock", "_windows", "app"])
        self.assertEqual({k: w.hits.maxlen for k, w in mw._windows.items()}, {"reports": 30, "default": 120})

        async def go(n):
            for i in range(n):
                clk.advance(0.003)
                await hit(mw, "GET", "/reports/a" if i % 3 else "/products", headers=[("X-Forwarded-For", "10.%d.%d.%d" % (i % 250, i % 97, i % 13))])

        run(go(3000))
        gc.collect()
        tracemalloc.start()
        before = tracemalloc.take_snapshot()
        run(go(30000))
        gc.collect()
        after = tracemalloc.take_snapshot()
        tracemalloc.stop()
        growth = sum(s.size_diff for s in after.compare_to(before, "filename"))
        self.assertLess(growth, 300 * 1024, "memory grew with request volume: %d bytes" % growth)
        self.assertLessEqual(len(mw._windows["reports"].hits), 30)
        self.assertLessEqual(len(mw._windows["default"].hits), 120)
        self.assertEqual(sorted(mw._windows), ["default", "reports"])  # yeni grup/anahtar uretilmez


# --------------------------------------------------------------------------- gercek yigin: alt surec
SCRIPT = r'''
import json, os, sys, threading, time
sys.path.insert(0, os.getcwd())
from app import rate_limit as rl
import app.main as m
from app.db import get_session

class R:
    def fetchall(self): return []
class Q:
    def filter(self, *a, **k): return self
    filter_by = filter
    distinct = filter
    def all(self): return []
    def get(self, *a): return None
    def first(self): return None
class S:
    def query(self, *a, **k): return Q()
    def execute(self, *a, **k): return R()
m.app.dependency_overrides[get_session] = lambda: S()
A, F = "https://allowed.example", "https://evil.example"
res = {"middleware": [x.cls.__name__ for x in m.app.user_middleware]}
mode = sys.argv[1]

if mode == "stack":
    from starlette.testclient import TestClient
    clock = [1000.0]
    rl._monotonic = lambda: clock[0]
    c = TestClient(m.app, raise_server_exceptions=False)
    def g(method, path, origin=None, headers=None, **kw):
        h = dict(headers or {})
        if origin is not None: h["Origin"] = origin
        return c.request(method, path, headers=h, **kw)
    def info(r): return {"status": r.status_code, "acao": r.headers.get("access-control-allow-origin"), "retry_after": r.headers.get("retry-after"),
                         "cache_control": r.headers.get("cache-control"), "body": r.text}
    res["reports_first30"] = [g("GET", "/reports/ingredient-frequency", A).status_code for _ in range(30)]
    res["reports_31_allowed_origin"] = info(g("GET", "/reports/ingredient-frequency", A))
    res["reports_31_foreign_origin"] = info(g("GET", "/reports/ingredient-frequency", F))
    res["reports_31_no_origin"] = info(g("GET", "/reports/ingredient-frequency"))
    res["reports_product_matching_429"] = g("GET", "/reports/product-matching?brand=x").status_code
    writes = []
    for method, path, kw in (("POST", "/restaurants", {}), ("POST", "/products", {}), ("POST", "/products/bulk", {}),
                             ("POST", "/restaurants/00000000-0000-0000-0000-000000000000/menus", {}), ("POST", "/import/csv-menu", {"content": b"null", "headers": {"content-type": "application/json"}}),
                             ("PUT", "/products", {}), ("DELETE", "/restaurants", {}), ("POST", "/reports/ingredient-frequency", {}), ("POST", "/no-such", {})):
        for origin in (None, A):
            r = g(method, path, origin, **kw)
            writes.append({"m": method, "p": path, "origin": origin, "status": r.status_code, "body": r.text, "acao": r.headers.get("access-control-allow-origin")})
    res["writes_while_reports_exhausted"] = writes
    res["get_body_untouched"] = [g("GET", "/products").text, g("GET", "/restaurants").text]
    res["default_first_118"] = [g("GET", "/products", A).status_code for _ in range(118)]  # 2 yukarida harcandi (/products, /restaurants)
    res["default_next"] = [g("GET", "/restaurants", A).status_code, g("GET", "/products", A).status_code]
    r = g("GET", "/docs", A); res["default_429_docs"] = info(r)
    res["default_429_unknown_path"] = g("GET", "/no-such-route").status_code
    res["health_when_exhausted"] = [g("GET", "/health").status_code for _ in range(5)]
    res["preflight_get_exhausted"] = {"status": g("OPTIONS", "/products", A, headers={"Access-Control-Request-Method": "GET"}).status_code,
                                      "acao": g("OPTIONS", "/products", A, headers={"Access-Control-Request-Method": "GET"}).headers.get("access-control-allow-origin")}
    res["preflight_post_exhausted"] = g("OPTIONS", "/products", A, headers={"Access-Control-Request-Method": "POST"}).status_code
    res["writes_when_both_exhausted"] = [g(mm, pp, A).status_code for mm, pp in (("POST", "/products"), ("POST", "/import/csv-menu"), ("PUT", "/products"), ("DELETE", "/restaurants"))]
    res["wildcard_seen"] = any(x.get("acao") == "*" for x in res["writes_while_reports_exhausted"])
    clock[0] += 60.0
    res["after_60s"] = [g("GET", "/products").status_code, g("GET", "/reports/ingredient-frequency").status_code]
else:
    import http.client, uvicorn
    srv = uvicorn.Server(uvicorn.Config(m.app, host="127.0.0.1", port=0, log_level="warning", lifespan="off"))
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    for _ in range(100):
        if srv.started: break
        time.sleep(0.1)
    port = srv.servers[0].sockets[0].getsockname()[1]
    def hc(method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request(method, path, headers=headers or {})
        r = conn.getresponse(); b = r.read(); h = {k.lower(): v for k, v in r.getheaders()}; conn.close()
        return r.status, h, b.decode()
    res["statuses"] = [hc("GET", "/reports/ingredient-frequency")[0] for _ in range(31)]
    s, h, b = hc("GET", "/reports/ingredient-frequency")
    res["limited"] = {"status": s, "retry_after": h.get("retry-after"), "cache_control": h.get("cache-control"), "body": b}
    s, h, b = hc("HEAD", "/reports/ingredient-frequency")
    res["head_limited"] = {"status": s, "body": b}
    res["health"] = hc("GET", "/health")[0]
    s, h, b = hc("POST", "/products"); res["post"] = {"status": s, "body": b}
    s, h, b = hc("OPTIONS", "/products", {"Origin": F, "Access-Control-Request-Method": "POST"}); res["preflight_post"] = {"status": s, "acao": h.get("access-control-allow-origin")}
    srv.should_exit = True; t.join(timeout=10)
print("RESULT_JSON=" + json.dumps(res, sort_keys=True))
'''


def run_script(mode):
    env = dict(os.environ)
    env.update({"DATABASE_URL": "postgresql://nouser:nopass@127.0.0.1:1/none", "WORKER_ENABLED": "false",
                "CORS_ALLOWED_ORIGINS": "https://allowed.example", "UPLOAD_DIR": tempfile.mkdtemp(prefix="rps_rl_up_"),
                "PYTHONDONTWRITEBYTECODE": "1"})
    for k in ("RPS_T20_ADMIN_URL", "RPS_T20_EVIDENCE_DIR"):
        env.pop(k, None)
    p = subprocess.run([sys.executable, "-W", "ignore", "-c", SCRIPT, mode], cwd=str(REPO), env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=180)
    out = p.stdout.decode("utf-8", "replace")
    line = [l for l in out.splitlines() if l.startswith("RESULT_JSON=")]
    if p.returncode != 0 or not line:
        raise AssertionError("integration subprocess failed (exit %s):\n%s" % (p.returncode, out[-3000:]))
    return json.loads(line[0][len("RESULT_JSON="):])


class RL7_RealStackThroughMainPy(unittest.TestCase):
    """app/main.py'in gercek yigini: CORS -> WriteGuard -> RateLimit, sahte saat, sahte oturum."""

    @classmethod
    def setUpClass(cls):
        cls.r = run_script("stack")

    def test_wiring_order(self):
        self.assertEqual(self.r["middleware"], ["CORSMiddleware", "WriteGuardMiddleware", "RateLimitMiddleware"])

    def test_reports_limit_and_429_shape_through_the_real_stack(self):
        r = self.r
        self.assertEqual(r["reports_first30"], [200] * 30)
        for k in ("reports_31_allowed_origin", "reports_31_foreign_origin", "reports_31_no_origin"):
            self.assertEqual(r[k]["status"], 429, k)
            self.assertEqual(r[k]["cache_control"], "no-store")
            self.assertEqual(r[k]["retry_after"], "60")
            self.assertEqual(json.loads(r[k]["body"]), {"detail": "rate_limit_exceeded"})
        self.assertEqual(r["reports_product_matching_429"], 429)  # /reports/* tek kova

    def test_cors_unchanged_on_429(self):
        r = self.r
        self.assertEqual(r["reports_31_allowed_origin"]["acao"], "https://allowed.example")  # CORS en disa: tarayici 429'u okuyabilir
        self.assertIsNone(r["reports_31_foreign_origin"]["acao"])
        self.assertIsNone(r["reports_31_no_origin"]["acao"])
        self.assertEqual(r["default_429_docs"]["acao"], "https://allowed.example")
        self.assertFalse(r["wildcard_seen"])
        self.assertEqual(r["preflight_get_exhausted"], {"status": 200, "acao": "https://allowed.example"})  # OPTIONS muaf
        self.assertEqual(r["preflight_post_exhausted"], 400)  # POST on-ucusu yine basarisiz

    def test_writes_stay_403_even_when_the_limit_is_full(self):
        for w in self.r["writes_while_reports_exhausted"]:
            self.assertEqual(w["status"], 403, w)
            self.assertEqual(json.loads(w["body"]), {"detail": "write_endpoints_closed"})
        self.assertEqual(self.r["writes_when_both_exhausted"], [403, 403, 403, 403])

    def test_default_group_120_and_health_exempt(self):
        r = self.r
        self.assertEqual(r["default_first_118"], [200] * 118)  # 2 + 118 = 120
        self.assertEqual(r["default_next"], [429, 429])
        self.assertEqual(r["default_429_unknown_path"], 429)
        self.assertEqual(r["health_when_exhausted"], [200] * 5)

    def test_get_bodies_untouched_and_quota_renews_after_60s(self):
        self.assertEqual(self.r["get_body_untouched"], ["[]", "[]"])
        self.assertEqual(self.r["after_60s"], [200, 200])


class RL8_LiveUvicorn(unittest.TestCase):
    def test_real_http_429_headers_head_and_403_priority(self):
        r = run_script("live")
        self.assertEqual(r["statuses"], [200] * 30 + [429])
        self.assertEqual(r["limited"]["status"], 429)
        self.assertEqual(r["limited"]["cache_control"], "no-store")
        self.assertTrue(1 <= int(r["limited"]["retry_after"]) <= 60)
        self.assertEqual(json.loads(r["limited"]["body"]), {"detail": "rate_limit_exceeded"})
        self.assertEqual(r["head_limited"], {"status": 429, "body": ""})
        self.assertEqual(r["health"], 200)
        self.assertEqual(r["post"]["status"], 403)
        self.assertEqual(json.loads(r["post"]["body"]), {"detail": "write_endpoints_closed"})
        self.assertEqual(r["preflight_post"], {"status": 400, "acao": None})


if __name__ == "__main__":
    unittest.main()
