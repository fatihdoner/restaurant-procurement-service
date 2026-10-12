"""RG-0 / T-20 (R0) -- yazma uclari fail-closed: guvenlik testleri.

Bu testler SADECE yalitilmis, gecici (throwaway) bir PostgreSQL 18 cluster'inda calisir:
  RPS_T20_ADMIN_URL  loopback (127.0.0.1/::1/localhost) uzerindeki cluster, yonetici baglantisi
  RPS_T20_PGDATA     cluster'in beklenen veri dizini (SHOW data_directory ile ayni olmali)
Her kosu icin `rps_t20_<hex>` adli yeni bir veritabani acilir ve sonunda silinir.
Degiskenler yoksa/uyusmuyorsa test BASLAMAZ (atlanmaz, basarisiz olur).

Calistirma (repo kokunden):  python3 -m unittest tests.test_t20_write_closed -v
Gereksinim: requirements.txt + httpx (Starlette TestClient icin; uretim imajina eklenmez).
Isteğe bagli: RPS_T20_EVIDENCE_DIR -> http_log.jsonl, cors_probe.json, isolation.json, summary.json

Bu testler T-20'nin TAMAMINI kanitlamaz: rate limit yok (R0), uretim dogrulamasi yok.
"""

import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REPO = Path(__file__).resolve().parent.parent
BASE_SHA = "29ac32b4e744ddf2c95889aa150d5dda68974708"
BASE_MAIN_SHA256 = "a837c29fb2158810e673c5f586990307133c65764b57325fbf992a22a218b4df"
ALLOWED_ORIGIN = "https://allowed.example"
FOREIGN_ORIGIN = "https://evil.example"
SAFE = {"GET", "HEAD", "OPTIONS"}
DENIED_JSON = {"detail": "write_endpoints_closed"}
PROBE = "T20PROBE"

G = {}
HTTP_LOG = []
NET = {"violations": [], "expected": []}


# --------------------------------------------------------------------------- module setup
def _is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _install_network_guard():
    """Python-seviyesinde loopback disi soket baglantisini engeller (anthropic/httpx vb.).
    Not: libpq (psycopg2) kendi baglantisini yapar; DB URL'i ayrica loopback olarak dogrulanir."""
    orig_connect, orig_connect_ex, orig_gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def local(self, addr):
        if self.family == socket.AF_UNIX:
            return True
        return _is_loopback(addr[0])

    def connect(self, addr):
        if not local(self, addr):
            NET["violations"].append(str(addr[0]))
            raise OSError("t20: non-loopback network access blocked")
        return orig_connect(self, addr)

    def connect_ex(self, addr):
        if not local(self, addr):
            NET["violations"].append(str(addr[0]))
            return 1
        return orig_connect_ex(self, addr)

    def getaddrinfo(host, *a, **kw):
        if isinstance(host, (str, bytes)):
            h = host.decode() if isinstance(host, bytes) else host
            if h and not _is_loopback(h):
                NET["violations"].append(h)
                raise socket.gaierror("t20: non-loopback name resolution blocked")
        return orig_gai(host, *a, **kw)

    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, getaddrinfo
    G["net_orig"] = (orig_connect, orig_connect_ex, orig_gai)


def _uninstall_network_guard():
    if "net_orig" in G:
        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = G.pop("net_orig")


def _load_main(label, path, cors):
    saved = {k: os.environ.get(k) for k in ("UPLOAD_DIR", "CORS_ALLOWED_ORIGINS")}
    upload = G["tmp"] / ("uploads_" + label)
    upload.mkdir(exist_ok=True)
    os.environ["UPLOAD_DIR"] = str(upload)
    if cors is None:
        os.environ.pop("CORS_ALLOWED_ORIGINS", None)
    else:
        os.environ["CORS_ALLOWED_ORIGINS"] = cors
    try:
        spec = importlib.util.spec_from_file_location("t20_main_" + label, str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod, upload


def setUpModule():
    admin = os.environ.get("RPS_T20_ADMIN_URL")
    expect_dd = os.environ.get("RPS_T20_PGDATA")
    if not admin or not expect_dd:
        raise AssertionError("RPS_T20_ADMIN_URL and RPS_T20_PGDATA are required: tests run only on the isolated throwaway cluster")
    u = urlsplit(admin)
    if not _is_loopback(u.hostname or ""):
        raise AssertionError("admin URL host is not loopback")

    import psycopg2

    G["tmp"] = Path(tempfile.mkdtemp(prefix="rps_t20_"))
    unittest.addModuleCleanup(_cleanup)  # setUpModule yarida kalsa da calisir
    sys_tmp = G["tmp"] / "sys_tmp"
    sys_tmp.mkdir()
    G["old_tempdir"] = tempfile.tempdir
    tempfile.tempdir = str(sys_tmp)  # Starlette'in multipart spool'u buraya duser -> gozlenebilir
    G["sys_tmp"] = sys_tmp

    ac = psycopg2.connect(admin)
    ac.autocommit = True
    cur = ac.cursor()
    cur.execute("select current_setting('server_version_num')::int, current_setting('data_directory'), "
                "coalesce(host(inet_server_addr()),'unix'), current_setting('server_version')")
    ver_num, data_dir, srv_addr, ver = cur.fetchone()
    if not (180000 <= ver_num < 190000):
        raise AssertionError("cluster is not PostgreSQL 18")
    if os.path.realpath(data_dir) != os.path.realpath(expect_dd):
        raise AssertionError("cluster data_directory does not match RPS_T20_PGDATA")
    if "rps-api-i1-pg18" in data_dir:
        raise AssertionError("refusing to run on the API-I1 cluster")
    if not _is_loopback(srv_addr):
        raise AssertionError("cluster is not reached over loopback")
    dbname = "rps_t20_" + uuid.uuid4().hex[:12]
    assert dbname.startswith("rps_t20_")
    cur.execute('create database "%s"' % dbname)
    G["admin_conn"], G["dbname"] = ac, dbname
    G["db_url"] = urlunsplit(u._replace(path="/" + dbname))
    G["isolation"] = {"server_version": ver, "server_version_num": ver_num, "server_addr": srv_addr,
                      "port": u.port, "data_directory_matches_env": True, "database": dbname,
                      "python": sys.version.split()[0]}

    os.environ["DATABASE_URL"] = G["db_url"]
    os.environ["WORKER_ENABLED"] = "false"
    os.environ.pop("INGREDIENT_WRITE_MODE", None)
    sys.path.insert(0, str(REPO))
    _install_network_guard()

    import app.db as dbm
    from sqlalchemy import create_engine, event

    if dbm.DATABASE_URL != G["db_url"]:
        raise AssertionError("app.db was imported with another DATABASE_URL")
    G["dbm"] = dbm
    G["conn"] = {"connect": 0, "checkout": 0}
    event.listen(dbm.engine, "connect", lambda *a: G["conn"].__setitem__("connect", G["conn"]["connect"] + 1))
    event.listen(dbm.engine, "checkout", lambda *a: G["conn"].__setitem__("checkout", G["conn"]["checkout"] + 1))
    G["fp_engine"] = create_engine(G["db_url"], pool_pre_ping=True)  # sayac disi, parmak izi icin
    dbm.Base.metadata.create_all(dbm.engine)
    G["tables"] = [t.name for t in dbm.Base.metadata.sorted_tables]
    _seed(dbm)

    # yamasiz taban uygulama (yalniz yalitilmis kontrol/diferansiyel icin)
    src = subprocess.run(["git", "show", BASE_SHA + ":app/main.py"], cwd=str(REPO), check=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    if hashlib.sha256(src).hexdigest() != BASE_MAIN_SHA256:
        raise AssertionError("baseline app/main.py hash mismatch")
    base_path = G["tmp"] / "baseline_main.py"
    base_path.write_bytes(src)

    from starlette.testclient import TestClient

    G["mods"], G["uploads"], G["clients"], G["startup"] = {}, {}, {}, {}
    for label, path, cors in (("default", REPO / "app" / "main.py", None),
                              ("allow", REPO / "app" / "main.py", ALLOWED_ORIGIN),
                              ("baseline", base_path, None)):
        mod, up = _load_main(label, path, cors)
        G["mods"][label], G["uploads"][label] = mod, up
        client = TestClient(mod.app, raise_server_exceptions=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            client.__enter__()  # lifespan startup
        G["clients"][label], G["startup"][label] = client, buf.getvalue()


def _seed(dbm):
    with dbm.SessionLocal() as s:
        brand = dbm.RestaurantBrand(name="Seed Brand", restaurant_type="burger")
        s.add(brand)
        s.flush()
        rest = dbm.Restaurant(brand_id=brand.id, name="Seed Brand", city="Istanbul", district="Kadikoy")
        s.add(rest)
        s.flush()
        menu = dbm.Menu(restaurant_id=rest.id, source_file_url="excel-import", source_file_name="excel-import", status="completed")
        s.add(menu)
        s.flush()
        sec = dbm.MenuSection(menu_id=menu.id, name="Menu")
        s.add(sec)
        s.flush()
        item = dbm.MenuItem(menu_section_id=sec.id, name="Burger", price=10, raw_description_text="sut, tuz")
        s.add(item)
        s.flush()
        ing = dbm.Ingredient(canonical_name="Sut")
        s.add(ing)
        s.flush()
        s.add(dbm.IngredientAlias(ingredient_id=ing.id, alias_text="sut", source="seed", confidence_score=99))
        s.add(dbm.MenuItemIngredient(menu_item_id=item.id, ingredient_id=ing.id, raw_text="sut", extraction_type="explicit", confidence_score=99))
        s.add(dbm.Product(brand="Yayla", name="Sut"))
        s.add(dbm.Product(brand="Yayla", name="Peynir"))
        s.commit()
        G["ids"] = {"restaurant": rest.id, "menu": menu.id}


def tearDownModule():
    try:
        for c in G.get("clients", {}).values():
            with contextlib.suppress(Exception):
                c.__exit__(None, None, None)
        problems = []
        wild = [r for r in HTTP_LOG if r["app"] != "baseline" and r.get("acao") == "*"]
        if wild:
            problems.append("wildcard Access-Control-Allow-Origin observed on a patched app: %d responses" % len(wild))
        if set(NET["violations"]) != set(NET["expected"]):
            problems.append("unexpected non-loopback network attempts: %s" % sorted(set(NET["violations"]) - set(NET["expected"])))
        ev = os.environ.get("RPS_T20_EVIDENCE_DIR")
        if ev:
            d = Path(ev)
            d.mkdir(parents=True, exist_ok=True)
            (d / "http_log.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False, sort_keys=True) for r in HTTP_LOG) + "\n", encoding="utf-8")
            probe = [r for r in HTTP_LOG if r.get("origin") or r["method"] == "OPTIONS"]
            (d / "cors_probe.json").write_text(json.dumps(probe, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
            (d / "isolation.json").write_text(json.dumps(dict(G.get("isolation", {}), network_probe_hosts_blocked=sorted(set(NET["violations"])),
                                                              tables_fingerprinted=G.get("tables"), startup_logs=G.get("startup")),
                                                         indent=1, sort_keys=True), encoding="utf-8")
            (d / "summary.json").write_text(json.dumps({"http_requests_logged": len(HTTP_LOG), "app_connections_total": G.get("conn")}, indent=1), encoding="utf-8")
        if problems:
            raise AssertionError("; ".join(problems))
    finally:
        _uninstall_network_guard()


def _cleanup():
    """Kaynak temizligi (tearDownModule'dan sonra ya da setUpModule basarisiz olunca): gecici veritabani, dizinler."""
    _uninstall_network_guard()
    if "old_tempdir" in G:
        tempfile.tempdir = G.pop("old_tempdir")
    with contextlib.suppress(Exception):
        G["dbm"].engine.dispose()
    with contextlib.suppress(Exception):
        G["fp_engine"].dispose()
    with contextlib.suppress(Exception):
        cur = G["admin_conn"].cursor()
        assert G["dbname"].startswith("rps_t20_")
        cur.execute('drop database if exists "%s" with (force)' % G["dbname"])
        G["admin_conn"].close()
    with contextlib.suppress(Exception):
        import shutil
        shutil.rmtree(str(G["tmp"]), ignore_errors=True)


# --------------------------------------------------------------------------- helpers
def send(label, method, path, origin=None, headers=None, **kw):
    h = dict(headers or {})
    if origin is not None:
        h["Origin"] = origin
    r = G["clients"][label].request(method, path, headers=h, **kw)
    HTTP_LOG.append({"app": label, "method": method, "path": path.split("?")[0], "origin": origin, "status": r.status_code,
                     "acao": r.headers.get("access-control-allow-origin"),
                     "acam": r.headers.get("access-control-allow-methods"),
                     "acac": r.headers.get("access-control-allow-credentials"),
                     "allow": r.headers.get("allow"), "cache_control": r.headers.get("cache-control"),
                     "connection": r.headers.get("connection"), "body": r.text[:100]})
    return r


def fingerprint(conn=None):
    """Tum tablolarin (satir sayisi, icerik ozeti). conn verilmezse ayri (sayac disi) motor kullanilir."""
    own = conn is None
    c = G["fp_engine"].connect() if own else conn
    try:
        out = {}
        for name in G["tables"]:
            out[name] = tuple(c.exec_driver_sql(
                'select count(*), coalesce(md5(string_agg(t::text, \'|\' order by t::text)), \'\') from "%s" t' % name).fetchone())
        n_public = c.exec_driver_sql("select count(*) from information_schema.tables where table_schema='public'").scalar()
        out["__public_table_count__"] = n_public
        return out
    finally:
        if own:
            c.close()


def listing(p):
    return sorted(str(x.relative_to(p)) for x in Path(p).rglob("*"))


def _forbidden_session():
    G["forbidden_calls"] = G.get("forbidden_calls", 0) + 1
    raise AssertionError("get_session was reached: a DB session would have been opened")
    yield  # pragma: no cover


def _forbidden_sessionlocal(*a, **kw):
    G["forbidden_calls"] = G.get("forbidden_calls", 0) + 1
    raise AssertionError("SessionLocal() was called: a DB session would have been opened")


@contextlib.contextmanager
def no_side_effects(tc, labels=("default",)):
    """Blok boyunca: DB parmak izi, yukleme dizinleri, sistem tmp dizini degismez; get_session /
    SessionLocal cagrilirsa ve uygulama motoru hic baglanti acarsa test duser."""
    dbm = G["dbm"]
    before = (fingerprint(), {l: listing(G["uploads"][l]) for l in labels}, listing(G["sys_tmp"]))
    G["conn"].update(connect=0, checkout=0)
    G["forbidden_calls"] = 0
    for l in labels:
        G["mods"][l].app.dependency_overrides[dbm.get_session] = _forbidden_session
    orig_sl = dbm.SessionLocal
    dbm.SessionLocal = _forbidden_sessionlocal
    try:
        yield
    finally:
        dbm.SessionLocal = orig_sl
        for l in labels:
            G["mods"][l].app.dependency_overrides.pop(dbm.get_session, None)
    after = (fingerprint(), {l: listing(G["uploads"][l]) for l in labels}, listing(G["sys_tmp"]))
    tc.assertEqual(before[0], after[0], "DB rows changed")
    tc.assertEqual(before[1], after[1], "a persistent upload file was created/changed")
    tc.assertEqual(before[2], after[2], "request body was spooled to disk")
    tc.assertEqual(G["forbidden_calls"], 0, "a DB session was requested")
    tc.assertEqual(G["conn"], {"connect": 0, "checkout": 0}, "the application engine opened/checked out a connection")


def write_cases(tag=PROBE):
    rid = G["ids"]["restaurant"]
    return [
        ("POST /restaurants", "POST", "/restaurants", dict(params={"name": tag + "-n", "brand_name": tag + "-b", "city": "c", "district": "d"})),
        ("POST /products", "POST", "/products", dict(params={"name": tag + "-p", "brand": tag + "-br"})),
        ("POST /products/bulk", "POST", "/products/bulk", dict(params={"brand": tag + "-br"}, json=[tag + "-1", tag + "-2"])),
        ("POST /restaurants/{id}/menus", "POST", "/restaurants/%s/menus" % rid,
         dict(files={"file": (tag + ".pdf", b"%PDF-1.4 " + tag.encode() * 200, "application/pdf")})),
        ("POST /import/csv-menu", "POST", "/import/csv-menu",
         dict(json={"city": "c", "district": "d", "rows": [{"marka": tag, "yemek": tag + "-y", "icerik": "sut, tuz", "fiyat": "10"}]})),
    ]


def assert_denied(tc, r):
    tc.assertEqual(r.status_code, 403)
    tc.assertEqual(r.json(), DENIED_JSON)
    tc.assertNotIn(PROBE.encode(), r.content, "request data was echoed")
    tc.assertNotIn("set-cookie", r.headers)


# --------------------------------------------------------------------------- N1
class N1_FiveEndpointsRejectAnonymous(unittest.TestCase):
    def test_each_write_endpoint_returns_fixed_403(self):
        with no_side_effects(self, ("default", "allow")):
            for lbl in ("default", "allow"):
                for name, m, p, kw in write_cases():
                    with self.subTest(app=lbl, endpoint=name):
                        r = send(lbl, m, p, **kw)
                        assert_denied(self, r)
                        self.assertEqual(r.headers["cache-control"], "no-store")
                        self.assertEqual(r.headers["content-type"], "application/json")


# --------------------------------------------------------------------------- N2
class N2_MalformedBodiesRejectedUnprocessed(unittest.TestCase):
    def bad_cases(self):
        rid = G["ids"]["restaurant"]
        js = {"content-type": "application/json"}
        mp = {"content-type": "multipart/form-data; boundary=BND"}
        return [
            ("bulk bad json", "/products/bulk?brand=b", dict(content=b"{not json", headers=js)),
            ("bulk missing brand", "/products/bulk", dict(json=["a"])),
            ("csv empty body", "/import/csv-menu", dict(content=b"", headers=js)),
            ("csv truncated json", "/import/csv-menu", dict(content=b"[1,2", headers=js)),
            ("csv invalid utf8", "/import/csv-menu", dict(content=b"\xff\xfe\x00", headers=js)),
            ("csv json null", "/import/csv-menu", dict(content=b"null", headers=js)),
            ("csv json list", "/import/csv-menu", dict(json=[PROBE])),
            ("csv wrong content-type", "/import/csv-menu", dict(content=PROBE.encode(), headers={"content-type": "text/plain"})),
            ("menus truncated multipart", "/restaurants/%s/menus" % rid, dict(content=b"--BND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"\r\n\r\n%PDF", headers=mp)),
            ("menus no file part", "/restaurants/%s/menus" % rid, dict(content=b"--BND--\r\n", headers=mp)),
            ("menus wrong content-type", "/restaurants/%s/menus" % rid, dict(content=PROBE.encode(), headers={"content-type": "text/plain"})),
            ("menus unknown restaurant", "/restaurants/%s/menus" % uuid.uuid4(), dict(files={"file": ("a.pdf", b"x" * 10)})),
            ("restaurants no params", "/restaurants", dict()),
            ("products no params", "/products", dict()),
            ("products no body, bad content-length", "/products", dict(headers={"content-length": "999999"}, content=b"")),
        ]

    def test_all_rejected_with_403_and_no_side_effects(self):
        with no_side_effects(self, ("default", "allow")):
            for lbl in ("default", "allow"):
                for name, path, kw in self.bad_cases():
                    with self.subTest(app=lbl, case=name):
                        r = send(lbl, "POST", path, **kw)
                        assert_denied(self, r)

    def test_control_unguarded_baseline_answers_these_with_validation_errors_not_403(self):
        """Kontrol: yamasiz uygulamada ayni bozuk istekler 403 degil dogrulama hatasi (400/422) alir;
        yani guard'in onceligi gercek (rota bagimliligi olsaydi 422 403'un onune gecerdi)."""
        dbm = G["dbm"]
        conn = G["fp_engine"].connect()
        trans = conn.begin()
        from sqlalchemy.orm import Session

        def sess():
            s = Session(bind=conn, autoflush=False, join_transaction_mode="create_savepoint")
            try:
                yield s
            finally:
                s.close()

        app = G["mods"]["baseline"].app
        app.dependency_overrides[dbm.get_session] = sess
        try:
            for name, path, kw in self.bad_cases()[:3] + self.bad_cases()[12:14]:
                r = send("baseline", "POST", path, **kw)
                self.assertIn(r.status_code, (400, 422), name)
        finally:
            app.dependency_overrides.pop(dbm.get_session, None)
            trans.rollback()
            conn.close()


# --------------------------------------------------------------------------- N3 (+ detector kontrolu)
class N3_DbUntouchedAndDetectorWorks(unittest.TestCase):
    def test_denied_requests_leave_every_table_identical(self):
        with no_side_effects(self, ("default",)):
            for _ in range(3):
                for name, m, p, kw in write_cases():
                    assert_denied(self, send("default", m, p, **kw))

    def test_positive_control_unguarded_baseline_writes_and_detector_sees_it(self):
        """Kontrol (yalniz izole kosu): yamasiz uygulama ayni istekleri gercekten yazar ve parmak izi bunu gorur.
        Yazmalar harici bir transaction icinde yapilir ve GERI ALINIR."""
        dbm = G["dbm"]
        from sqlalchemy.orm import Session
        conn = G["fp_engine"].connect()
        trans = conn.begin()

        def sess():
            s = Session(bind=conn, autoflush=False, join_transaction_mode="create_savepoint")
            try:
                yield s
            finally:
                s.close()

        app = G["mods"]["baseline"].app
        app.dependency_overrides[dbm.get_session] = sess
        up = G["uploads"]["baseline"]
        up_before = listing(up)
        try:
            for name, m, p, kw in write_cases("T20CTL"):
                before = fingerprint(conn)
                r = send("baseline", m, p, **kw)
                after = fingerprint(conn)
                self.assertEqual(r.status_code, 200, name)
                self.assertNotEqual(before, after, "detector failed to see an unguarded write: " + name)
            self.assertNotEqual(listing(up), up_before, "detector failed to see the unguarded upload file")
        finally:
            app.dependency_overrides.pop(dbm.get_session, None)
            trans.rollback()
            conn.close()
            for f in Path(up).glob("*"):
                f.unlink()
        # geri alma kanitlandi: kalici DB tohum durumuna donmus olmali
        self.assertEqual(fingerprint()["products"][0], 2)
        self.assertEqual(fingerprint()["restaurants"][0], 1)


# --------------------------------------------------------------------------- N4
class _CountingReceive:
    def __init__(self):
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        # sinirli: govde okunursa test takilmak yerine (calls > 0) iddiasiyla basarisiz olur
        return {"type": "http.request", "body": b"x" * 65536, "more_body": self.calls < 4}


def _http_scope(method, path, headers=None, query=b""):
    return {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
            "path": path, "raw_path": path.encode(), "query_string": query,
            "headers": [(b"host", b"testserver")] + [(k.encode().lower(), v.encode()) for k, v in (headers or {}).items()],
            "client": ("127.0.0.1", 1), "server": ("testserver", 80)}


def _run_asgi(app, scope, receive=None):
    import asyncio
    sent = []

    async def send_(msg):
        sent.append(msg)

    rcv = receive or _CountingReceive()
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(app(scope, rcv, send_))
    finally:
        loop.close()
    return sent, rcv


class N4_NoBodyReadNoPersistentFile(unittest.TestCase):
    def test_large_multipart_denied_before_body_is_read(self):
        with no_side_effects(self, ("default",)):
            rid = G["ids"]["restaurant"]
            big = b"x" * (5 * 1024 * 1024)
            r = send("default", "POST", "/restaurants/%s/menus" % rid, files={"file": (PROBE + ".pdf", big, "application/pdf")})
            assert_denied(self, r)

    def test_asgi_receive_is_never_called_through_the_full_stack(self):
        app = G["mods"]["default"].app
        for name, m, p, kw in write_cases():
            hdrs = {"content-type": "multipart/form-data; boundary=x", "content-length": str(5 * 1024 * 1024)}
            sent, rcv = _run_asgi(app, _http_scope(m, p, hdrs))
            self.assertEqual(rcv.calls, 0, name + ": request body was read")
            self.assertEqual([s["type"] for s in sent], ["http.response.start", "http.response.body"])
            self.assertEqual(sent[0]["status"], 403)
            self.assertEqual(json.loads(sent[1]["body"]), DENIED_JSON)


class N4b_LiveUvicornServer(unittest.TestCase):
    """Gercek uvicorn + gercek TCP (127.0.0.1): govde sonuna kadar gonderilmeden 403 gelir, hicbir dosya olusmaz."""

    @classmethod
    def setUpClass(cls):
        import uvicorn
        cfg = uvicorn.Config(G["mods"]["default"].app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
        cls.server = uvicorn.Server(cfg)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.1)
        if not cls.server.started:
            raise AssertionError("uvicorn did not start")
        cls.port = cls.server.servers[0].sockets[0].getsockname()[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=10)

    def raw(self, head, body_chunks):
        """Basligi ve (sinirli) govdeyi gonderir, yaniti ayri bir thread'de okur. Sunucu govdeyi okumadan
        yanit verip baglantiyi kapatabildigi icin (RST) yanit kacirilirsa en fazla 3 deneme yapilir."""
        for attempt in range(3):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            buf = []

            def reader():
                s.settimeout(5)
                while True:
                    try:
                        part = s.recv(65536)
                    except (socket.timeout, ConnectionResetError, OSError):
                        return
                    if not part:
                        return
                    buf.append(part)

            t = threading.Thread(target=reader, daemon=True)
            t.start()
            sent = 0
            try:
                s.sendall(head)
                for ch in body_chunks:
                    s.sendall(ch)
                    sent += len(ch)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            t.join(timeout=6)
            s.close()
            data = b"".join(buf)
            if data:
                return data, sent
        return b"", sent

    def test_oversized_multipart_over_real_http_is_403_and_leaves_nothing(self):
        rid = G["ids"]["restaurant"]
        total = 6 * 1024 * 1024
        head = (("POST /restaurants/%s/menus HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary=BND\r\n"
                 "Content-Length: %d\r\n\r\n") % (rid, total)).encode()
        chunks = [b"x" * 65536]  # govdenin yalniz ilk 64 KiB'i gonderilir; Content-Length 6 MiB bildirir
        with no_side_effects(self, ("default",)):
            data, sent = self.raw(head, chunks)
            self.assertTrue(data.startswith(b"HTTP/1.1 403"), data[:80])
            self.assertIn(b"write_endpoints_closed", data)
            self.assertIn(b"connection: close", data.lower())
            self.assertNotIn(PROBE.encode(), data)

    def test_json_post_and_preflight_and_get_over_real_http(self):
        body = json.dumps({"rows": [{"marka": PROBE, "yemek": "y"}]}).encode()
        head = ("POST /import/csv-menu HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body)).encode()
        pre = (b"OPTIONS /products HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: " + ALLOWED_ORIGIN.encode() +
               b"\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n")
        get = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        with no_side_effects(self, ("default",)):
            d1, _ = self.raw(head, [body])
            self.assertTrue(d1.startswith(b"HTTP/1.1 403"), d1[:80])
            d2, _ = self.raw(pre, [])
            self.assertFalse(d2.startswith(b"HTTP/1.1 2"), d2[:80])
            self.assertNotIn(b"access-control-allow-origin", d2.lower())
        d3, _ = self.raw(get, [])
        self.assertTrue(d3.startswith(b"HTTP/1.1 200"), d3[:80])
        self.assertIn(b'"status":"ok"', d3.replace(b" ", b""))


# --------------------------------------------------------------------------- N5
class N5_AllWriteMethodsEverywhere(unittest.TestCase):
    PATHS = ["/restaurants", "/products", "/products/bulk", "/import/csv-menu", "/health", "/docs", "/openapi.json",
             "/no-such-route", "/menus/x/status", "/reports/ingredient-frequency"]

    def test_non_safe_methods_denied_on_every_path(self):
        paths = self.PATHS + ["/restaurants/%s/menus" % G["ids"]["restaurant"]]
        with no_side_effects(self, ("default", "allow")):
            for lbl in ("default", "allow"):
                for p in paths:
                    for m in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "FOO", "PROPFIND", "LOCK"):
                        with self.subTest(app=lbl, method=m, path=p):
                            assert_denied(self, send(lbl, m, p, content=PROBE.encode()))

    def test_method_names_are_normalised_by_the_guard(self):
        app = G["mods"]["default"].app
        for m in ("post", "Post", "put", "delete", ""):
            sent, rcv = _run_asgi(app, _http_scope(m, "/products"))
            self.assertEqual(sent[0]["status"], 403, repr(m))
            self.assertEqual(rcv.calls, 0)

    def test_safe_methods_still_reach_the_application(self):
        self.assertEqual(send("default", "GET", "/health").status_code, 200)
        self.assertEqual(send("default", "HEAD", "/health").status_code, send("baseline", "HEAD", "/health").status_code)
        self.assertNotEqual(send("default", "OPTIONS", "/health").status_code, 403)


# --------------------------------------------------------------------------- N6
class N6_CorsIsNotAuthAndHasNoWildcard(unittest.TestCase):
    def test_default_allow_list_is_empty_nothing_cross_origin_is_granted(self):
        for origin in (ALLOWED_ORIGIN, FOREIGN_ORIGIN, "null"):
            with self.subTest(origin=origin):
                r = send("default", "GET", "/health", origin=origin)
                self.assertEqual(r.status_code, 200)
                self.assertNotIn("access-control-allow-origin", r.headers)
                for m in ("POST", "PUT", "PATCH", "DELETE", "GET"):
                    pre = send("default", "OPTIONS", "/products", origin=origin, headers={"Access-Control-Request-Method": m})
                    self.assertEqual(pre.status_code, 400, m)
                    self.assertNotIn("access-control-allow-origin", pre.headers)
                p = send("default", "POST", "/products", origin=origin, params={"name": PROBE, "brand": PROBE})
                assert_denied(self, p)
                self.assertNotIn("access-control-allow-origin", p.headers)

    def test_allow_list_applies_only_to_listed_origin_and_never_wildcard(self):
        ok = send("allow", "GET", "/health", origin=ALLOWED_ORIGIN)
        self.assertEqual(ok.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN)
        self.assertNotIn("access-control-allow-credentials", ok.headers)
        for origin in (FOREIGN_ORIGIN, "null", ALLOWED_ORIGIN + ".evil.example", "http://allowed.example"):
            r = send("allow", "GET", "/health", origin=origin)
            self.assertNotIn("access-control-allow-origin", r.headers, origin)

    def test_preflight_for_write_methods_never_grants_success(self):
        for origin in (ALLOWED_ORIGIN, FOREIGN_ORIGIN):
            for path in ("/restaurants", "/products", "/products/bulk", "/import/csv-menu", "/restaurants/%s/menus" % G["ids"]["restaurant"]):
                for m in ("POST", "PUT", "PATCH", "DELETE"):
                    with self.subTest(origin=origin, path=path, method=m):
                        pre = send("allow", "OPTIONS", path, origin=origin, headers={"Access-Control-Request-Method": m})
                        self.assertFalse(200 <= pre.status_code < 300, "preflight for a write method succeeded")
                        allow = pre.headers.get("access-control-allow-methods", "")
                        for w in ("POST", "PUT", "PATCH", "DELETE", "*"):
                            self.assertNotIn(w, allow)
                        self.assertNotEqual(pre.headers.get("access-control-allow-origin"), "*")

    def test_preflight_for_read_from_listed_origin_is_the_only_success(self):
        pre = send("allow", "OPTIONS", "/products", origin=ALLOWED_ORIGIN, headers={"Access-Control-Request-Method": "GET"})
        self.assertEqual(pre.status_code, 200)
        self.assertEqual(pre.headers["access-control-allow-origin"], ALLOWED_ORIGIN)
        self.assertEqual(sorted(x.strip() for x in pre.headers["access-control-allow-methods"].split(",")), ["GET", "HEAD", "OPTIONS"])

    def test_listed_origin_does_not_authorise_a_write(self):
        with no_side_effects(self, ("allow",)):
            for name, m, p, kw in write_cases():
                r = send("allow", m, p, origin=ALLOWED_ORIGIN, **kw)
                assert_denied(self, r)
                self.assertEqual(r.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN)  # CORS en disa: tarayici 403'u okuyabilir
            for name, m, p, kw in write_cases():
                r = send("allow", m, p, origin=FOREIGN_ORIGIN, **kw)
                assert_denied(self, r)
                self.assertNotIn("access-control-allow-origin", r.headers)

    def test_options_cannot_be_confused_with_a_write(self):
        with no_side_effects(self, ("default", "allow")):
            for lbl in ("default", "allow"):
                for name, m, p, kw in write_cases():
                    for hdrs in ({}, {"X-HTTP-Method-Override": "POST"}, {"X-HTTP-Method": "POST"}, {"X-Method-Override": "POST"}):
                        with self.subTest(app=lbl, path=p, hdrs=sorted(hdrs)):
                            r = send(lbl, "OPTIONS", p, headers=hdrs, **kw)
                            self.assertFalse(200 <= r.status_code < 300, "OPTIONS acted like a write/success")
                    r = send(lbl, "OPTIONS", p + ("&" if "?" in p else "?") + "_method=POST", **kw)
                    self.assertFalse(200 <= r.status_code < 300)
        # GET + yontem-gecersiz kilma basligi: yalnizca okur (DB oturumu burada gerekli, blok disinda)
        for lbl in ("default", "allow"):
            before = fingerprint()
            g = send(lbl, "GET", "/products", headers={"X-HTTP-Method-Override": "POST"}, params={"brand": "Yayla"})
            self.assertEqual(g.status_code, 200)
            self.assertTrue(all(x["brand"] == "Yayla" for x in g.json()))
            self.assertEqual(before, fingerprint())


# --------------------------------------------------------------------------- N7
class N7_ThrottledStatusIsNeverRewritten(unittest.TestCase):
    CREDS = [{}, {"Authorization": "Bearer " + PROBE}, {"X-API-Key": PROBE}, {"Cookie": "session=" + PROBE},
             {"X-Forwarded-User": "admin"}, {"Authorization": "Basic " + PROBE}]

    def test_403_for_every_origin_endpoint_and_credential_shape(self):
        with no_side_effects(self, ("allow", "default")):
            for lbl in ("allow", "default"):
                for origin in (None, ALLOWED_ORIGIN, FOREIGN_ORIGIN, "null"):
                    for name, m, p, kw in write_cases():
                        for cred in self.CREDS:
                            with self.subTest(app=lbl, origin=origin, endpoint=name, cred=sorted(cred)):
                                r = send(lbl, m, p, origin=origin, headers=cred, **kw)
                                assert_denied(self, r)


# --------------------------------------------------------------------------- N8
class N8_GetBehaviourPreserved(unittest.TestCase):
    def paths(self):
        mid = G["ids"]["menu"]
        return ["/health", "/restaurants", "/restaurants?district=Kadikoy", "/restaurants?district=Yok", "/products", "/products?brand=Yayla",
                "/products/brands", "/menus/%s/status" % mid, "/menus/%s/status" % uuid.uuid4(), "/reports/ingredient-frequency",
                "/reports/ingredient-frequency?district=Kadikoy", "/reports/ingredient-frequency?city=Istanbul",
                "/reports/product-matching?brand=Yayla", "/reports/product-matching?brand=NoSuchBrand", "/openapi.json", "/docs", "/redoc"]

    def test_get_and_head_responses_match_the_unpatched_application(self):
        for p in self.paths():
            for m in ("GET", "HEAD"):
                if m == "HEAD" and p.startswith("/openapi"):
                    continue
                with self.subTest(method=m, path=p):
                    a, b = send("default", m, p), send("baseline", m, p)
                    self.assertEqual(a.status_code, b.status_code)
                    self.assertEqual(a.content, b.content)
                    self.assertEqual(a.headers.get("content-type"), b.headers.get("content-type"))
        self.assertEqual(send("default", "GET", "/health").json(), {"status": "ok"})
        self.assertEqual(send("default", "GET", "/products/brands").json(), ["Yayla"])

    def test_the_only_intended_header_difference_is_cors(self):
        a = send("default", "GET", "/health", origin=FOREIGN_ORIGIN)
        b = send("baseline", "GET", "/health", origin=FOREIGN_ORIGIN)
        self.assertEqual(b.headers.get("access-control-allow-origin"), "*")  # kontrol: taban joker veriyordu
        self.assertNotIn("access-control-allow-origin", a.headers)

    def test_reports_still_read_through_the_real_database(self):
        r = send("default", "GET", "/reports/product-matching?brand=Yayla")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["results"]), 2)


# --------------------------------------------------------------------------- N9
class N9_StartupWorkerAndNetworkIsolation(unittest.TestCase):
    def test_worker_is_off_and_never_imported(self):
        self.assertEqual(os.environ["WORKER_ENABLED"], "false")
        for lbl in ("default", "allow", "baseline"):
            log = G["startup"][lbl]
            self.assertIn("WORKER_ENABLED false, thread BASLATILMADI", log)
            self.assertNotIn("thread baslatiliyor", log)
        for mod in ("worker", "anthropic", "fitz", "app.extraction"):
            self.assertNotIn(mod, sys.modules, mod + " was imported")

    def test_external_network_is_blocked_during_tests(self):
        NET["expected"].append("93.184.216.34")
        with self.assertRaises(OSError):
            socket.create_connection(("93.184.216.34", 80), timeout=1)
        NET["expected"].append("api.anthropic.com")
        with self.assertRaises(OSError):
            socket.create_connection(("api.anthropic.com", 443), timeout=1)
        self.assertEqual(set(NET["violations"]), set(NET["expected"]))


# --------------------------------------------------------------------------- N10
class N10_NoWriteRouteCanStayOpen(unittest.TestCase):
    SENTINEL = {("POST", "/restaurants"), ("POST", "/products"), ("POST", "/products/bulk"),
                ("POST", "/restaurants/{restaurant_id}/menus"), ("POST", "/import/csv-menu")}

    def test_route_inventory_is_exactly_the_five_known_writers_and_all_are_closed(self):
        app = G["mods"]["default"].app
        found = set()
        for route in app.routes:
            for m in getattr(route, "methods", None) or ():
                if m not in SAFE:
                    found.add((m, route.path))
        self.assertEqual(found, self.SENTINEL, "a write route was added/removed: review the guard and this test")
        with no_side_effects(self, ("default",)):
            for m, path in sorted(found):
                url = path.replace("{restaurant_id}", str(uuid.uuid4()))
                assert_denied(self, send("default", m, url, content=b""))

    def test_a_route_added_in_the_future_is_closed_by_default(self):
        from fastapi import FastAPI
        from starlette.testclient import TestClient
        from app.write_guard import WriteGuardMiddleware
        hit = []
        inner = FastAPI()

        @inner.post("/__t20_future_write")
        def future():
            hit.append(1)
            return {"ok": True}

        @inner.get("/__t20_read")
        def read():
            return {"ok": True}

        c = TestClient(WriteGuardMiddleware(inner), raise_server_exceptions=False)
        self.assertEqual(c.post("/__t20_future_write").status_code, 403)
        self.assertEqual(c.request("DELETE", "/__t20_future_write").status_code, 403)
        self.assertEqual(hit, [])
        self.assertEqual(c.get("/__t20_read").status_code, 200)

    def test_every_baseline_write_route_is_covered_by_the_inventory(self):
        base = G["mods"]["baseline"].app
        found = {(m, r.path) for r in base.routes for m in (getattr(r, "methods", None) or ()) if m not in SAFE}
        self.assertEqual(found, self.SENTINEL)


# --------------------------------------------------------------------------- ek: ASGI kapsam ve ayristirici
class X1_AsgiScopes(unittest.TestCase):
    def setUp(self):
        from app.write_guard import WriteGuardMiddleware
        self.calls = []

        async def inner(scope, receive, send):
            self.calls.append(scope["type"])

        self.guard = WriteGuardMiddleware(inner)

    def test_non_http_scopes_pass_through_unchanged(self):
        for t in ("lifespan", "websocket"):
            sent, rcv = _run_asgi(self.guard, {"type": t, "asgi": {"version": "3.0"}})
            self.assertEqual(sent, [])
        self.assertEqual(self.calls, ["lifespan", "websocket"])

    def test_safe_methods_pass(self):
        for m in ("GET", "HEAD", "OPTIONS"):
            _run_asgi(self.guard, _http_scope(m, "/x"))
        self.assertEqual(self.calls, ["http"] * 3)

    def test_everything_else_is_denied_without_calling_inner_or_receive(self):
        for m in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "FOO", ""):
            sent, rcv = _run_asgi(self.guard, _http_scope(m, "/x"))
            self.assertEqual(sent[0]["status"], 403)
            self.assertEqual(rcv.calls, 0)
        scope = _http_scope("POST", "/x")
        del scope["method"]
        sent, rcv = _run_asgi(self.guard, scope)
        self.assertEqual(sent[0]["status"], 403)
        self.assertEqual(self.calls, [])


class X2_CorsOriginParser(unittest.TestCase):
    def test_parser(self):
        from app.write_guard import parse_allowed_origins as p
        self.assertEqual(p(None), [])
        self.assertEqual(p(""), [])
        self.assertEqual(p("  ,  "), [])
        self.assertEqual(p("https://a.example, https://b.example:8443,https://a.example"), ["https://a.example", "https://b.example:8443"])
        for bad in ("*", "null", "https://*.a.example", "https://a.example/", "https://a.example/path", "a.example", "ftp://a.example",
                    "https://a.example, *", "https://a.example?x=1", "javascript:alert(1)", "https://"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as cm:
                    p(bad)
                self.assertNotIn(bad, str(cm.exception), "the offending value must not be echoed")

    def test_a_wildcard_in_the_environment_stops_the_application_from_loading(self):
        with self.assertRaises(ValueError):
            _load_main("badcors", REPO / "app" / "main.py", "*")
        mod, _ = _load_main("emptycors", REPO / "app" / "main.py", None)
        cors = [m for m in mod.app.user_middleware if m.cls.__name__ == "CORSMiddleware"][0]
        self.assertEqual(cors.kwargs["allow_origins"], [])
        self.assertEqual(sorted(cors.kwargs["allow_methods"]), ["GET", "HEAD", "OPTIONS"])
        names = [m.cls.__name__ for m in mod.app.user_middleware]
        self.assertEqual(names, ["CORSMiddleware", "WriteGuardMiddleware"], "CORS must be outermost, guard inside")
        self.assertNotIn("allow_credentials", cors.kwargs)


if __name__ == "__main__":
    unittest.main()
