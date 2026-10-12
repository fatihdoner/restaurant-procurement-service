"""AO-01 / A0 -- yalitim testleri: dogrulayici HICBIR seye bagli degildir ve mevcut hicbir dosya degismemistir.

Bu testler yeni modulun (1) hicbir rotaya/ara yazilima/DB'ye/ortam degiskenine baglanmadigini, (2) uretim
onyuklemesinin PyJWT'ye bagimli olmadigini ve (3) A0'in mevcut RG-0 dosyalarina dokunmadigini kanitlar.
`git` gerekir (mevcut RG-0 testleri de kullanir). Taban: uretimdeki 7e6a177.
"""

import ast
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASE = "7e6a17736278bb9e00c16056c1b59d1e97ac29ec"
ALLOWED_NEW_FILES = {"app/auth/__init__.py", "app/auth/oidc.py", "requirements-auth-dev.txt",
                     "tests/test_ao01_oidc_verifier.py", "tests/test_ao01_a0_isolation.py"}
PRODUCTION_FILES = ["Dockerfile", "README_DEPLOYMENT.md", "app/db.py", "app/extraction.py", "app/main.py", "app/rate_limit.py", "app/write_guard.py",
                    "railway.json", "requirements.txt", "tests/test_t20_rate_limit.py", "tests/test_t20_write_closed.py", "worker.py"]
FASTAPI_BUILTIN_DOC_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}  # FastAPI'nin kendi Swagger yollari
AUTH_FILES = sorted((REPO / "app" / "auth").glob("*.py"))


def git(*args):
    return subprocess.run(["git", *args], cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def imports_of(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            mods.add(("." * node.level) + (node.module or ""))
    return mods, tree


class I1_NothingExistingChanged(unittest.TestCase):
    def test_every_file_of_the_production_tree_is_byte_identical(self):
        files = git("ls-tree", "-r", "--name-only", BASE).decode().split("\n")
        files = [f for f in files if f]
        self.assertEqual(sorted(files), sorted(PRODUCTION_FILES))  # uretim agaci tam olarak bu 12 dosya
        for rel in files:
            with self.subTest(file=rel):
                self.assertEqual((REPO / rel).read_bytes(), git("show", BASE + ":" + rel), "existing file modified: " + rel)

    def test_only_the_expected_new_files_were_added(self):
        diff = git("diff", "--name-status", BASE).decode().split("\n")
        changed = [l for l in diff if l and not l.startswith("A\t")]
        self.assertEqual(changed, [], "existing files modified/deleted/renamed")
        added = {l.split("\t")[1] for l in diff if l.startswith("A\t")}
        untracked = {l for l in git("ls-files", "-o", "--exclude-standard").decode().split("\n") if l}
        self.assertEqual(added | untracked, ALLOWED_NEW_FILES)


class I2_VerifierIsWiredToNothing(unittest.TestCase):
    ALLOWED = {"base64", "dataclasses", "ipaddress", "json", "logging", "math", "re", "ssl", "threading", "time", "urllib.error", "urllib.parse",
               "urllib.request", "typing", "jwt", "jwt.algorithms", "cryptography.hazmat.primitives.asymmetric", "cryptography"}
    FORBIDDEN_PREFIX = ("app", ".", "os", "sys", "subprocess", "sqlalchemy", "psycopg2", "fastapi", "starlette", "worker", "anthropic", "fitz", "requests", "httpx", "socket")

    def test_auth_package_has_only_the_expected_imports(self):
        self.assertTrue(AUTH_FILES)
        for path in AUTH_FILES:
            mods, _ = imports_of(path)
            for m in mods:
                with self.subTest(file=path.name, module=m):
                    self.assertFalse(m.split(".")[0] in self.FORBIDDEN_PREFIX or m.startswith("."), "forbidden import: " + m)
                    self.assertTrue(m in self.ALLOWED or m.startswith("cryptography.") or m.startswith("jwt"), "unexpected import: " + m)

    def test_auth_package_reads_no_environment_prints_nothing_and_opens_no_files(self):
        for path in AUTH_FILES:
            src = path.read_text(encoding="utf-8")
            _, tree = imports_of(path)
            for bad in ("environ", "getenv", "DATABASE_URL", "os.path"):
                self.assertNotIn(bad, src, "%s mentions %s" % (path.name, bad))
            names = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            self.assertFalse(names & {"print", "open", "eval", "exec", "compile", "__import__"}, names & {"print", "open", "eval", "exec", "compile", "__import__"})

    def test_no_other_application_module_imports_the_auth_package_or_jwt(self):
        for path in list((REPO / "app").glob("*.py")) + [REPO / "worker.py"] + list((REPO / "app").glob("*/*.py")):
            if path.parent.name == "auth":
                continue
            mods, _ = imports_of(path)
            for m in mods:
                with self.subTest(file=str(path.relative_to(REPO)), module=m):
                    self.assertFalse(m == "app.auth" or m.startswith("app.auth.") or m.split(".")[0] in ("jwt", "cryptography"))

    def run_main_probe(self, block_jwt):
        script = r'''
import json, sys
BLOCK = %s
if BLOCK:
    class Blocker:
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in ("jwt", "cryptography"):
                raise ImportError("blocked for test: " + name)
    sys.meta_path.insert(0, Blocker())
sys.path.insert(0, ".")
import app.main as m
routes = sorted([sorted(r.methods or []), r.path] if hasattr(r, "methods") else ["-", r.path] for r in m.app.routes)
print("RESULT=" + json.dumps({"routes": [[",".join(x[0]) if isinstance(x[0], list) else x[0], x[1]] for x in routes],
      "middleware": [x.cls.__name__ for x in m.app.user_middleware],
      "jwt_loaded": "jwt" in sys.modules, "auth_loaded": any(k == "app.auth" or k.startswith("app.auth.") for k in sys.modules)}))
''' % ("True" if block_jwt else "False")
        env = dict(os.environ, DATABASE_URL="postgresql://nouser:nopass@127.0.0.1:1/none", WORKER_ENABLED="false",
                   UPLOAD_DIR=tempfile.mkdtemp(prefix="rps_a0_up_"), PYTHONDONTWRITEBYTECODE="1")
        for k in ("RPS_T20_ADMIN_URL", "RPS_T20_EVIDENCE_DIR", "CORS_ALLOWED_ORIGINS"):
            env.pop(k, None)
        p = subprocess.run([sys.executable, "-W", "ignore", "-c", script], cwd=str(REPO), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        line = [l for l in p.stdout.decode().splitlines() if l.startswith("RESULT=")]
        self.assertTrue(line, p.stdout.decode()[-2000:])
        return json.loads(line[0][7:])

    EXPECTED_ROUTES = sorted([["GET", "/health"], ["GET", "/restaurants"], ["POST", "/restaurants"], ["GET", "/products"], ["POST", "/products"],
                              ["POST", "/products/bulk"], ["GET", "/products/brands"], ["POST", "/restaurants/{restaurant_id}/menus"],
                              ["GET", "/menus/{menu_id}/status"], ["GET", "/reports/ingredient-frequency"], ["GET", "/reports/product-matching"],
                              ["POST", "/import/csv-menu"], ["GET,HEAD", "/openapi.json"], ["GET,HEAD", "/docs"], ["GET,HEAD", "/docs/oauth2-redirect"],
                              ["GET,HEAD", "/redoc"]])

    def test_production_boot_does_not_need_or_load_the_new_dependency(self):
        r = self.run_main_probe(block_jwt=True)  # PyJWT/cryptography import'u yapay olarak engellendi: uygulama yine acilmali
        self.assertEqual(r["middleware"], ["CORSMiddleware", "WriteGuardMiddleware", "RateLimitMiddleware"])
        self.assertFalse(r["jwt_loaded"])
        self.assertFalse(r["auth_loaded"])

    def test_the_route_table_is_exactly_the_production_one_and_has_no_auth_routes(self):
        r = self.run_main_probe(block_jwt=False)
        self.assertEqual(sorted(r["routes"]), self.EXPECTED_ROUTES)
        self.assertFalse(r["jwt_loaded"])
        self.assertFalse(r["auth_loaded"])
        for method, path in r["routes"]:
            if path in FASTAPI_BUILTIN_DOC_PATHS:
                continue
            self.assertIsNone(re.search(r"login|logout|signup|register|/me\b|auth|token|oidc|callback|session|userinfo", path, re.I), path)

    def test_importing_the_package_alone_does_not_load_pyjwt(self):
        p = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, '.'); import app.auth; print('jwt' in sys.modules)"],
                           cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(p.stdout.decode().strip(), "False")


class I3_DependencyHygiene(unittest.TestCase):
    def test_dev_requirements_are_exactly_pinned_and_match_the_installed_versions(self):
        lines = [l.strip() for l in (REPO / "requirements-auth-dev.txt").read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
        self.assertGreaterEqual(len(lines), 4)
        pins = {}
        for l in lines:
            m = re.fullmatch(r"([A-Za-z0-9_.-]+)(\[[a-z,]+\])?==([0-9][0-9.]*)", l)
            self.assertIsNotNone(m, "not exactly pinned: " + l)
            pins[m.group(1).lower()] = m.group(3)
        for name, version in pins.items():
            self.assertEqual(importlib.metadata.version(name), version, name)
        self.assertIn("pyjwt", pins)

    def test_production_build_files_do_not_reference_the_dev_requirements(self):
        for rel in ("Dockerfile", "railway.json", "requirements.txt", "README_DEPLOYMENT.md"):
            self.assertNotIn("requirements-auth-dev", (REPO / rel).read_text(encoding="utf-8"))
        self.assertNotIn("jwt", (REPO / "requirements.txt").read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
