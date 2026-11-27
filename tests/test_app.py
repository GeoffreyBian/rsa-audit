import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from rsa_audit.app import make_handler

from .test_audit import FakeHome


class TestApp(unittest.TestCase):
    def setUp(self):
        self._home = FakeHome()
        self.home = self._home.__enter__()
        self.state = {"last_seen": 0, "quit": False}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("tok", self.home, self.state))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._home.__exit__(None, None, None)

    def get(self, path, headers=None, method="GET"):
        req = urllib.request.Request(self.base + path, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_page_served(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("RSA Audit", body)

    def test_api_requires_token(self):
        self.assertEqual(self.get("/api/scan")[0], 403)
        self.assertEqual(self.get("/api/scan", {"X-Token": "wrong"})[0], 403)

    def test_foreign_host_rejected(self):
        # DNS-rebinding style request: right token, wrong Host header
        self.assertEqual(self.get("/api/scan", {"X-Token": "tok", "Host": "evil.example"})[0], 403)

    def test_scan_payload(self):
        status, body = self.get("/api/scan", {"X-Token": "tok"})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertGreaterEqual(data["summary"]["fix"], 3)
        self.assertEqual(data["touched"]["network"], [])
        self.assertTrue(all(p.startswith(("~", "/")) for p in data["touched"]["files_read"]))
        self.assertNotIn(str(self.home), body)

    def test_quit(self):
        self.assertEqual(self.get("/api/quit", method="POST")[0], 403)
        self.assertFalse(self.state["quit"])
        self.assertEqual(self.get("/api/quit", {"X-Token": "tok"}, method="POST")[0], 200)
        self.assertTrue(self.state["quit"])
