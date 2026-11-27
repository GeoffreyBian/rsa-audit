"""Local web app: serves the report UI on 127.0.0.1 and opens it in the browser.

Only reachable from this machine. Every API call needs a random per-launch token,
so other websites open in your browser can't trigger scans. The server exits
shortly after the tab is closed.
"""

import json
import secrets
import threading
import time
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .cli import run_scan
from .core import FIX, INFO, OTHERS, SAFE

IDLE_TIMEOUT = 150  # seconds without a heartbeat; background tabs only tick about once a minute


def scan_payload(home: Path, sites: list[str]) -> dict:
    findings, scan = run_scan(home, sites)
    tilde = lambda s: s.replace(str(home), "~")
    return {
        "summary": {s: sum(f.severity == s for f in findings) for s in (FIX, OTHERS, INFO, SAFE)},
        "findings": [
            {k: (tilde(v) if isinstance(v, str) else [tilde(x) for x in v] if isinstance(v, list) else v)
             for k, v in asdict(f).items()}
            for f in findings
        ],
        "touched": {
            "files_read": [tilde(p) for p in scan.files_read],
            "commands_run": [tilde(" ".join(c)) for c in scan.commands_run],
            "network": scan.network,
            "writes": [],
        },
    }


def make_handler(token: str, home: Path, state: dict):
    page = resources.files("rsa_audit").joinpath("web/index.html").read_text()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, body: str, ctype: str = "application/json"):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self' 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            # Host check blocks DNS-rebinding; token blocks other local pages.
            host_ok = self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")
            return host_ok and secrets.compare_digest(self.headers.get("X-Token", ""), token)

        def do_GET(self):
            url = urlparse(self.path)
            state["last_seen"] = time.monotonic()
            if url.path == "/":
                self._send(200, page, "text/html")
            elif not self._authorized():
                self._send(403, '{"error": "forbidden"}')
            elif url.path == "/api/scan":
                raw = parse_qs(url.query).get("sites", [""])[0]
                sites = [s.strip() for s in raw.split(",") if s.strip()][:20]
                self._send(200, json.dumps(scan_payload(home, sites)))
            elif url.path == "/api/heartbeat":
                self._send(200, "{}")
            else:
                self._send(404, '{"error": "not found"}')

        def do_POST(self):
            if urlparse(self.path).path == "/api/quit" and self._authorized():
                self._send(200, "{}")
                state["quit"] = True
            else:
                self._send(403, '{"error": "forbidden"}')

    return Handler


def serve(home: Path = Path.home(), open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(24)
    state = {"last_seen": time.monotonic(), "quit": False}
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token, home, state))
    url = f"http://127.0.0.1:{server.server_port}/#{token}"  # fragment never leaves the browser
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"RSA Audit running at {url}\nClose the tab (or press Ctrl-C) to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        while not state["quit"] and time.monotonic() - state["last_seen"] < IDLE_TIMEOUT:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    server.shutdown()
