"""Scan context: every file read, command run and connection made goes through
here, so the report can list exactly what was touched and nothing can write."""

import os
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

FIX = "fix"  # exposed, and you can fix it
OTHERS = "others"  # exposed, someone else (a server, site, vendor) has to fix it
INFO = "info"
SAFE = "safe"

MAX_READ = 256 * 1024

# Only these read-only command shapes may run. Matched on argv prefix.
ALLOWED_COMMANDS = [
    ["security", "find-certificate", "-a", "-p"],
    ["security", "find-identity"],
    ["git", "config", "--global", "--list"],
    ["gpg", "--homedir"],  # further restricted in run() to list operations
]
GPG_LIST_OPS = {"--list-keys", "--list-secret-keys"}


@dataclass
class Finding:
    severity: str
    area: str
    title: str
    why: str = ""
    fix: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)


class NotAllowed(Exception):
    pass


class Scan:
    def __init__(self, home: Path, sites: list[str] | None = None):
        self.home = Path(home)
        self.sites = sites or []
        self.files_read: list[str] = []
        self.commands_run: list[list[str]] = []
        self.network: list[str] = []

    def read_text(self, path: Path) -> str | None:
        path = Path(path)
        try:
            if not path.is_file() or path.stat().st_size > MAX_READ:
                return None
            with open(path, "rb") as f:  # read-only mode, never "w"/"a"
                data = f.read()
        except OSError:
            return None
        self.files_read.append(str(path))
        return data.decode("utf-8", "replace")

    def run(self, argv: list[str]) -> str | None:
        if not any(argv[: len(p)] == p for p in ALLOWED_COMMANDS):
            raise NotAllowed(argv)
        if argv[0] == "gpg" and not (GPG_LIST_OPS & set(argv)):
            raise NotAllowed(argv)
        exe = shutil.which(argv[0])
        if not exe:
            return None
        self.commands_run.append(argv)
        env = {**os.environ, "HOME": str(self.home)}
        try:
            out = subprocess.run(
                [exe, *argv[1:]],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=30,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return out.stdout.decode("utf-8", "replace")

    def fetch_cert(self, host: str, port: int = 443) -> tuple[bytes, str]:
        """Leaf certificate DER + TLS version. Only called for sites the user listed."""
        self.network.append(f"{host}:{port}")
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), tls.version()
