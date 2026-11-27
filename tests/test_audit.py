import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from rsa_audit import checks, der, sshkeys
from rsa_audit.cli import run_scan
from rsa_audit.core import FIX, OTHERS, SAFE, NotAllowed, Scan
from rsa_audit.report import render_json


def keygen(path: Path, kind: str, bits: int | None = None) -> None:
    cmd = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", str(path), "-C", path.name]
    if bits:
        cmd += ["-b", str(bits)]
    subprocess.run(cmd, check=True)


def make_cert(tmp: Path, keyopt: list[str], cn: str) -> bytes:
    key, crt = tmp / f"{cn}.key", tmp / f"{cn}.der"
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", *keyopt, "-keyout", str(key),
                    "-subj", f"/CN={cn}", "-days", "30", "-outform", "DER", "-out", str(crt)],
                   check=True, capture_output=True)
    return crt.read_bytes()


def snapshot(root: Path) -> dict:
    """path -> (sha256, mtime) for every file under root."""
    return {
        str(p): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*")) if p.is_file()
    }


class FakeHome:
    """A throwaway home dir with a mix of RSA and non-RSA SSH material."""

    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        home = Path(self._tmp.name)
        ssh = home / ".ssh"
        ssh.mkdir()
        keygen(ssh / "id_rsa", "rsa", 2048)
        keygen(ssh / "id_ed25519", "ed25519")
        keygen(home / "server_rsa", "rsa", 3072)
        keygen(home / "server_ed", "ed25519")
        rsa_host = (home / "server_rsa.pub").read_text().split()[:2]
        ed_host = (home / "server_ed.pub").read_text().split()[:2]
        (ssh / "known_hosts").write_text(
            f"old.example.com {' '.join(rsa_host)}\n"
            f"new.example.com {' '.join(ed_host)}\n"
            f"both.example.com {' '.join(rsa_host)}\n"
            f"both.example.com {' '.join(ed_host)}\n"
        )
        (ssh / "authorized_keys").write_text(
            f'from="10.0.0.1" {(ssh / "id_rsa.pub").read_text()}'
        )
        (home / ".gitconfig").write_text(
            f"[gpg]\n\tformat = ssh\n[user]\n\tsigningkey = {ssh / 'id_rsa.pub'}\n"
            "[commit]\n\tgpgsign = true\n"
        )
        return home

    def __exit__(self, *exc):
        self._tmp.cleanup()


class TestParsing(unittest.TestCase):
    def test_ssh_private_key_types(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            keygen(d / "r", "rsa", 2048)
            keygen(d / "e", "ed25519")
            keygen(d / "c", "ecdsa", 384)
            self.assertEqual(sshkeys.private_key_type((d / "r").read_text()), ("RSA", 2048))
            self.assertEqual(sshkeys.private_key_type((d / "e").read_text()), ("Ed25519", 256))
            self.assertEqual(sshkeys.private_key_type((d / "c").read_text()), ("EC", 384))

    def test_passphrase_key_header_still_readable(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k"
            subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "hunter22",
                            "-f", str(p)], check=True)
            self.assertEqual(sshkeys.private_key_type(p.read_text()), ("RSA", 2048))

    def test_pubkey_line_with_options(self):
        with tempfile.TemporaryDirectory() as d:
            keygen(Path(d) / "k", "rsa", 3072)
            line = 'no-pty,from="1.2.3.4" ' + (Path(d) / "k.pub").read_text()
            family, bits, before = sshkeys.parse_pubkey_line(line)
            self.assertEqual((family, bits), ("RSA", 3072))
            self.assertIn("no-pty", before)

    def test_x509_key_types(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            rsa = der.parse_cert(make_cert(d, ["rsa:2048"], "rsa.test"))
            self.assertEqual((rsa.key_type, rsa.key_bits, rsa.subject), ("RSA", 2048, "rsa.test"))
            ec = der.parse_cert(make_cert(d, ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "ec.test"))
            self.assertEqual((ec.key_type, ec.key_bits), ("EC", 256))
            ed = der.parse_cert(make_cert(d, ["ed25519"], "ed.test"))
            self.assertEqual(ed.key_type, "Ed25519")
            self.assertEqual(rsa.subject, rsa.issuer)  # self-signed


    def test_gpg_colon_parsing(self):
        colons = (
            "sec:u:4096:1:AAAA1111BBBB2222:1700000000:::u:::scESC:::+:::23::0:\n"
            "uid:u::::1700000000::HASH::Geoff <g@example.com>::::::::::0:\n"
            "sec:e:256:22:CCCC3333DDDD4444:1600000000:::u:::scESC:::+:::ed25519::0:\n"
        )
        keys = checks._gpg_keys(colons, "sec")
        self.assertEqual([(k["algo"], k["bits"], k["validity"]) for k in keys],
                         [("RSA", "4096", "u"), ("EdDSA", "256", "e")])
        self.assertEqual(keys[0]["uid"], "Geoff <g@example.com>")


class TestScan(unittest.TestCase):
    def test_findings_on_fake_home(self):
        with FakeHome() as home:
            findings, _ = run_scan(home, [])
        by_title = {f.title: f for f in findings}

        def find(severity, fragment):
            hits = [f for f in findings if f.severity == severity and fragment in f.title]
            self.assertTrue(hits, f"no {severity} finding containing {fragment!r}: {list(by_title)}")
            return hits[0]

        find(FIX, "~/.ssh/id_rsa is RSA-2048")
        find(FIX, "can log into this Mac")
        find(FIX, "Git commits are signed with an RSA")
        rsa_hosts = find(OTHERS, "only prove who they are with RSA")
        self.assertEqual(rsa_hosts.details, ["old.example.com"])
        safe = find(SAFE, "SSH key not affected")
        self.assertEqual(safe.details, ["~/.ssh/id_ed25519 (Ed25519)"])

    def test_scan_changes_nothing(self):
        with FakeHome() as home:
            before = snapshot(home)
            run_scan(home, [])
            self.assertEqual(snapshot(home), before)
            self.assertFalse((home / ".gnupg").exists(), "gpg must not create a keyring")

    def test_no_network_unless_sites_given(self):
        with FakeHome() as home:
            findings, scan = run_scan(home, [])
            self.assertEqual(scan.network, [])
            self.assertEqual(json.loads(render_json(findings, scan))["touched"]["writes"], [])

    def test_private_key_material_never_in_report(self):
        with FakeHome() as home:
            findings, scan = run_scan(home, [])
            secret_body = "".join((home / ".ssh/id_rsa").read_text().splitlines()[1:-1])
            out = render_json(findings, scan)
            self.assertNotIn(secret_body[40:120], out)

    def test_disallowed_commands_refused(self):
        scan = Scan(Path("/nonexistent"))
        for argv in (["rm", "-rf", "/"], ["git", "config", "--global", "user.name", "x"],
                     ["gpg", "--homedir", "/x", "--gen-key"], ["security", "delete-certificate"]):
            with self.assertRaises(NotAllowed, msg=argv):
                scan.run(argv)


if __name__ == "__main__":
    unittest.main()
