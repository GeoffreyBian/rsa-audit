"""Each check looks at one place RSA can hide and returns plain-language findings."""

import os
import re
from collections import defaultdict
from datetime import date
from pathlib import Path

from . import der, sshkeys
from .core import FIX, INFO, OTHERS, SAFE, Finding, Scan

NEW_SSH_KEY = 'ssh-keygen -t ed25519 -C "you@example.com"'


def _desc(family: str, bits: int | None) -> str:
    return f"{family}-{bits}" if family == "RSA" and bits else family


# ---------------------------------------------------------------- SSH


def check_ssh(scan: Scan) -> list[Finding]:
    ssh_dir = scan.home / ".ssh"
    if not ssh_dir.is_dir():
        return [Finding(INFO, "SSH", "No ~/.ssh folder, so no SSH keys to check")]

    findings: list[Finding] = []
    candidates = {p for p in ssh_dir.iterdir() if p.is_file()}
    config = scan.read_text(ssh_dir / "config") or ""
    for m in re.finditer(r"(?im)^\s*IdentityFile\s+(\S+)", config):
        p = Path(os.path.expanduser(m.group(1).replace("~", str(scan.home), 1)))
        candidates.add(p)

    safe_keys = []
    for path in sorted(candidates):
        name = path.name
        if name.endswith(".pub") or name == "config" or name.startswith(
            ("known_hosts", "authorized_keys")
        ):
            continue
        text = scan.read_text(path)
        if not text or "PRIVATE KEY-----" not in text:
            continue
        family, bits = sshkeys.private_key_type(text) or ("unknown", None)
        label = str(path).replace(str(scan.home), "~")
        if family in ("RSA", "DSA"):
            findings.append(
                Finding(
                    FIX,
                    "SSH",
                    f"Your SSH key {label} is {_desc(family, bits)}",
                    why=(
                        "You've shared the public half of this key with GitHub and "
                        "servers. If RSA is broken, anyone could rebuild your private "
                        "key from it and log in as you, or push code under your name."
                    ),
                    fix=[
                        f"Make a new key: `{NEW_SSH_KEY}`",
                        "Add the new .pub file everywhere the old one is used "
                        "(GitHub > Settings > SSH keys, and each server's ~/.ssh/authorized_keys).",
                        "Remove the old public key from those places.",
                        f"Then delete {label} and {label}.pub on this Mac.",
                    ],
                )
            )
        elif family == "unknown":
            findings.append(
                Finding(
                    INFO,
                    "SSH",
                    f"Couldn't tell what type {label} is (it may be passphrase-protected PEM)",
                    fix=[f"Check it yourself: `ssh-keygen -l -f {label}.pub`"],
                )
            )
        else:
            safe_keys.append(f"{label} ({_desc(family, bits)})")

    if safe_keys:
        findings.append(
            Finding(
                SAFE,
                "SSH",
                f"{len(safe_keys)} SSH key{'s' if len(safe_keys) > 1 else ''} not affected by an RSA break",
                details=safe_keys,
            )
        )

    findings += _check_known_hosts(scan, ssh_dir)
    findings += _check_authorized_keys(scan, ssh_dir)
    return findings


def _check_known_hosts(scan: Scan, ssh_dir: Path) -> list[Finding]:
    text = scan.read_text(ssh_dir / "known_hosts")
    if not text:
        return []
    by_host: dict[str, set[str]] = defaultdict(set)
    for line in text.splitlines():
        parsed = sshkeys.parse_pubkey_line(line)
        if not parsed:
            continue
        family, _, hosts = parsed
        if hosts.startswith("@revoked"):
            continue
        hosts = hosts.removeprefix("@cert-authority").strip()
        name = "(hashed hostname)" if hosts.startswith("|1|") else hosts
        # hashed entries can't be grouped by host, so keep each one separate
        key = f"{name}#{len(by_host)}" if name == "(hashed hostname)" else name
        by_host[key].add(family)

    rsa_only = sorted(h for h, fams in by_host.items() if fams == {"RSA"})
    mixed = sorted(h for h, fams in by_host.items() if "RSA" in fams and len(fams) > 1)
    clean = len(by_host) - len(rsa_only) - len(mixed)

    findings = []
    if rsa_only:
        shown = [h.split("#")[0] for h in rsa_only]
        findings.append(
            Finding(
                OTHERS,
                "SSH",
                f"{len(rsa_only)} server{'s' if len(rsa_only) > 1 else ''} you've connected to "
                "only prove who they are with RSA",
                why=(
                    "When you SSH in, your Mac checks the server's key to make sure it's "
                    "really that server. If RSA is broken, someone on your network (café "
                    "Wi-Fi, a compromised router) could pretend to be it and see what you type."
                ),
                fix=[
                    "The server's owner has to fix this by adding an Ed25519 host key. "
                    "If it's your server or a lab machine, ask the admin.",
                    "Optional, stricter: add `HostKeyAlgorithms -ssh-rsa*,rsa-sha2-*` to "
                    "~/.ssh/config so your Mac refuses RSA host keys. Connections to "
                    "RSA-only servers will then fail.",
                    "Old entries for machines you no longer use can be removed with "
                    "`ssh-keygen -R <host>`.",
                ],
                details=shown[:12] + ([f"...and {len(shown) - 12} more"] if len(shown) > 12 else []),
            )
        )
    if mixed:
        findings.append(
            Finding(
                INFO,
                "SSH",
                f"{len(mixed)} server{'s' if len(mixed) > 1 else ''} offer both RSA and a "
                "safer key type",
                why="Modern SSH picks the safer key, so these are low risk.",
                details=[h.split("#")[0] for h in mixed][:12]
                + ([f"...and {len(mixed) - 12} more"] if len(mixed) > 12 else []),
            )
        )
    if clean:
        findings.append(
            Finding(SAFE, "SSH", f"{clean} known server{'s' if clean > 1 else ''} use non-RSA keys")
        )
    return findings


def _check_authorized_keys(scan: Scan, ssh_dir: Path) -> list[Finding]:
    findings = []
    for name in ("authorized_keys", "authorized_keys2"):
        text = scan.read_text(ssh_dir / name)
        if not text:
            continue
        rsa = []
        for line in text.splitlines():
            parsed = sshkeys.parse_pubkey_line(line)
            if parsed and parsed[0] in ("RSA", "DSA"):
                comment = line.split()[-1] if len(line.split()) > 2 else "(no label)"
                rsa.append(f"{_desc(parsed[0], parsed[1])} key: {comment}")
        if rsa:
            findings.append(
                Finding(
                    FIX,
                    "SSH",
                    f"{len(rsa)} RSA key{'s' if len(rsa) > 1 else ''} can log into this Mac (~/.ssh/{name})",
                    why=(
                        "If Remote Login is on, anyone who can break RSA could rebuild "
                        "these keys and log into your computer."
                    ),
                    fix=[
                        "Ask whoever owns each key to make an Ed25519 key and send you the new .pub.",
                        f"Replace the RSA lines in ~/.ssh/{name}, or turn off Remote Login "
                        "(System Settings > General > Sharing) if you don't use it.",
                    ],
                    details=rsa,
                )
            )
    return findings


# ---------------------------------------------------------------- GPG

GPG_ALGOS = {"1": "RSA", "2": "RSA", "3": "RSA", "17": "DSA", "16": "ElGamal",
             "20": "ElGamal", "18": "ECDH", "19": "ECDSA", "22": "EdDSA"}


def _gpg_keys(colons: str, record: str) -> list[dict]:
    keys = []
    for line in colons.splitlines():
        f = line.split(":")
        if f[0] == record:
            keys.append({"validity": f[1], "bits": f[2], "algo": GPG_ALGOS.get(f[3], f[3]),
                         "id": f[4], "uid": "(no name)"})
        elif f[0] == "uid" and keys and keys[-1]["uid"] == "(no name)":
            keys[-1]["uid"] = f[9]
    return keys


def check_gpg(scan: Scan) -> list[Finding]:
    homedir = Path(os.environ.get("GNUPGHOME") or scan.home / ".gnupg")
    if not homedir.is_dir():
        # Running gpg here would create a keyring, so don't.
        return [Finding(INFO, "GPG", "No GPG keyring on this Mac (gpg not run, nothing created)")]

    base = ["gpg", "--homedir", str(homedir), "--batch", "--no-auto-check-trustdb",
            "--with-colons"]
    secret = scan.run(base + ["--list-secret-keys"])
    public = scan.run(base + ["--list-keys"])
    if secret is None and public is None:
        return [Finding(INFO, "GPG", "GPG keyring found but gpg isn't installed")]

    findings = []
    mine = [k for k in _gpg_keys(secret or "", "sec") if k["validity"] not in ("r", "e")]
    my_ids = {k["id"] for k in mine}
    for k in mine:
        if k["algo"] == "RSA":
            findings.append(
                Finding(
                    FIX,
                    "GPG",
                    f"Your GPG key for {k['uid']} is RSA-{k['bits']}",
                    why=(
                        "Someone who can break RSA could sign things as you and read "
                        "messages encrypted to this key, including old ones they saved."
                    ),
                    fix=[
                        f'Make a new key: `gpg --quick-generate-key "{k["uid"]}" ed25519 sign 2y`',
                        "Add an encryption subkey: `gpg --quick-add-key <new-fingerprint> cv25519 encr 2y`",
                        "Upload the new public key wherever the old one lives (GitHub, keyservers).",
                        f"Revoke the old one: `gpg --gen-revoke {k['id']}`, then import and publish it.",
                    ],
                )
            )
        else:
            findings.append(Finding(SAFE, "GPG", f"Your GPG key for {k['uid']} is {k['algo']}"))

    others = [k for k in _gpg_keys(public or "", "pub")
              if k["id"] not in my_ids and k["validity"] not in ("r", "e")]
    rsa_others = [k for k in others if k["algo"] == "RSA"]
    if rsa_others:
        findings.append(
            Finding(
                OTHERS,
                "GPG",
                f"{len(rsa_others)} people's GPG keys you've imported are RSA",
                why="Signatures from these keys (e.g. on software downloads) could be forged.",
                fix=["Nothing to do on your side; their owners need to publish new keys."],
                details=[f"{k['uid']} (RSA-{k['bits']})" for k in rsa_others][:12],
            )
        )
    return findings


# ---------------------------------------------------------------- Git signing


def check_git(scan: Scan) -> list[Finding]:
    out = scan.run(["git", "config", "--global", "--list"])
    if out is None:
        return []
    cfg = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if cfg.get("commit.gpgsign", "").lower() != "true" and "user.signingkey" not in cfg:
        return [Finding(INFO, "Git", "Git commit signing is off, so there's nothing RSA-based to check")]

    fmt = cfg.get("gpg.format", "openpgp")
    key = cfg.get("user.signingkey", "")
    if fmt == "ssh":
        if key.startswith("key::"):
            parsed = sshkeys.parse_pubkey_line(key[5:])
        else:
            path = Path(key.replace("~", str(scan.home), 1))
            text = scan.read_text(path) or ""
            parsed = sshkeys.parse_pubkey_line(text) if text.startswith(("ssh-", "ecdsa-", "sk-")) else None
            if parsed is None and text:
                kt = sshkeys.private_key_type(text)
                parsed = (*kt, "") if kt else None
        family = parsed[0] if parsed else "unknown"
    else:
        family = "GPG (see GPG section)"

    if family == "RSA":
        return [
            Finding(
                FIX,
                "Git",
                "Your Git commits are signed with an RSA SSH key",
                why="Someone who breaks RSA could make commits that show as Verified under your name.",
                fix=[
                    f"Make an Ed25519 key (`{NEW_SSH_KEY}`), then: "
                    "`git config --global user.signingkey ~/.ssh/id_ed25519.pub`",
                    "Add it on GitHub as a *signing* key (Settings > SSH and GPG keys).",
                ],
            )
        ]
    sev = SAFE if family not in ("unknown",) and not family.startswith("GPG") else INFO
    return [Finding(sev, "Git", f"Git commit signing uses {fmt} ({family})")]


# ---------------------------------------------------------------- Keychain


def _expiry(c: der.CertInfo) -> str:
    expired = c.not_after < date.today().isoformat()
    return f"expired {c.not_after}" if expired else f"expires {c.not_after}"


def _identities(out: str) -> dict[str, str]:
    ids = {}
    for m in re.finditer(r'^\s*\d+\)\s+([0-9A-F]{40})\s+"(.*)"', out or "", re.M):
        ids[m.group(1)] = m.group(2)
    return ids


def check_keychain(scan: Scan) -> list[Finding]:
    login = scan.home / "Library/Keychains/login.keychain-db"
    findings = []
    if login.exists():
        pem = scan.run(["security", "find-certificate", "-a", "-p", str(login)]) or ""
        ids = _identities(scan.run(["security", "find-identity"]) or "")
        certs = []
        for d in der.certs_from_pem(pem.encode()):
            try:
                certs.append(der.parse_cert(d))
            except (IndexError, ValueError):
                continue

        mine_rsa = [c for c in certs if c.sha1 in ids and c.key_type == "RSA"]
        self_made = [c for c in mine_rsa if c.subject == c.issuer]
        mine_rsa = [c for c in mine_rsa if c.subject != c.issuer]
        mine_ok = [c for c in certs if c.sha1 in ids and c.key_type != "RSA"]
        stored_rsa = [c for c in certs if c.sha1 not in ids and c.key_type == "RSA"]
        if self_made:
            findings.append(
                Finding(
                    FIX,
                    "Keychain",
                    f"{len(self_made)} self-made certificate{'s' if len(self_made) > 1 else ''} "
                    f"in your keychain {'use' if len(self_made) > 1 else 'uses'} RSA",
                    why=(
                        "You (or an app) created these yourself, usually for local code "
                        "signing or testing. If RSA breaks, anyone with the certificate "
                        "could sign things as it."
                    ),
                    fix=[
                        "If you don't remember using it, delete it: Keychain Access > "
                        "My Certificates > right-click > Delete.",
                        "If you need it, make a replacement: Keychain Access > Certificate "
                        "Assistant > Create a Certificate, tick 'Let me override defaults' "
                        "and pick ECC as the key type.",
                    ],
                    details=[f"{c.subject} (RSA-{c.key_bits}, expires {c.not_after})"
                             for c in self_made],
                )
            )
        if mine_rsa:
            findings.append(
                Finding(
                    OTHERS,
                    "Keychain",
                    f"{len(mine_rsa)} issued certificate{'s' if len(mine_rsa) > 1 else ''} "
                    f"that {'identify you use' if len(mine_rsa) > 1 else 'identifies you uses'} RSA keys",
                    why=(
                        "These prove who you are to an organization (Apple developer "
                        "signing, work VPN, school Wi-Fi). If RSA breaks, they could be "
                        "copied. The issuer has to offer a non-RSA replacement."
                    ),
                    fix=[
                        "When the issuer (Apple, your IT team) offers new certificates, "
                        "re-issue these and delete the old ones in Keychain Access.",
                        "Delete any you no longer use: Keychain Access > My Certificates.",
                    ],
                    details=[f"{c.subject} (issued by {c.issuer}, RSA-{c.key_bits}, "
                             f"expires {c.not_after})" for c in mine_rsa],
                )
            )
        if mine_ok:
            findings.append(Finding(SAFE, "Keychain", f"{len(mine_ok)} personal certificates use non-RSA keys",
                                    details=[f"{c.subject} ({c.key_type})" for c in mine_ok]))
        if not ids:
            findings.append(Finding(SAFE, "Keychain", "No personal signing/login certificates in your keychain"))
        if stored_rsa:
            findings.append(
                Finding(
                    INFO,
                    "Keychain",
                    f"{len(stored_rsa)} other certificates saved in your login keychain are RSA",
                    why="These belong to others (intermediates, sites, contacts), not you.",
                    details=[f"{c.subject} (RSA-{c.key_bits}, {_expiry(c)})" for c in stored_rsa][:12],
                )
            )

    roots_path = "/System/Library/Keychains/SystemRootCertificates.keychain"
    if Path(roots_path).exists():
        pem = scan.run(["security", "find-certificate", "-a", "-p", roots_path]) or ""
        types: dict[str, int] = defaultdict(int)
        for d in der.certs_from_pem(pem.encode()):
            try:
                types[der.parse_cert(d).key_type] += 1
            except (IndexError, ValueError):
                types["unreadable"] += 1
        total = sum(types.values())
        if total:
            findings.append(
                Finding(
                    OTHERS,
                    "System",
                    f"{types['RSA']} of the {total} root certificates your Mac trusts are RSA",
                    why=(
                        "Root certificates are how your browser knows a site is real. "
                        "With RSA broken, a forged root signature would let attackers "
                        "impersonate any website. Apple would push fixes through macOS updates."
                    ),
                    fix=["Turn on automatic updates: System Settings > General > "
                         "Software Update > Automatic Updates, and keep browsers updated."],
                    details=[f"{k}: {v}" for k, v in sorted(types.items(), key=lambda kv: -kv[1])],
                )
            )
    return findings


# ---------------------------------------------------------------- Websites (opt-in)


def check_sites(scan: Scan) -> list[Finding]:
    findings = []
    for site in scan.sites:
        host, _, port = site.partition(":")
        try:
            leaf, version = scan.fetch_cert(host, int(port or 443))
            c = der.parse_cert(leaf)
        except Exception as e:  # network errors, odd certs: report, don't crash
            findings.append(Finding(INFO, "Websites", f"Couldn't check {host}: {e}"))
            continue
        if c.key_type == "RSA":
            findings.append(
                Finding(
                    OTHERS,
                    "Websites",
                    f"{host} proves its identity with an RSA-{c.key_bits} certificate",
                    why=(
                        f"Your connection uses {version}, so recorded traffic stays private, "
                        "but someone who breaks RSA could impersonate this site."
                    ),
                    fix=["Only the site can fix this. Keep your browser updated so it "
                         "picks up distrust lists quickly."],
                )
            )
        else:
            findings.append(Finding(SAFE, "Websites", f"{host} uses an {c.key_type} certificate ({version})"))
    return findings


ALL_CHECKS = [check_ssh, check_gpg, check_git, check_keychain]
