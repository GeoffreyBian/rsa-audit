# rsa-audit

Read-only check of what on your Mac would be exposed if RSA were broken, with
plain-language fixes for each finding.

No dependencies beyond Python 3.10+ and built-in macOS tools.

## Run the app

The app shows the report in your browser: a summary of what's exposed, a card
for each finding with step-by-step fixes (commands have a Copy button), an
optional website check, and a list of everything the scan looked at.

**Option 1: from the terminal**

```
git clone https://github.com/GeoffreyBian/rsa-audit.git
cd rsa-audit
python3 -m rsa_audit --app
```

Your browser opens to the report. Close the tab or click **Quit** to stop it
(it also shuts itself down a couple of minutes after the tab is closed).

**Option 2: as a Mac app you can double-click**

```
./scripts/build-mac-app.sh
open "dist/RSA Audit.app"
```

Drag `dist/RSA Audit.app` into `/Applications` to keep it. The app uses the
`python3` you built it with (needs 3.10+; on a fresh Mac, `brew install python`
first, or set `PYTHON=/path/to/python3` when building). Rebuild after pulling
updates.

The app server only listens on `127.0.0.1`, uses a random token each launch so
other websites can't trigger a scan, and never makes network calls unless you
type sites into the website check.

## Run in the terminal

```
python3 -m rsa_audit                               # local only, no network
python3 -m rsa_audit --sites github.com,mybank.com # also check these sites' certificates
python3 -m rsa_audit --json
```

## What it checks

- SSH: your private keys (public header only), `known_hosts`, `authorized_keys`, `IdentityFile` entries
- GPG keys (skipped without running gpg if you have no keyring, since gpg would create one)
- Git commit signing key
- Keychain: your own certificates/identities, other saved certs, and the system root store
- Websites you list with `--sites` (the only thing that touches the network)

## Ratings

- **RED**: exposed, and you can fix it
- **YELLOW**: exposed, but a server, site or vendor has to fix it
- **NOTE**: context
- **GREEN**: not affected by an RSA (factoring) break

## Safety

Every file read, command and connection goes through `rsa_audit/core.py`, which
only opens files for reading and only runs an allowlist of read-only commands.
The report ends with the full list of what was touched. Tests check that a scan
leaves a fake home directory byte-for-byte unchanged.

```
python3 -m unittest -v
```

## Not yet

Firmware image scanning, Linux/Windows, automatic fixes.
