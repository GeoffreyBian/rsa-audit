#!/bin/bash
# Builds dist/RSA Audit.app, a double-clickable wrapper around `python3 -m rsa_audit --app`.
# The package is copied into the bundle; the Python used to build it is the one it runs with.
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-$(command -v python3)}"
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
  echo "Needs Python 3.10+ (found $("$PYTHON" --version)). Set PYTHON=/path/to/python3." >&2
  exit 1
}

APP="dist/RSA Audit.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -R rsa_audit "$APP/Contents/Resources/"
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +

cat > "$APP/Contents/MacOS/rsa-audit" <<EOF
#!/bin/bash
cd "\$(dirname "\$0")/../Resources"
exec "$PYTHON" -E -s -B -m rsa_audit --app
EOF
chmod +x "$APP/Contents/MacOS/rsa-audit"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>RSA Audit</string>
  <key>CFBundleDisplayName</key><string>RSA Audit</string>
  <key>CFBundleIdentifier</key><string>com.geoffreybian.rsa-audit</string>
  <key>CFBundleExecutable</key><string>rsa-audit</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF

echo "Built $APP (runs with $PYTHON)"
