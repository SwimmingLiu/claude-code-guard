#!/bin/bash
# Build ProxyGuard.app (menu-bar dashboard) with the Command Line Tools only.
# Output: dist/ProxyGuard.app — ad-hoc signed, no Xcode project required.
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
APP="$SRC_DIR/dist/ProxyGuard.app"
BIN="$APP/Contents/MacOS/ProxyGuard"
INFO="$APP/Contents/Info.plist"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "ERROR: swiftc not found (install Xcode Command Line Tools: xcode-select --install)" >&2
  exit 1
fi
if ! /bin/bash -n "$SRC_DIR/guard.sh" >/dev/null 2>&1; then
  echo "ERROR: guard.sh has a syntax error" >&2
  exit 1
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

cat > "$INFO" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>ProxyGuard</string>
  <key>CFBundleDisplayName</key><string>ProxyGuard</string>
  <key>CFBundleIdentifier</key><string>com.swimmingliu.proxyguardui</string>
  <key>CFBundleExecutable</key><string>ProxyGuard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
plutil -lint "$INFO" >/dev/null

echo "compiling..."
swiftc -O -swift-version 5 -target "$(uname -m)-apple-macos13.0" \
  -framework Cocoa -o "$BIN" "$SRC_DIR/app/main.swift"

codesign --force --sign - "$APP" >/dev/null 2>&1 || {
  echo "WARNING: ad-hoc codesign failed; the app still runs locally." >&2
}

echo "built: $APP"
echo "run  : open \"$APP\""
