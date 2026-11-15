#!/bin/bash
# Install the built menu-bar app for this user and launch it.
# The app is a viewer/edit switch only: the guard itself runs from the
# LaunchAgent, so the app can be closed at any time without losing protection.
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
APP="$SRC_DIR/dist/ProxyGuard.app"
DEST_DIR="$HOME/Applications"
DEST="$DEST_DIR/ProxyGuard.app"

if [ ! -d "$APP" ]; then
  echo "building first..."
  "$SRC_DIR/build-app.sh"
fi

mkdir -p "$DEST_DIR"
rm -rf "$DEST"
cp -R "$APP" "$DEST"
codesign --force --deep --sign - "$DEST" >/dev/null 2>&1 || true

echo "installed: $DEST"
open "$DEST"
echo "opened; look for the shield icon in the menu bar."
