#!/bin/bash
# Unload and remove the proxyguard launchd agent. Keeps config and logs by
# default; pass --purge to delete them too.

set -u
PLIST="$HOME/Library/LaunchAgents/com.swimmingliu.proxyguard.plist"
DEST="$HOME/Library/Application Support/proxyguard"
LABEL="com.swimmingliu.proxyguard"
UID_NUM=$(id -u)

launchctl bootout "gui/$UID_NUM" "$PLIST" 2>/dev/null || true
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
echo "unloaded $LABEL"

if [ "${1:-}" = "--purge" ]; then
  if [ -x "$DEST/identity.sh" ]; then
    /bin/bash "$DEST/identity.sh" revert 2>/dev/null || true
  fi
  rm -rf "$DEST" "$HOME/Library/Logs/proxyguard.log" \
         "$HOME/Library/Logs/proxyguard.launchd.log" \
         "$HOME/Library/Logs/proxyguard.launchd.err.log" \
         "$HOME/.cache/proxyguard"
  echo "purged config, state and logs (identity gate reverted from its backup)"
else
  echo "kept $DEST and logs (use --purge to remove)"
  if [ -x "$DEST/identity.sh" ]; then
    echo "identity gate is still applied in ~/.claude/settings.json;"
    echo "  revert it with: /bin/bash \"$DEST/identity.sh\" revert"
  fi
fi
