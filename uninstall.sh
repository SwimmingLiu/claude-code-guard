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
  # The gate lives in ~/.claude/settings.json, not in $DEST, and reverting it
  # needs only bash+jq plus the backup. Never claim it was reverted unless we
  # checked: the backup is a user-deletable dotfile, jq may be missing, and an
  # older install may not have $DEST/identity.sh at all. Deleting the tool
  # while reporting success would leave the gate on with no off-switch.
  gate_reverted=false
  if [ -x "$DEST/identity.sh" ]; then
    if /bin/bash "$DEST/identity.sh" revert; then
      gate_reverted=true
    fi
  elif [ -f "$HOME/.claude/settings.json.proxyguard.bak" ]; then
    # No installed tool: restore the backup inline so the gate still comes off.
    if cp -p "$HOME/.claude/settings.json.proxyguard.bak" \
              "$HOME/.claude/settings.json.proxyguard.restore" \
       && mv -f "$HOME/.claude/settings.json.proxyguard.restore" \
                "$HOME/.claude/settings.json"; then
      echo "restored ~/.claude/settings.json from its proxyguard backup"
      gate_reverted=true
    fi
  fi
  if [ "$gate_reverted" = true ]; then
    rm -rf "$DEST" "$HOME/Library/Logs/proxyguard.log" \
           "$HOME/Library/Logs/proxyguard.launchd.log" \
           "$HOME/Library/Logs/proxyguard.launchd.err.log" \
           "$HOME/.cache/proxyguard"
    # identity.sh revert exits 0 both for "restored from backup" and for the
    # surgical path it takes when the backup is gone, so don't name the backup.
    echo "purged config, state and logs (identity gate turned off)"
  else
    # Keep the tool: with the gate still applied, identity.sh is the only
    # supported off-switch. Deleting it here would strand the user.
    rm -f "$HOME/Library/Logs/proxyguard.log" \
          "$HOME/Library/Logs/proxyguard.launchd.log" \
          "$HOME/Library/Logs/proxyguard.launchd.err.log"
    echo "the launchd agent is unloaded and its logs removed, but NOT purged:"
    echo "⚠️  the identity gate is still in ~/.claude/settings.json."
    # Say only what is actually possible. With a backup, restore it; without
    # one, identity.sh removes exactly what it added (surgical revert) — so
    # never print a `cp` of a file that isn't there.
    if [ -f "$HOME/.claude/settings.json.proxyguard.bak" ]; then
      [ -x "$DEST/identity.sh" ] && echo "    Turn it off with:" && \
        echo "      /bin/bash \"$DEST/identity.sh\" revert"
      echo "    Or restore the backup by hand:"
      echo "      cp -p ~/.claude/settings.json.proxyguard.bak ~/.claude/settings.json"
    elif [ -x "$DEST/identity.sh" ]; then
      echo "    There is no backup to restore, but identity.sh can still remove"
      echo "    exactly the entries the gate added:"
      echo "      /bin/bash \"$DEST/identity.sh\" revert"
    else
      echo "    There is no backup and no installed identity.sh: remove by hand"
      echo "    from ~/.claude/settings.json:"
      echo "      - sandbox.filesystem.denyRead"
      echo "      - permissions.deny entries starting with Read( or Bash("
      echo "      - env.TZ / env.LANG / env.LC_ALL"
    fi
    [ -x "$DEST/identity.sh" ] && echo "    Kept $DEST so the off-switch stays available."
  fi
else
  echo "kept $DEST and logs (use --purge to remove)"
  if [ -x "$DEST/identity.sh" ]; then
    echo "identity gate may still be applied in ~/.claude/settings.json;"
    echo "  revert it with: /bin/bash \"$DEST/identity.sh\" revert"
  fi
fi
