#!/bin/bash
# Install proxyguard as a per-user launchd agent.
# It runs guard.sh --once every 10 seconds and kills Claude Desktop /
# Claude Code / magpie whenever egress is not covered by the Clash Verge proxy.
# Read README.md before running this.
#
# Files are staged and validated before the live copy is replaced; if launchd
# refuses to load the agent, the previous guard is restored and the script
# exits non-zero instead of leaving the guard silently disabled.

set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
DEST="$HOME/Library/Application Support/proxyguard"
PLIST="$HOME/Library/LaunchAgents/com.swimmingliu.proxyguard.plist"
LABEL="com.swimmingliu.proxyguard"
UID_NUM=$(id -u)
GUARD_PATH="$DEST/guard.sh"
GUARD_NEW="$DEST/guard.sh.new.$$"
GEO_PATH="$DEST/geo.sh"
GEO_NEW="$DEST/geo.sh.new.$$"
GEO_PREV="$DEST/geo.sh.prev"
ID_PATH="$DEST/identity.sh"
ID_NEW="$DEST/identity.sh.new.$$"
ID_PREV="$DEST/identity.sh.prev"
PLIST_PREV="$PLIST.prev"
PLIST_NEW="$PLIST.new.$$"
CONFIG_NEW=""

cleanup() {
  rm -f "$GUARD_NEW" "$GEO_NEW" "$ID_NEW" "$PLIST_NEW" 2>/dev/null || true
  [ -n "$CONFIG_NEW" ] && rm -f "$CONFIG_NEW" 2>/dev/null || true
}
trap cleanup EXIT

echo "== proxyguard install =="
echo "source : $SRC_DIR"
echo "dest   : $DEST"
echo "plist  : $PLIST"
echo

# same PATH guard.sh pins, so "install found jq" means the runtime finds it too
if ! PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
     command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required (mihomo TUN/rule-chain checks parse JSON with it)." >&2
  echo "       brew install jq" >&2
  exit 1
fi

if ! /bin/bash -n "$SRC_DIR/guard.sh" >/dev/null 2>&1; then
  echo "ERROR: $SRC_DIR/guard.sh has a syntax error; refusing to install." >&2
  exit 1
fi
if [ -f "$SRC_DIR/geo.sh" ] && ! /bin/bash -n "$SRC_DIR/geo.sh" >/dev/null 2>&1; then
  echo "ERROR: $SRC_DIR/geo.sh has a syntax error; refusing to install." >&2
  exit 1
fi

# sanity: show the current verdict first
if [ -f "$SRC_DIR/guard.sh" ]; then
  echo "-- current state (dry run) --"
  /bin/bash "$SRC_DIR/guard.sh" --check || true
  echo
fi

mkdir -p "$DEST" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs" "$HOME/.cache/proxyguard"

# ---- stage everything before touching the live copy ----
cp "$SRC_DIR/guard.sh" "$GUARD_NEW"
chmod 755 "$GUARD_NEW"
if [ -f "$SRC_DIR/geo.sh" ]; then
  cp "$SRC_DIR/geo.sh" "$GEO_NEW"
  chmod 755 "$GEO_NEW"
fi
if [ -f "$SRC_DIR/identity.sh" ]; then
  if ! /bin/bash -n "$SRC_DIR/identity.sh" >/dev/null 2>&1; then
    echo "ERROR: $SRC_DIR/identity.sh has a syntax error; refusing to install." >&2
    exit 1
  fi
  cp "$SRC_DIR/identity.sh" "$ID_NEW"
  chmod 755 "$ID_NEW"
fi
if [ ! -f "$DEST/config.env" ]; then
  CONFIG_NEW="$DEST/config.env.new.$$"
  if [ -f "$SRC_DIR/config.env" ]; then
    cp "$SRC_DIR/config.env" "$CONFIG_NEW"
    echo "will install config from $SRC_DIR/config.env"
  else
    cp "$SRC_DIR/config.env.example" "$CONFIG_NEW"
    echo "will install default config: $DEST/config.env"
  fi
else
  echo "kept existing config: $DEST/config.env"
fi

sed -e "s|__GUARD__|$GUARD_PATH|g" \
    -e "s|__LOGOUT__|$HOME/Library/Logs/proxyguard.launchd.log|g" \
    -e "s|__LOGERR__|$HOME/Library/Logs/proxyguard.launchd.err.log|g" \
    "$SRC_DIR/com.swimmingliu.proxyguard.plist" > "$PLIST_NEW"
plutil -lint "$PLIST_NEW" >/dev/null

if [ -n "$CONFIG_NEW" ]; then _cfg="$CONFIG_NEW"; else _cfg="$DEST/config.env"; fi

echo
echo "-- installed config dry run --"
PROXYGUARD_CONFIG="$_cfg" /bin/bash "$GUARD_NEW" --check || true
echo

# ---- stop the old agent before resetting its state or replacing files ----
launchctl bootout "gui/$UID_NUM" "$PLIST" 2>/dev/null || true

# Reset enforcement state in the *configured* state dir (it may be overridden
# in config.env) so the documented startup grace really starts at install time
# instead of inheriting an old counter, grace timestamp, or TUN device name.
_state=$(PROXYGUARD_CONFIG="$_cfg" /bin/bash -c \
  '. "$1" >/dev/null 2>&1; printf "%s" "${STATE_DIR:-$HOME/.cache/proxyguard}"' _ "$_cfg" 2>/dev/null || true)
[ -n "$_state" ] || _state="$HOME/.cache/proxyguard"
mkdir -p "$_state" 2>/dev/null || true
rm -f "$_state/fail_count" "$_state/started_this_boot" "$_state/boot_id" \
      "$_state/last_key" "$_state/last_ts" "$_state/last_run" \
      "$_state/wake_until" "$_state/tun_dev" "$_state/ever_ok" 2>/dev/null || true

# ---- atomically replace, keeping the previous files for rollback ----
if [ -f "$GUARD_PATH" ]; then
  cp -p "$GUARD_PATH" "$DEST/guard.sh.prev" 2>/dev/null || true
fi
if [ -f "$GEO_PATH" ]; then
  cp -p "$GEO_PATH" "$GEO_PREV" 2>/dev/null || true
fi
if [ -f "$ID_PATH" ]; then
  cp -p "$ID_PATH" "$ID_PREV" 2>/dev/null || true
fi
if [ -f "$PLIST" ]; then
  cp -p "$PLIST" "$PLIST_PREV" 2>/dev/null || true
fi
mv -f "$GUARD_NEW" "$GUARD_PATH"
if [ -f "$GEO_NEW" ]; then mv -f "$GEO_NEW" "$GEO_PATH"; fi
if [ -f "$ID_NEW" ]; then mv -f "$ID_NEW" "$ID_PATH"; fi
if [ -n "$CONFIG_NEW" ]; then mv -f "$CONFIG_NEW" "$DEST/config.env"; fi
mv -f "$PLIST_NEW" "$PLIST"

if ! launchctl bootstrap "gui/$UID_NUM" "$PLIST"; then
  echo "ERROR: launchctl bootstrap failed; restoring the previous files." >&2
  if [ -f "$DEST/guard.sh.prev" ]; then
    mv -f "$DEST/guard.sh.prev" "$GUARD_PATH"
  fi
  # The old guard must not pick up a new, possibly runtime-broken geo.sh.
  if [ -f "$GEO_PREV" ]; then
    mv -f "$GEO_PREV" "$GEO_PATH"
  else
    rm -f "$GEO_PATH"
  fi
  if [ -f "$ID_PREV" ]; then mv -f "$ID_PREV" "$ID_PATH"; fi
  if [ -f "$PLIST_PREV" ]; then mv -f "$PLIST_PREV" "$PLIST"; fi
  launchctl bootstrap "gui/$UID_NUM" "$PLIST" 2>/dev/null || true
  echo "       The agent was NOT started. Run: /bin/bash $GUARD_PATH --check" >&2
  exit 1
fi
launchctl kickstart -k "gui/$UID_NUM/$LABEL" 2>/dev/null || true

echo
echo "installed and loaded: $LABEL"
echo "logs    : $HOME/Library/Logs/proxyguard.log"
echo "config  : $DEST/config.env"
echo "disable : ./uninstall.sh   (or set ENFORCE=0 in config.env)"
echo "check   : /bin/bash $GUARD_PATH --check"
if [ -f "$ID_PATH" ]; then
  echo "identity: /bin/bash $ID_PATH status    (查看身份闸门)"
  echo "          /bin/bash $ID_PATH apply     (写入 Claude Code 设置；会先备份)"
  echo "          /bin/bash $ID_PATH verify    (seatbelt 对照实验，只读)"
fi
