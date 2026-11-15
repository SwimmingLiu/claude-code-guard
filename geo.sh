#!/bin/bash
# geo.sh — derive the egress IP's public profile and apply it to the Claude chain.
#
# Policy:
#   - The ONLY location source is the egress IP lookup (or an address the user
#     writes into config.env as GEO_ADDRESS). Device location (CoreLocation,
#     Wi-Fi, GPS) is never read, requested or stored.
#   - Timezone, region and the rest of the profile follow the current IP.
#   - Telemetry-related switches in Claude Code settings are forced on (off for
#     telemetry): DISABLE_TELEMETRY, DISABLE_ERROR_REPORTING, DO_NOT_TRACK and
#     CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC.
#   - The resolved profile is written to $STATE_DIR/geo.json for the UI.
#
# Modes:
#   (none)      fetch if stale, apply, print a summary
#   --force     fetch now even if the cached profile is fresh
#   --print     print the cached profile as JSON, never fetch or apply
#   --quiet     no stdout (used by guard.sh)
#
# Config: config.env next to this script (or $PROXYGUARD_CONFIG).

set -u
export LC_ALL=C
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONFIG_FILE=${PROXYGUARD_CONFIG:-$SCRIPT_DIR/config.env}
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

STATE_DIR=${STATE_DIR:-$HOME/.cache/proxyguard}
GEO_ENABLED=${GEO_ENABLED:-1}
GEO_URL=${GEO_URL:-https://ipinfo.io/json}
GEO_TIMEOUT=${GEO_TIMEOUT:-8}
GEO_REFRESH=${GEO_REFRESH:-600}
GEO_APPLY=${GEO_APPLY:-1}
GEO_WRITE_CC_ENV=${GEO_WRITE_CC_ENV:-1}
GEO_ADDRESS=${GEO_ADDRESS:-}
CC_SETTINGS=${CC_SETTINGS:-$HOME/.claude/settings.json}
PROXY_URL="http://${PROXY_HOST:-127.0.0.1}:${PROXY_PORT:-7897}"

FORCE=0
QUIET=0
PRINT=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --quiet) QUIET=1 ;;
    --print) PRINT=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

say() { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }
now() { date +%s; }

command -v jq >/dev/null 2>&1 || { say "geo: jq missing"; exit 1; }
mkdir -p "$STATE_DIR" 2>/dev/null || true
GEO_FILE="$STATE_DIR/geo.json"

if [ "$PRINT" = 1 ]; then
  [ -f "$GEO_FILE" ] && cat "$GEO_FILE"
  exit 0
fi

if [ "$GEO_ENABLED" != 1 ]; then
  say "geo: disabled (GEO_ENABLED=0)"
  exit 0
fi

age=999999
if [ -f "$GEO_FILE" ]; then
  mtime=$(stat -f %m "$GEO_FILE" 2>/dev/null || echo 0)
  age=$(( $(now) - mtime ))
fi
if [ "$FORCE" != 1 ] && [ "$age" -lt "$GEO_REFRESH" ]; then
  say "geo: fresh (${age}s old)"
  exit 0
fi

# ---- fetch: always through the Clash Verge mixed port ----
# A direct curl does not use the macOS system proxy and would expose the real
# ISP address whenever the system proxy is not set (ALLOW_TUN=0) or the TUN
# is down — silently moving TZ/region/telemetry to the real location. There is
# deliberately no direct fallback: no proxy answer means no refresh.
raw=$(curl -fsS --max-time "$GEO_TIMEOUT" -x "$PROXY_URL" "$GEO_URL" 2>/dev/null) || raw=""
if [ -z "$raw" ]; then
  # One retry rides out a node switch or a momentarily busy mixed port.
  raw=$(curl -fsS --max-time "$GEO_TIMEOUT" -x "$PROXY_URL" "$GEO_URL" 2>/dev/null) || raw=""
fi
if [ -z "$raw" ]; then
  say "geo: lookup failed (no response)"
  exit 1
fi

ip=$(printf '%s' "$raw" | jq -r '.ip // ""' 2>/dev/null)
country=$(printf '%s' "$raw" | jq -r '.country // ""' 2>/dev/null)
tz=$(printf '%s' "$raw" | jq -r '.timezone // ""' 2>/dev/null)
case "$ip" in
  ''|*[!0-9a-fA-F:.]*) say "geo: lookup returned no usable ip"; exit 1 ;;
esac
case "$country" in
  [A-Z][A-Z]) ;;
  *) say "geo: lookup returned no usable country"; exit 1 ;;
esac
if [ -z "$tz" ] || [ ! -f "/usr/share/zoneinfo/$tz" ]; then
  say "geo: lookup returned no valid timezone ($tz)"
  exit 1
fi

city=$(printf '%s' "$raw" | jq -r '.city // ""' 2>/dev/null)
region=$(printf '%s' "$raw" | jq -r '.region // ""' 2>/dev/null)
postal=$(printf '%s' "$raw" | jq -r '.postal // ""' 2>/dev/null)
loc=$(printf '%s' "$raw" | jq -r '.loc // ""' 2>/dev/null)
org=$(printf '%s' "$raw" | jq -r '.org // ""' 2>/dev/null)

# Location detail: the user's address wins when provided; the IP profile is
# the fallback. Timezone is always the IP's unless the address explicitly
# carries one (GEO_ADDRESS_TZ), so "time" follows the IP by default.
address="$city, $region, $country"
loc_source="ip"
if [ -n "$GEO_ADDRESS" ]; then
  address="$GEO_ADDRESS"
  loc_source="user"
fi

local_time=$(TZ="$tz" date '+%Y-%m-%d %H:%M:%S %Z')
system_tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')

# ---- apply timezone to future GUI / CLI launches ----
tz_applied=false
if [ "$GEO_APPLY" = 1 ]; then
  if launchctl setenv TZ "$tz" 2>/dev/null; then
    tz_applied=true
  fi
fi
tz_env=$(launchctl getenv TZ 2>/dev/null)

# ---- Claude Code settings: TZ + telemetry off ----
cc_env_ok=false
telemetry_off=false
cc_fail=0
if [ "$GEO_WRITE_CC_ENV" = 1 ] && [ -f "$CC_SETTINGS" ] && command -v jq >/dev/null 2>&1; then
  # Follow symlinks (dotfiles repos): rewrite the target file and keep the
  # link, instead of replacing the link with a regular file. Write the temp
  # next to the target so mv stays atomic on the same filesystem.
  settings_target=$CC_SETTINGS
  while [ -L "$settings_target" ]; do
    link=$(readlink "$settings_target" 2>/dev/null) || break
    case "$link" in
      /*) settings_target=$link ;;
      *) settings_target=$(dirname "$settings_target")/$link ;;
    esac
  done
  # stat on the resolved target: on macOS stat reports the link's own 0755
  # mode, not the file's, which would widen the settings file.
  mode=$(stat -f %Lp "$settings_target" 2>/dev/null || echo 600)
  tmp="${settings_target}.geo.$$"
  if ( umask 077; jq --arg tz "$tz" '
      .env = ((.env // {}) + {
        TZ: $tz,
        DISABLE_TELEMETRY: "1",
        DISABLE_ERROR_REPORTING: "1",
        DO_NOT_TRACK: "1",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
      })' "$CC_SETTINGS" > "$tmp" ) 2>/dev/null && [ -s "$tmp" ]; then
    # Keep the original permissions (settings.env may hold an auth token).
    chmod "$mode" "$tmp" 2>/dev/null
    if cmp -s "$tmp" "$settings_target"; then
      rm -f "$tmp"
      cc_env_ok=true
    else
      [ -f "$CC_SETTINGS.proxyguard.bak" ] || cp -p "$CC_SETTINGS" "$CC_SETTINGS.proxyguard.bak" 2>/dev/null
      if mv -f "$tmp" "$settings_target" 2>/dev/null; then
        cc_env_ok=true
        say "geo: Claude Code settings updated (TZ=$tz, telemetry off)"
      else
        rm -f "$tmp" 2>/dev/null
        cc_fail=1
        say "geo: Claude Code settings update failed (could not replace $settings_target)"
      fi
    fi
  else
    rm -f "$tmp" 2>/dev/null
    cc_fail=1
    say "geo: Claude Code settings update failed (jq)"
  fi
fi
if [ -f "$CC_SETTINGS" ]; then
  flags=$(jq -r '[.env.DISABLE_TELEMETRY, .env.DISABLE_ERROR_REPORTING, .env.DO_NOT_TRACK, .env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC] | map(select(. == "1")) | length' "$CC_SETTINGS" 2>/dev/null)
  [ "${flags:-0}" = "4" ] && telemetry_off=true
fi

# ---- write profile ----
tmpj="$STATE_DIR/.geo.$$"
jq -n \
  --argjson fetched_at "$(now)" \
  --arg time "$(date '+%Y-%m-%d %H:%M:%S')" \
  --arg source "$GEO_URL" \
  --arg ip "$ip" \
  --arg city "$city" \
  --arg region "$region" \
  --arg country "$country" \
  --arg postal "$postal" \
  --arg loc "$loc" \
  --arg org "$org" \
  --arg timezone "$tz" \
  --arg local_time "$local_time" \
  --arg system_tz "$system_tz" \
  --arg tz_env "$tz_env" \
  --argjson tz_applied "$tz_applied" \
  --arg address "$address" \
  --arg location_source "$loc_source" \
  --argjson telemetry_off "$telemetry_off" \
  --argjson cc_env_ok "$cc_env_ok" \
  --arg location_policy "device-location-never-read" \
  '{fetched_at: $fetched_at, time: $time, source: $source,
    ip: $ip, city: $city, region: $region, country: $country,
    postal: $postal, loc: $loc, org: $org, timezone: $timezone,
    local_time: $local_time, system_tz: $system_tz, tz_env: $tz_env,
    tz_applied: $tz_applied, address: $address, location_source: $location_source,
    telemetry_off: $telemetry_off, cc_env_ok: $cc_env_ok,
    location_policy: $location_policy}' > "$tmpj" 2>/dev/null \
  && mv -f "$tmpj" "$GEO_FILE" \
  || { rm -f "$tmpj"; say "geo: could not write $GEO_FILE"; exit 1; }

say "geo: $ip  $address  $tz  ($local_time)"
say "geo: tz_applied=$tz_applied cc_env_ok=$cc_env_ok telemetry_off=$telemetry_off"
exit "$cc_fail"
