#!/bin/bash
# proxyguard — fail-closed egress guard for the Claude chain.
#
# Policy:
#   Claude Desktop / Claude Code (and the local model gateway "magpie" they
#   depend on) are allowed to run only while their egress is actually covered
#   by the Clash Verge proxy (system proxy 127.0.0.1:7897 and/or TUN utun1024).
#   If the proxy is down, the network is down, or a Claude process has a
#   non-loopback TCP connection while nothing covers it, the guard terminates
#   the Claude chain instead of letting it fall back to a direct connection.
#
# Modes:
#   --check                 one-shot dry run, prints a report, never kills
#   --status                same report, exit 0
#   --once                  one enforcement tick (launchd calls this)
#   --loop                  enforcement loop (manual use)
#   --json                  with --check/--status: print JSON instead of text
#   --state-dir             print the resolved state directory and exit
#   --simulate=unhealthy    force a failing health check (test aid, never kills)
#   --simulate=direct       force "no TUN, no system proxy" (test aid)
#   --simulate=bypass       inject a fake external socket (test aid)
#
# Config: config.env next to this script (or $PROXYGUARD_CONFIG).

set -u
export LC_ALL=C
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONFIG_FILE=${PROXYGUARD_CONFIG:-$SCRIPT_DIR/config.env}
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

PROXY_HOST=${PROXY_HOST:-127.0.0.1}
PROXY_PORT=${PROXY_PORT:-7897}
PROXY_PORTS=${PROXY_PORTS:-"7897 7898 7899"}
HEALTH_URLS=${HEALTH_URLS:-"http://www.gstatic.com/generate_204 https://api.anthropic.com/"}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-5}
INTERVAL=${INTERVAL:-10}
FAIL_THRESHOLD=${FAIL_THRESHOLD:-2}
STARTUP_GRACE=${STARTUP_GRACE:-30}
ENFORCE=${ENFORCE:-1}
ALLOW_TUN=${ALLOW_TUN:-1}
KILL_GATEWAY=${KILL_GATEWAY:-1}
BYPASS_KILL_IMMEDIATE=${BYPASS_KILL_IMMEDIATE:-1}
CUT_NETWORK=${CUT_NETWORK:-0}
WIFI_DEVICE=${WIFI_DEVICE:-en0}
STATE_DIR=${STATE_DIR:-$HOME/.cache/proxyguard}
LOG_FILE=${LOG_FILE:-$HOME/Library/Logs/proxyguard.log}
LOG_MAX_BYTES=${LOG_MAX_BYTES:-1048576}
MIHOMO_SOCK_FALLBACK=${MIHOMO_SOCK_FALLBACK:-"/var/run/clash-verge-service/users/$(id -u)/verge-mihomo.sock"}
# Optional explicit controller socket (service mode / non-standard layout).
MIHOMO_SOCK_OVERRIDE=${MIHOMO_SOCK_OVERRIDE:-}
DRY_RUN=${DRY_RUN:-0}
# Under TUN, a healthy control plane plus route coverage is enough: an
# upstream node that blocks the probe URL is not a direct-egress leak. Set 1
# to keep requiring the TCP/HTTP probe even when TUN covers.
HEALTH_UNDER_TUN=${HEALTH_UNDER_TUN:-0}
# Extra grace after a detected sleep/wake gap, in seconds.
WAKE_GRACE=${WAKE_GRACE:-15}

# Egress-IP profile (geo.sh): refresh cadence in seconds. The profile drives
# the timezone injected into the Claude chain and the "IP 身份" UI card.
GEO_ENABLED=${GEO_ENABLED:-1}
GEO_REFRESH=${GEO_REFRESH:-600}

# Rule-result audit: a connection that Clash carries through a DIRECT rule is
# still "not proxied" even though TUN captures it. Check live mihomo
# connections for Claude/Anthropic/OpenAI hosts and treat DIRECT as bypass.
VERIFY_CHAINS=${VERIFY_CHAINS:-1}
# When the rule audit cannot run (controller unreadable, jq missing, process
# attribution unavailable) while Claude processes are running, coverage is
# unverified: fail closed after FAIL_THRESHOLD instead of trusting TUN alone.
REQUIRE_CHAIN_AUDIT=${REQUIRE_CHAIN_AUDIT:-1}
CLAUDE_HOST_RE=${CLAUDE_HOST_RE:-'(^|[.])(anthropic[.]com|claude[.]ai|claudeusercontent[.]com|openai[.]com|chatgpt[.]com)$'}
CHAIN_DIRECT_KILL=${CHAIN_DIRECT_KILL:-1}
# Report (default) or kill direct connections from Claude-chain processes to
# hosts outside CLAUDE_HOST_RE (e.g. magpie's domestic model providers).
KILL_ANY_DIRECT=${KILL_ANY_DIRECT:-0}
# The acceptable final exit. A Claude/Anthropic/OpenAI connection must pass
# through this mihomo group; if the chain omits it (different node, DIRECT,
# another group), it is treated as not proxied even when TUN carries it.
# Set to "" to accept any non-DIRECT chain.
REQUIRED_CHAIN=${REQUIRED_CHAIN-"🛡️ 静态IP出口"}

MODE=check
SIMULATE=""
ALLOW_SIM_KILL=0
JSON_OUT=0
for arg in "$@"; do
  case "$arg" in
    --check)        MODE=check ;;
    --status)       MODE=status ;;
    --once)         MODE=once ;;
    --loop)         MODE=loop ;;
    --json)         JSON_OUT=1 ;;
    --state-dir)    MODE=state_dir ;;
    --no-enforce)   ENFORCE=0 ;;
    --allow-sim-kill) ALLOW_SIM_KILL=1 ;;
    --simulate=*)   SIMULATE=${arg#*=} ;;
    -h|--help)
      sed -n '2,23p' "$0"
      exit 0
      ;;
    *)
      printf 'unknown argument: %s (use --check/--status/--once/--loop)\n' "$arg" >&2
      exit 2
      ;;
  esac
done

# Flags the --loop children must inherit (the mode selectors are replaced by
# --once). Without this, "guard.sh --loop --no-enforce" would still enforce.
LOOP_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --check|--status|--once|--loop|-h|--help|--json|--state-dir) ;;
    *) LOOP_ARGS+=("$arg") ;;
  esac
done

case "$SIMULATE" in
  ""|unhealthy|direct|bypass) ;;
  *)
    printf 'unknown simulate mode: %s (unhealthy|direct|bypass)\n' "$SIMULATE" >&2
    exit 2
    ;;
esac

# ---------------------------------------------------------------- utilities
now() { date +%s; }

rotate_log() {
  [ -f "$LOG_FILE" ] || return 0
  size=$(stat -f %z "$LOG_FILE" 2>/dev/null || echo 0)
  if [ "$size" -gt "$LOG_MAX_BYTES" ]; then
    tmp=$(mktemp "$LOG_FILE.XXXXXX" 2>/dev/null) || return 0
    if tail -c 200000 "$LOG_FILE" > "$tmp" 2>/dev/null; then
      mv "$tmp" "$LOG_FILE"
    else
      rm -f "$tmp"
    fi
  fi
}

log() {
  rotate_log
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE" 2>/dev/null
}

say() { printf '%s\n' "$*"; }

usage_targets() {
  say "targets:"
  if [ -s "$TARGETS_FILE" ]; then
    while IFS=$'\t' read -r pid kind args; do
      say "  pid=$pid kind=$kind $(printf '%s' "$args" | cut -c1-110)"
    done < "$TARGETS_FILE"
  else
    say "  (none running)"
  fi
}

# ---------------------------------------------------------------- proxy checks
mihomo_socket() {
  local sock
  if [ -n "$MIHOMO_SOCK_OVERRIDE" ]; then
    printf '%s' "$MIHOMO_SOCK_OVERRIDE"
    return
  fi
  # Prefer the per-user controller socket path: it is what Clash Verge
  # actually creates, and scanning ps can match unrelated processes whose
  # command line merely mentions "-ext-ctl-unix" (editors, grep, other
  # scripts), which previously produced a bogus path and silently disabled
  # both TUN and rule-chain checks.
  if [ -S "$MIHOMO_SOCK_FALLBACK" ]; then
    printf '%s' "$MIHOMO_SOCK_FALLBACK"
    return
  fi
  sock=$(ps -axo args= 2>/dev/null | awk '
    $1 ~ /(^|\/)(verge-)?mihomo$/ {
      for (i = 1; i < NF; i++) if ($i == "-ext-ctl-unix") { print $(i + 1); exit }
    }' 2>/dev/null)
  [ -n "$sock" ] || sock="$MIHOMO_SOCK_FALLBACK"
  printf '%s' "$sock"
}

jq_get() {
  # $1 = jq expression. Do NOT append "// empty": jq treats false as empty,
  # which would turn an explicit tun.enable=false into "unknown" and let the
  # saved-device fallback treat a disabled TUN as coverage.
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$MIHOMO_CFG" | jq -r "$1" 2>/dev/null
  else
    printf ''
  fi
}

check_mihomo() {
  MIHOMO_SOCK=$(mihomo_socket)
  MIHOMO_OK=0
  MIHOMO_CFG=""
  MIHOMO_MODE=""
  MIXED_PORT=""
  PROC_MODE=""
  TUN_ON=unknown
  TUN_DEV=""
  if [ -S "$MIHOMO_SOCK" ]; then
    MIHOMO_CFG=$(curl -sS --max-time 3 --unix-socket "$MIHOMO_SOCK" http://localhost/configs 2>/dev/null) || MIHOMO_CFG=""
  fi
  if [ -n "$MIHOMO_CFG" ] && printf '%s' "$MIHOMO_CFG" | grep -q '"mode"'; then
    MIHOMO_OK=1
    MIHOMO_MODE=$(jq_get '.mode')
    MIXED_PORT=$(jq_get '."mixed-port"')
    PROC_MODE=$(jq_get '."find-process-mode"')
    TUN_ON=$(jq_get '.tun.enable')
    TUN_DEV=$(jq_get '.tun.device')
    case "$MIHOMO_MODE" in null) MIHOMO_MODE="" ;; esac
    case "$MIXED_PORT" in null) MIXED_PORT="" ;; esac
    case "$PROC_MODE" in null) PROC_MODE="" ;; esac
    case "$TUN_DEV" in null) TUN_DEV="" ;; esac
    case "$TUN_ON" in
      true|false) ;;
      *) TUN_ON=unknown ;;
    esac
    [ -n "$MIXED_PORT" ] || MIXED_PORT=""
    # Explicitly disabled TUN: never fall back to the saved device later.
    [ "$TUN_ON" = "false" ] && rm -f "$STATE_DIR/tun_dev" 2>/dev/null
    # Without jq the JSON cannot be parsed; never claim the API is usable.
    if ! command -v jq >/dev/null 2>&1; then
      MIHOMO_OK=0
      MIHOMO_MODE=""
      MIXED_PORT=""
      PROC_MODE=""
      TUN_ON=unknown
      TUN_DEV=""
    fi
    if [ "$TUN_ON" = "true" ] && [ -n "$TUN_DEV" ]; then
      printf '%s' "$TUN_DEV" > "$STATE_DIR/tun_dev" 2>/dev/null
    fi
  fi
}

check_tun() {
  TUN_COV=0
  [ "$ALLOW_TUN" = 1 ] || return 0
  # If the controller API hiccupped (timeout, restart, 401), do not lose TUN
  # coverage: fall back to the last device the API confirmed, then verify it
  # against ifconfig and the live route table. An explicit tun=false from the
  # API is still respected.
  if [ "$TUN_ON" = "unknown" ]; then
    saved=$(cat "$STATE_DIR/tun_dev" 2>/dev/null)
    [ -n "$saved" ] || return 0
    TUN_DEV=$saved
    TUN_ON=unknown-saved
  fi
  [ "$TUN_ON" = "true" ] || [ "$TUN_ON" = "unknown-saved" ] || return 0
  [ -n "$TUN_DEV" ] || return 0
  ifconfig "$TUN_DEV" >/dev/null 2>&1 || return 0
  ifconfig "$TUN_DEV" 2>/dev/null | grep -q 'inet ' || return 0
  # Clash's auto-route here installs 1.0.0.0/8 .. 128.0.0.0/1 (leaving the
  # unroutable 0.0.0.0/8 on the physical default route), not literally 0/1.
  # Probe four points across the unicast IPv4 space instead of guessing the
  # route layout; all of them must resolve to the TUN device.
  cov=1
  for _ip in 1.1.1.1 64.1.1.1 128.1.1.1 223.5.5.5; do
    _iface=$(route -n get -inet "$_ip" 2>/dev/null | awk '/interface:/{print $2; exit}')
    if [ "$_iface" != "$TUN_DEV" ]; then
      cov=0
      break
    fi
  done
  # IPv4-only proof is not enough: Clash here also installs IPv6 routes, and a
  # host with native IPv6 could otherwise egress around the proxy. Require the
  # IPv6 probes to land on the TUN as well.
  if [ "$cov" = 1 ]; then
    for _ip6 in 2606:4700:4700::1111 2001:4860:4860::8888; do
      _iface6=$(route -n get -inet6 "$_ip6" 2>/dev/null | awk '/interface:/{print $2; exit}')
      if [ "$_iface6" != "$TUN_DEV" ]; then
        cov=0
        break
      fi
    done
  fi
  TUN_COV=$cov
}

sp_get() {
  printf '%s\n' "$SP_TEXT" | awk -F' : ' -v k="$1" '{key=$1; gsub(/^[ \t]+|[ \t]+$/,"",key); if(key==k){print $2; exit}}' | tr -d ' '
}

port_allowed() {
  case " $PROXY_PORTS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

# Physical link check: with TUN on, routes still exist after Wi-Fi is turned
# off, so coverage alone cannot tell "network down". The primary interface's
# link status can.
check_link() {
  LINK_UP=0
  LINK_IFACE=""
  _di=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
  if [ -n "$_di" ] && ifconfig "$_di" 2>/dev/null | grep -q 'status: active'; then
    LINK_UP=1
    LINK_IFACE=$_di
  fi
}

check_system_proxy() {  SP_TEXT=$(scutil --proxy 2>/dev/null)
  SYSPROXY_OK=0
  SYSPROXY_DESC="off"
  for trio in "HTTPSEnable:HTTPSProxy:HTTPSPort" "HTTPEnable:HTTPProxy:HTTPPort" "SOCKSEnable:SOCKSProxy:SOCKSPort"; do
    en_k=${trio%%:*}; rest=${trio#*:}
    host_k=${rest%%:*}; port_k=${rest#*:}
    en=$(sp_get "$en_k"); host=$(sp_get "$host_k"); port=$(sp_get "$port_k")
    if [ "$en" = "1" ] && [ "$host" = "$PROXY_HOST" ] && [ -n "$port" ] && port_allowed "$port"; then
      SYSPROXY_OK=1
      SYSPROXY_DESC="${en_k%Enable}=$host:$port"
      break
    fi
  done
  # A Claude host in the macOS proxy ExceptionsList bypasses the system proxy
  # even though HTTPSEnable=1. In that case the proxy is not coverage for it.
  excl=$(printf '%s\n' "$SP_TEXT" | sed -n '/ExceptionsList/,/^  }/p' \
    | grep -Ei 'anthropic|claude|openai|chatgpt|: \*[[:space:]]*$' 2>/dev/null || true)
  if [ -n "$excl" ]; then
    SYSPROXY_OK=0
    SYSPROXY_DESC="$SYSPROXY_DESC exceptions-cover-claude"
  fi
}

check_tcp() {
  HEALTH_TCP=0
  if nc -z -G 2 "$PROXY_HOST" "$HEALTH_PORT" >/dev/null 2>&1; then
    HEALTH_TCP=1
  fi
}

check_http() {
  HEALTH_HTTP_CODES=""
  HEALTH_HTTP_OK=0
  round=0
  while [ "$round" -lt 2 ]; do
    round=$((round + 1))
    for url in $HEALTH_URLS; do
      code=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 2 \
        -x "http://$PROXY_HOST:$HEALTH_PORT" --max-time "$HEALTH_TIMEOUT" "$url" 2>/dev/null) || code=000
      HEALTH_HTTP_CODES="$HEALTH_HTTP_CODES $code"
      case "$code" in
        2??|3??|4??)
          if [ "$code" != 407 ]; then
            HEALTH_HTTP_OK=1
            break
          fi
          ;;
      esac
    done
    [ "$HEALTH_HTTP_OK" = 1 ] && break
    [ "$round" -lt 2 ] && sleep 1
  done
}

# A DIRECT rule still means "not proxied", even when TUN carries the packets.
# Inspect live mihomo connections for Claude/Anthropic/OpenAI hosts.
check_chains() {
  CHAIN_CHECKED=0
  CHAIN_DIRECT=0
  CHAIN_DETAIL=""
  CHAIN_OTHER_DIRECT=0
  CHAIN_OTHER_DETAIL=""
  # CHAIN_AUDIT_OK=1 only after /connections was read and parsed. Callers use
  # it to fail closed when the required-exit check could not run at all.
  CHAIN_AUDIT_OK=0
  CHAIN_UNVERIFIED=0
  [ "$VERIFY_CHAINS" = 1 ] || { CHAIN_AUDIT_OK=1; return 0; }
  [ "$MIHOMO_OK" = 1 ] || return 0
  [ -S "$MIHOMO_SOCK" ] || return 0
  command -v jq >/dev/null 2>&1 || return 0
  # An invalid CLAUDE_HOST_RE makes every jq query below exit 5. Without this
  # probe the empty results would look like "nothing to audit" and the audit
  # would be reported successful while checking nothing (fail-open).
  if ! printf '' | jq -n --arg re "$CLAUDE_HOST_RE" '"" | test($re)' >/dev/null 2>&1; then
    CHAIN_DETAIL=" invalid CLAUDE_HOST_RE"
    CHAIN_UNVERIFIED=1
    return 0
  fi
  conns=$(curl -sS --max-time 3 --unix-socket "$MIHOMO_SOCK" \
    http://localhost/connections 2>/dev/null) || return 0
  [ -n "$conns" ] || return 0
  # An empty list is a valid answer (nothing connected); malformed JSON is not.
  printf '%s' "$conns" | jq -e '(.connections // []) | type == "array"' >/dev/null 2>&1 || return 0
  CHAIN_AUDIT_OK=1
  rows=$(printf '%s' "$conns" | jq -r --arg re "$CLAUDE_HOST_RE" '
    .connections[]?
    | select(((.metadata.processPath // "") | test("Claude|magpie|antify|node|bun"; "i")))
    | (if ((.metadata.host // "") | length) > 0 then .metadata.host else (.metadata.destinationIP // "") end) as $h
    | select(($h | tostring) | test($re; "i"))
    | [ ($h | tostring),
        (if ((.chains[0] // "") == "DIRECT") then 1 else 0 end),
        ((.chains // []) | join(" > ")) ]
    | @tsv
  ' 2>/dev/null) || { CHAIN_AUDIT_OK=0; CHAIN_DETAIL=" chain query failed"; CHAIN_UNVERIFIED=1; return 0; }
  if [ -n "$rows" ]; then
    while IFS=$'\t' read -r host direct chain; do
      [ -n "$host" ] || continue
      CHAIN_CHECKED=$((CHAIN_CHECKED + 1))
      if [ "$direct" = "1" ]; then
        CHAIN_DIRECT=1
        CHAIN_DETAIL="$CHAIN_DETAIL $host{$chain}"
      elif [ -n "$REQUIRED_CHAIN" ]; then
        case " > $chain > " in
          *" > $REQUIRED_CHAIN > "*) : ;;
          *)
            CHAIN_DIRECT=1
            CHAIN_DETAIL="$CHAIN_DETAIL $host{no-required-exit:$chain}"
            ;;
        esac
      fi
    done <<< "$rows"
  fi

  # If mihomo cannot attribute a Claude-host connection to a process (its
  # find-process-mode is off/limited), the audit above saw nothing for it.
  # Treat that as "not verifiable", not as "proxied".
  pidless=$(printf '%s' "$conns" | jq -r --arg re "$CLAUDE_HOST_RE" '
    [.connections[]?
     | select(((.metadata.processPath // "") | length) == 0)
     | (if ((.metadata.host // "") | length) > 0 then .metadata.host else (.metadata.destinationIP // "") end) as $h
     | select(($h | tostring) | test($re; "i"))] | length
  ' 2>/dev/null) || { CHAIN_AUDIT_OK=0; CHAIN_DETAIL=" chain query failed"; CHAIN_UNVERIFIED=1; return 0; }
  case "$pidless" in ''|*[!0-9]*) pidless=0 ;; esac
  [ "$pidless" -gt 0 ] && CHAIN_UNVERIFIED=1

  # Visibility for DIRECT egress from a Claude-chain process to a host outside
  # the model allowlist (observed: magpie -> api.deepseek.com DIRECT).
  other=$(printf '%s' "$conns" | jq -r --arg re "$CLAUDE_HOST_RE" '
    .connections[]?
    | select(((.metadata.processPath // "") | test("Claude|magpie|antify"; "i")))
    | select((.chains[0] // "") == "DIRECT")
    | (if ((.metadata.host // "") | length) > 0 then .metadata.host else (.metadata.destinationIP // "") end) as $h
    | select(((($h | tostring) | test($re; "i")) | not))
    | ($h | tostring)' 2>/dev/null) || { CHAIN_AUDIT_OK=0; CHAIN_DETAIL=" chain query failed"; CHAIN_UNVERIFIED=1; return 0; }
  if [ -n "$other" ]; then
    CHAIN_OTHER_DIRECT=$(printf '%s\n' "$other" | grep -c .)
    CHAIN_OTHER_DETAIL=$(printf '%s\n' "$other" | head -3 | tr '\n' ' ')
    if [ "$KILL_ANY_DIRECT" = 1 ]; then
      CHAIN_DIRECT=1
      CHAIN_DETAIL="$CHAIN_DETAIL other-direct:$CHAIN_OTHER_DETAIL"
    fi
  fi
}

# ---------------------------------------------------------------- targets
is_guard_arg() {
  # Skip only the guard's own helper scripts, not every process that happens
  # to mention the project directory (a Claude session opened with --add-dir
  # .../proxyguard must stay a target).
  case "$1" in
    *"/guard.sh"*|*"/install.sh"*|*"/uninstall.sh"*) return 0 ;;
    *) return 1 ;;
  esac
}

kind_of_comm() {
  local a=$1
  case "$a" in
    # Prefix wildcard: also matches ~/Applications/Claude.app.
    *"/Claude.app/Contents/MacOS/Claude")             printf 'desktop' ;;
    *"/Claude.app/Contents/"*)                        printf 'desktop-helper' ;;
    *claude-code*/Contents/MacOS/claude)              printf 'claude-code' ;;
    *"/Caskroom/claude-code"*)                        printf 'claude-code' ;;
    *"/.claude/local/claude")                         printf 'claude-code' ;;
    *"/bin/claude")                                   printf 'claude-code' ;;
    *"/Applications/magpie.app/Contents/MacOS/magpie"*) printf 'gateway' ;;
    *"/magpie-bun")                                   printf 'gateway' ;;
    *)                                                printf '' ;;
  esac
}

# Classify by the process's real executable (ps -o comm=), not by substrings of
# its argv: a shell, editor or grep that merely mentions a target path must not
# be killed. node/bun-hosted CLIs keep the args fallback.
kind_of_process() {
  local pid=$1 comm k args
  comm=$(ps -p "$pid" -o comm= 2>/dev/null)
  [ -n "$comm" ] || return 1
  k=$(kind_of_comm "$comm")
  if [ -z "$k" ]; then
    case "${comm##*/}" in
      node|nodejs|bun|deno)
        args=$(ps -p "$pid" -o args= 2>/dev/null)
        case "$args" in
          *"@anthropic-ai/claude-code"*|*claude-code*/Contents/MacOS/claude*) k=claude-code ;;
        esac
        ;;
    esac
  fi
  [ -n "$k" ] || return 1
  printf '%s' "$k"
}

collect_targets() {
  local out=$1 ps_out pid comm kind args
  : > "$out" 2>/dev/null || { AUDIT_FAILED=1; return 1; }
  command -v ps >/dev/null 2>&1 || { AUDIT_FAILED=1; return 1; }
  # Capture first: a pipeline would hide ps's exit status in a subshell.
  ps_out=$(ps -axo pid=,comm= 2>/dev/null) || { AUDIT_FAILED=1; return 1; }
  [ -n "$ps_out" ] || { AUDIT_FAILED=1; return 1; }
  printf '%s\n' "$ps_out" | while read -r pid comm; do
    [ -n "${pid:-}" ] || continue
    [ "$pid" = "$$" ] && continue
    kind=$(kind_of_comm "$comm")
    if [ -z "$kind" ]; then
      case "${comm##*/}" in
        node|nodejs|bun|deno) ;;
        *) continue ;;
      esac
      args=$(ps -p "$pid" -o args= 2>/dev/null)
      case "$args" in
        *"@anthropic-ai/claude-code"*|*claude-code*/Contents/MacOS/claude*) kind=claude-code ;;
        *) continue ;;
      esac
    else
      args=$(ps -p "$pid" -o args= 2>/dev/null)
    fi
    is_guard_arg "$args" && continue
    printf '%s\t%s\t%s\n' "$pid" "$kind" "$args" >> "$out"
  done
}

# A socket to a private/LAN/link-local address is not an Anthropic request and
# macOS itself exempts these ranges from the system proxy (ExceptionsList).
# Killing on them would fire on legitimate local MCP/dev/LAN traffic.
is_local_remote() {
  local r=$1
  case "$r" in
    127.*|localhost:*|\[::1\]:*|\[::ffff:127.*) return 0 ;;
  esac
  case "${r%:*}" in
    10.*|192.168.*|169.254.*) return 0 ;;
    # Clash fake-IP DNS answers inside 198.18.0.0/15; these are not real
    # destinations and must not be counted as external sockets.
    198.18.*|198.19.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    \[fe80:*|\[fc[0-9a-f]*|\[fd[0-9a-f]*) return 0 ;;
  esac
  return 1
}

audit_sockets() {
  hits=$1
  : > "$hits"
  : > "$hits.raw"
  [ -s "$TARGETS_FILE" ] || return 0
  command -v lsof >/dev/null 2>&1 || { AUDIT_FAILED=1; return 1; }
  while IFS=$'\t' read -r pid kind args; do
    # TCP and connected UDP: QUIC is not covered by the system proxy, so it is
    # part of "did anything leave outside the proxy".
    lsof -nP -iTCP -iUDP -a -p "$pid" 2>/dev/null \
      | awk -v p="$pid" -v k="$kind" 'NR>1 && $9 ~ /->/ {print p "\t" k "\t" $9}' \
      >> "$hits.raw"
  done < "$TARGETS_FILE"
  [ -f "$hits.raw" ] || return 0
  while IFS=$'\t' read -r pid kind conn; do
    remote=${conn#*->}
    if ! is_local_remote "$remote"; then
      printf '%s\t%s\t%s\n' "$pid" "$kind" "$remote" >> "$hits"
    fi
  done < "$hits.raw"
  rm -f "$hits.raw"
}

# ---------------------------------------------------------------- verdict
evaluate() {
  AUDIT_FAILED=0
  check_mihomo
  check_tun
  check_link
  check_system_proxy
  # Prefer the port mihomo reports as mixed-port; fall back to PROXY_PORT.
  HEALTH_PORT=$PROXY_PORT
  if [ -n "$MIXED_PORT" ] && port_allowed "$MIXED_PORT"; then HEALTH_PORT=$MIXED_PORT; fi
  check_tcp
  # Under verified TUN coverage with a live control plane, the HTTP probe is
  # informational only; skipping it keeps the tick short (the plist fires
  # every 10s and a blocked URL could otherwise stretch it past 20s).
  if [ "$TUN_COV" = 1 ] && [ "$MIHOMO_OK" = 1 ] && [ "$HEALTH_UNDER_TUN" != 1 ]; then
    HEALTH_HTTP_OK=1
    HEALTH_HTTP_CODES=" skipped(tun)"
  else
    check_http
  fi
  check_chains
  collect_targets "$TARGETS_FILE"
  audit_sockets "$HITS_FILE"
  # If a required audit could not run while Claude processes are alive, the
  # exit is unverified. TUN alone cannot prove the selected group, so fail
  # closed through the normal failure threshold instead of trusting coverage.
  if [ "$VERIFY_CHAINS" = 1 ] && [ "$REQUIRE_CHAIN_AUDIT" = 1 ] \
     && [ -s "$TARGETS_FILE" ] && [ "$CHAIN_AUDIT_OK" != 1 ]; then
    CHAIN_UNVERIFIED=1
  fi
  # With find-process-mode=off mihomo never attributes connections, so the
  # process-filtered audit above can silently see nothing.
  if [ "$VERIFY_CHAINS" = 1 ] && [ "$REQUIRE_CHAIN_AUDIT" = 1 ] \
     && [ -s "$TARGETS_FILE" ] && [ "$PROC_MODE" = "off" ]; then
    CHAIN_UNVERIFIED=1
  fi
  # A global mode=direct means nothing is proxied, but only matters when a
  # Claude-chain process is actually running (otherwise there is nothing to
  # kill and CUT_NETWORK must not fire).
  if [ "$VERIFY_CHAINS" = 1 ] && [ "$MIHOMO_MODE" = "direct" ] && [ -s "$TARGETS_FILE" ]; then
    CHAIN_DIRECT=1
    CHAIN_DETAIL="$CHAIN_DETAIL global-direct"
  fi

  case "$SIMULATE" in
    unhealthy)
      HEALTH_TCP=0
      HEALTH_HTTP_OK=0
      HEALTH_HTTP_CODES=" 000"
      HEALTH_UNDER_TUN=1
      ;;
    direct)
      TUN_COV=0
      SYSPROXY_OK=0
      SYSPROXY_DESC="off (simulated)"
      ;;
    bypass)
      TUN_COV=0
      CHAIN_DIRECT=1
      CHAIN_DETAIL=" simulated-direct"
      printf '0\tsimulated\t203.0.113.7:443\n' >> "$HITS_FILE"
      ;;
  esac

  BYPASS=0
  if [ "$CHAIN_DIRECT" = 1 ] && [ "$CHAIN_DIRECT_KILL" = 1 ]; then
    BYPASS=1
  fi
  [ -s "$HITS_FILE" ] && [ "$TUN_COV" != 1 ] && BYPASS=1

  HEALTHY=1
  [ "$LINK_UP" = 1 ] || HEALTHY=0
  if [ "$TUN_COV" = 1 ] && [ "$MIHOMO_OK" = 1 ] && [ "$HEALTH_UNDER_TUN" != 1 ]; then
    :
  else
    [ "$HEALTH_TCP" = 1 ] || HEALTHY=0
    [ "$HEALTH_HTTP_OK" = 1 ] || HEALTHY=0
  fi
  if [ "$TUN_COV" = 1 ]; then
    :
  elif [ "$SYSPROXY_OK" = 1 ]; then
    [ "$BYPASS" = 0 ] || HEALTHY=0
  else
    HEALTHY=0
  fi
  [ "$BYPASS" = 1 ] && HEALTHY=0
  # A coverage claim that could not be verified is not coverage.
  [ "$CHAIN_UNVERIFIED" = 1 ] && HEALTHY=0
  [ "$AUDIT_FAILED" = 1 ] && HEALTHY=0
  # Degraded mode: if the controller API is down, TUN coverage proven by the
  # device and live route table still counts (rule-chain audit is skipped).
  [ "$MIHOMO_OK" = 1 ] || [ "$TUN_COV" = 1 ] || HEALTHY=0
}

coverage_text() {
  if [ "$TUN_COV" = 1 ]; then printf 'TUN(%s)' "$TUN_DEV"
  elif [ "$SYSPROXY_OK" = 1 ]; then printf 'system-proxy(%s)' "$SYSPROXY_DESC"
  else printf 'none'; fi
}

print_report() {
  say "proxyguard @ $(date '+%Y-%m-%d %H:%M:%S')"
  say "mihomo:      ok=$MIHOMO_OK  mode=${MIHOMO_MODE:-?}  tun=$TUN_ON  dev=$TUN_DEV  mixed-port=${MIXED_PORT:-?}  proc=${PROC_MODE:-?}  sock=$MIHOMO_SOCK"
  say "system proxy: $SYSPROXY_DESC  link=${LINK_UP}${LINK_IFACE:+($LINK_IFACE)}"
  say "tcp $PROXY_HOST:$HEALTH_PORT: $HEALTH_TCP   http codes:$HEALTH_HTTP_CODES (via proxy)"
  say "coverage:    $(coverage_text)"
  if [ "$VERIFY_CHAINS" = 1 ]; then
    say "rules:       checked=$CHAIN_CHECKED direct=$CHAIN_DIRECT$CHAIN_DETAIL"
    [ -n "$REQUIRED_CHAIN" ] && say "required exit: $REQUIRED_CHAIN"
    if [ "$CHAIN_AUDIT_OK" != 1 ]; then
      if [ "$REQUIRE_CHAIN_AUDIT" = 1 ]; then
        say "chain audit: unavailable (coverage unverified)"
      else
        say "chain audit: unavailable (not required)"
      fi
    elif [ "$CHAIN_UNVERIFIED" = 1 ]; then
      say "chain audit: attribution incomplete (coverage unverified)"
    fi
    if [ "$CHAIN_OTHER_DIRECT" -gt 0 ]; then
      if [ "$KILL_ANY_DIRECT" = 1 ]; then
        say "other direct: $CHAIN_OTHER_DIRECT (counted as bypass) from Claude-chain processes (${CHAIN_OTHER_DETAIL% })"
      else
        say "other direct: $CHAIN_OTHER_DIRECT (report only, not Claude hosts) from Claude-chain processes (${CHAIN_OTHER_DETAIL% })"
      fi
    fi
  else
    say "rules:       off"
  fi
  say "verdict:     $([ "$HEALTHY" = 1 ] && echo HEALTHY/PROXIED || echo UNHEALTHY/NOT-PROXIED)"
  [ "$AUDIT_FAILED" = 1 ] && say "socket audit: FAILED (ps/lsof unavailable)"
  usage_targets
  if [ -s "$HITS_FILE" ]; then
    say "external sockets:"
    while IFS=$'\t' read -r pid kind remote; do
      say "  pid=$pid kind=$kind remote=$remote"
    done < "$HITS_FILE"
  else
    say "external sockets: none"
  fi
}

# ---------------------------------------------------------------- machine report
# One JSON object per evaluate(), used by the menu-bar app and any other UI.
# jq is required to emit it; the guard keeps working (text report) without jq.
report_json() {
  local tj hj fail detail
  command -v jq >/dev/null 2>&1 || return 1
  if [ -s "$TARGETS_FILE" ]; then
    tj=$(jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {pid: .[0], kind: .[1], cmd: ((.[2] // "")[0:160])})' \
      "$TARGETS_FILE" 2>/dev/null) || tj='[]'
  else
    tj='[]'
  fi
  if [ -s "$HITS_FILE" ]; then
    hj=$(jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {pid: .[0], kind: .[1], remote: (.[2] // "")})' \
      "$HITS_FILE" 2>/dev/null) || hj='[]'
  else
    hj='[]'
  fi
  [ -n "$tj" ] || tj='[]'
  [ -n "$hj" ] || hj='[]'
  fail=$(read_int "$STATE_DIR/fail_count")
  detail=$(printf '%s' "${CHAIN_DETAIL# }" | sed 's/  */ /g')
  jq -n \
    --argjson ts "$(now)" \
    --arg time "$(date '+%Y-%m-%d %H:%M:%S')" \
    --argjson healthy "$([ "$HEALTHY" = 1 ] && printf true || printf false)" \
    --arg coverage "$(coverage_text)" \
    --argjson mihomo_ok "$MIHOMO_OK" \
    --arg mihomo_mode "$MIHOMO_MODE" \
    --arg tun_on "$TUN_ON" \
    --arg tun_dev "$TUN_DEV" \
    --argjson tun_cov "$TUN_COV" \
    --argjson sysproxy_ok "$SYSPROXY_OK" \
    --arg sysproxy_desc "$SYSPROXY_DESC" \
    --argjson link_up "$LINK_UP" \
    --arg link_iface "$LINK_IFACE" \
    --argjson tcp_ok "$HEALTH_TCP" \
    --argjson http_ok "$HEALTH_HTTP_OK" \
    --arg http_codes "$(printf '%s' "$HEALTH_HTTP_CODES" | sed 's/^ *//')" \
    --arg health_port "$HEALTH_PORT" \
    --argjson chain_checked "$CHAIN_CHECKED" \
    --argjson chain_direct "$CHAIN_DIRECT" \
    --arg chain_detail "$detail" \
    --argjson chain_audit_ok "$CHAIN_AUDIT_OK" \
    --argjson chain_unverified "$CHAIN_UNVERIFIED" \
    --argjson audit_failed "$AUDIT_FAILED" \
    --argjson bypass "$BYPASS" \
    --argjson other_direct "$CHAIN_OTHER_DIRECT" \
    --arg other_direct_detail "${CHAIN_OTHER_DETAIL% }" \
    --arg required_chain "$REQUIRED_CHAIN" \
    --argjson verify_chains "$VERIFY_CHAINS" \
    --argjson require_chain_audit "$REQUIRE_CHAIN_AUDIT" \
    --argjson kill_any_direct "$KILL_ANY_DIRECT" \
    --arg proc_mode "$PROC_MODE" \
    --arg mixed_port "$MIXED_PORT" \
    --argjson enforce "$([ "$ENFORCE" = 1 ] && [ "$DRY_RUN" != 1 ] && printf true || printf false)" \
    --argjson dry_run "$([ "$DRY_RUN" = 1 ] && printf true || printf false)" \
    --arg simulate "$SIMULATE" \
    --argjson interval "$INTERVAL" \
    --argjson fail_threshold "$FAIL_THRESHOLD" \
    --argjson fail_count "$fail" \
    --argjson targets "$tj" \
    --argjson hits "$hj" \
    '{ts: $ts, time: $time, healthy: $healthy,
      verdict: (if $healthy then "HEALTHY/PROXIED" else "UNHEALTHY/NOT-PROXIED" end),
      coverage: $coverage,
      mihomo_ok: $mihomo_ok, mihomo_mode: $mihomo_mode, proc_mode: $proc_mode,
      tun_on: $tun_on, tun_dev: $tun_dev, tun_cov: $tun_cov, mixed_port: $mixed_port,
      sysproxy_ok: $sysproxy_ok, sysproxy_desc: $sysproxy_desc,
      link_up: $link_up, link_iface: $link_iface,
      tcp_ok: $tcp_ok, http_ok: $http_ok, http_codes: $http_codes, health_port: $health_port,
      chain_checked: $chain_checked, chain_direct: $chain_direct, chain_detail: $chain_detail,
      chain_audit_ok: $chain_audit_ok, chain_unverified: $chain_unverified,
      audit_failed: $audit_failed, bypass: $bypass,
      other_direct: $other_direct, other_direct_detail: $other_direct_detail,
      required_chain: $required_chain, verify_chains: $verify_chains,
      require_chain_audit: $require_chain_audit, kill_any_direct: $kill_any_direct,
      enforce: $enforce, dry_run: $dry_run, simulate: $simulate,
      interval: $interval, fail_threshold: $fail_threshold, fail_count: $fail_count,
      targets: $targets, hits: $hits}'
}

# Refresh the egress-IP profile at most every GEO_REFRESH seconds. Runs after
# evaluation and detached: a slow or failing lookup must never delay the
# enforcement verdict, and a failed attempt is negatively cached so an
# unreachable proxy does not cost 2 x GEO_TIMEOUT on every tick.
refresh_geo_if_stale() {
  [ "$GEO_ENABLED" = 1 ] || return 0
  [ -x "$SCRIPT_DIR/geo.sh" ] || return 0
  local f m age stamp s_age
  f="$STATE_DIR/geo.json"
  m=$(stat -f %m "$f" 2>/dev/null || echo 0)
  age=$(( $(now) - m ))
  [ "$age" -lt "$GEO_REFRESH" ] && return 0
  stamp="$STATE_DIR/geo_attempt"
  s_age=$(( $(now) - $(stat -f %m "$stamp" 2>/dev/null || echo 0) ))
  [ "$s_age" -lt "$GEO_REFRESH" ] && return 0
  # If the attempt stamp cannot be written the state dir is unusable; geo.sh
  # could not store its result either, so do not spawn it.
  : > "$stamp" 2>/dev/null || return 0
  ( "$SCRIPT_DIR/geo.sh" --quiet >>"$LOG_FILE" 2>&1 & ) >/dev/null 2>&1 \
    || log "geo refresh failed to start"
}

# Replace the report atomically so a reader never sees a half-written file.
write_report_file() {
  [ -d "$STATE_DIR" ] || return 0
  local tmp
  tmp="$STATE_DIR/.last_report.$$"
  if report_json > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    mv -f "$tmp" "$STATE_DIR/last_report.json" 2>/dev/null
  else
    rm -f "$tmp" 2>/dev/null
  fi
}

# ---------------------------------------------------------------- enforcement
kill_list() {
  signalf=$1
  list=$2
  [ -s "$list" ] || return 0
  while IFS=$'\t' read -r pid kind args; do
    [ -n "$pid" ] || continue
    [ "$pid" -gt 1 ] 2>/dev/null || continue
    [ "$kind" = "gateway" ] && [ "$KILL_GATEWAY" != 1 ] && continue
    # Re-read the process right before signalling: the PID may have exited and
    # been reused between collect_targets and this loop.
    cur=$(ps -p "$pid" -o args= 2>/dev/null)
    [ -n "$cur" ] || continue
    ckind=$(kind_of_process "$pid")
    [ "$ckind" = "$kind" ] || continue
    is_guard_arg "$cur" && continue
    if [ "$DRY_RUN" = 1 ] || [ "$ENFORCE" != 1 ] || { [ -n "$SIMULATE" ] && [ "$ALLOW_SIM_KILL" != 1 ]; }; then
      log "would-send $signalf pid=$pid kind=$kind cmd=$(printf '%s' "$args" | cut -c1-140)"
      [ -n "$SIMULATE" ] && say "would-send $signalf pid=$pid kind=$kind $(printf '%s' "$args" | cut -c1-110)"
    else
      if kill -"$signalf" "$pid" 2>/dev/null; then
        log "sent $signalf pid=$pid kind=$kind cmd=$(printf '%s' "$args" | cut -c1-140)"
      fi
    fi
  done < "$list"
}

enforce_kill() {
  reason=$1
  log "ENFORCE reason=$reason coverage=$(coverage_text) tcp=$HEALTH_TCP http=$HEALTH_HTTP_CODES bypass=$BYPASS unverified=$CHAIN_UNVERIFIED audit_failed=$AUDIT_FAILED"
  if [ "$CUT_NETWORK" = 1 ]; then
    if [ ! -s "$TARGETS_FILE" ]; then
      log "cut-network skipped (no Claude-chain targets running)"
      CUT_NETWORK_DONE=1
    fi
  fi
  if [ "$CUT_NETWORK" = 1 ] && [ "${CUT_NETWORK_DONE:-0}" != 1 ]; then
    sim=0
    { [ -n "$SIMULATE" ] && [ "$ALLOW_SIM_KILL" != 1 ]; } && sim=1
    if [ "$DRY_RUN" = 1 ] || [ "$ENFORCE" != 1 ] || [ "$sim" = 1 ]; then
      log "would-cut-network device=$WIFI_DEVICE"
      [ -n "$SIMULATE" ] && say "would-cut-network device=$WIFI_DEVICE"
    else
      /usr/sbin/networksetup -setairportpower "$WIFI_DEVICE" off >>"$LOG_FILE" 2>&1 \
        && log "cut-network device=$WIFI_DEVICE" \
        || log "cut-network failed device=$WIFI_DEVICE"
    fi
  fi
  # gateway (the actual egress) first
  awk -F'\t' '$2=="gateway"' "$TARGETS_FILE" > "$KILL_LIST" 2>/dev/null || : > "$KILL_LIST"
  kill_list TERM "$KILL_LIST"
  sleep 1
  # everything else
  awk -F'\t' '$2!="gateway"' "$TARGETS_FILE" > "$KILL_LIST" 2>/dev/null || : > "$KILL_LIST"
  kill_list TERM "$KILL_LIST"
  sleep 2
  collect_targets "$TARGETS_FILE"
  if [ "$DRY_RUN" != 1 ] && [ "$ENFORCE" = 1 ] && { [ -z "$SIMULATE" ] || [ "$ALLOW_SIM_KILL" = 1 ]; }; then
    awk -F'\t' '$2=="gateway"' "$TARGETS_FILE" > "$KILL_LIST" 2>/dev/null || : > "$KILL_LIST"
    kill_list KILL "$KILL_LIST"
    awk -F'\t' '$2!="gateway" {print}' "$TARGETS_FILE" > "$KILL_LIST" 2>/dev/null || : > "$KILL_LIST"
    kill_list KILL "$KILL_LIST"
  fi
}

# ---------------------------------------------------------------- state
read_int() {
  local v
  v=$(cat "$1" 2>/dev/null)
  case "$v" in
    ''|*[!0-9]*) echo 0 ;;
    # 10# keeps "08"/"09" from being parsed as invalid octal and aborting the
    # tick; a corrupt counter must not disable enforcement.
    *) printf '%d\n' $((10#$v)) 2>/dev/null || echo 0 ;;
  esac
}

enforce_tick() {
  mkdir -p "$STATE_DIR" 2>/dev/null
  # Simulation is a test aid: run before the lock and before any state read or
  # write, show the full kill plan deterministically, never wait for the
  # threshold or grace, and never touch the real fail counter, wake or grace
  # state (otherwise a few sim runs could make the next real tick kill early).
  # kill_list only logs/says "would-send" here because --allow-sim-kill is off.
  if [ -n "$SIMULATE" ] && [ "$ALLOW_SIM_KILL" != 1 ]; then
    evaluate
    print_report
    log "simulate=$SIMULATE healthy=$HEALTHY coverage=$(coverage_text) tcp=$HEALTH_TCP http=$HEALTH_HTTP_CODES bypass=$BYPASS"
    if [ "$HEALTHY" = 1 ]; then
      say "kill plan: none (healthy under simulation)"
      exit 0
    fi
    enforce_kill "simulate-$SIMULATE"
    say "kill plan: simulated only; no process signalled"
    exit 0
  fi
  LOCK="$STATE_DIR/lock"
  LOCK_HELD=0
  if mkdir "$LOCK" 2>/dev/null; then
    LOCK_HELD=1
  elif [ -d "$LOCK" ]; then
    lpid=$(read_int "$LOCK/pid")
    # A missing/unreadable mtime means treat the lock as stale, not as fresh.
    lmt=$(stat -f %m "$LOCK" 2>/dev/null || echo 0)
    age=$(( $(now) - lmt ))
    if [ "$age" -gt 120 ] || { [ "$lpid" -gt 1 ] && ! kill -0 "$lpid" 2>/dev/null; }; then
      rm -rf "$LOCK"
      if mkdir "$LOCK" 2>/dev/null; then LOCK_HELD=1; else exit 0; fi
    else
      # A live holder (or a legacy lock inside the stale timeout).
      exit 0
    fi
  else
    # Could not create the lock (state dir missing/unwritable). Do not turn
    # that into a silent no-op: continue unlocked so enforcement still runs.
    log "lock unavailable ($LOCK); continuing without lock"
  fi
  # Only the process that actually holds the lock may remove it.
  [ "$LOCK_HELD" = 1 ] && printf '%s' "$$" > "$LOCK/pid" 2>/dev/null
  trap '[ "$LOCK_HELD" = 1 ] && rm -rf "$LOCK"; rm -f "$TARGETS_FILE" "$HITS_FILE" "$KILL_LIST" 2>/dev/null' EXIT

  # Sleep/wake or a long stall leaves the previous tick's fail count in place
  # and jumps straight to enforcement on the first tick after lid-open. Reset
  # the counter and grant a short wake grace when the gap is obvious. The
  # threshold is relative to INTERVAL so a documented --loop interval above
  # 60 s is not mistaken for a wake gap on every tick.
  nowts=$(now)
  last_run=$(read_int "$STATE_DIR/last_run")
  if [ "$last_run" -gt 0 ] && [ $((nowts - last_run)) -gt $(( ${INTERVAL:-10} + 50 )) ]; then
    log "gap $((nowts - last_run))s since last tick (sleep/wake); fail count reset, wake grace ${WAKE_GRACE}s"
    echo 0 > "$STATE_DIR/fail_count" 2>/dev/null
    printf '%s' "$nowts" > "$STATE_DIR/last_run" 2>/dev/null
    printf '%s' "$((nowts + WAKE_GRACE))" > "$STATE_DIR/wake_until" 2>/dev/null
    exit 0
  fi
  printf '%s' "$nowts" > "$STATE_DIR/last_run" 2>/dev/null

  # Record the first guard tick of this boot and keep it stable; grace is
  # measured from here, not from the state dir mtime.
  boot_id=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[ ,=]+' '{print $3}')
  [ -n "$boot_id" ] || boot_id=0
  if [ "$(cat "$STATE_DIR/boot_id" 2>/dev/null || echo '')" != "$boot_id" ]; then
    echo "$boot_id" > "$STATE_DIR/boot_id" 2>/dev/null
    now > "$STATE_DIR/started_this_boot" 2>/dev/null
    echo 0 > "$STATE_DIR/fail_count" 2>/dev/null
  fi
  started=$(read_int "$STATE_DIR/started_this_boot")
  # If the timestamp is missing/unreadable, treat grace as already over
  # (started=1). A future timestamp must not extend grace indefinitely either.
  [ "$started" -gt 0 ] 2>/dev/null || started=1
  [ "$started" -gt "$nowts" ] && started=1

  evaluate
  write_report_file
  # Refresh the IP profile only after the enforcement decision; the lookup
  # runs detached so it cannot delay this or the next tick.
  refresh_geo_if_stale

  if [ "$HEALTHY" = 1 ]; then
    echo 0 > "$STATE_DIR/fail_count" 2>/dev/null
    touch "$STATE_DIR/ever_ok" 2>/dev/null
    key="OK:$(coverage_text)"
    last_key=$(cat "$STATE_DIR/last_key" 2>/dev/null || echo "")
    last_ts=$(read_int "$STATE_DIR/last_ts")
    if [ "$key" != "$last_key" ] || [ $(( $(now) - last_ts )) -ge 600 ]; then
      log "healthy coverage=$(coverage_text) tcp=$HEALTH_TCP http=$HEALTH_HTTP_CODES targets=$([ -s "$TARGETS_FILE" ] && wc -l < "$TARGETS_FILE" | tr -d ' ' || echo 0)"
      printf '%s' "$key" > "$STATE_DIR/last_key"
      now > "$STATE_DIR/last_ts"
    fi
    exit 0
  fi

  fail=$(read_int "$STATE_DIR/fail_count")
  fail=$((fail + 1))
  echo "$fail" > "$STATE_DIR/fail_count"

  # A live direct connection (external socket or DIRECT rule) is evidence of a
  # bypass, not just "proxy not ready": kill immediately, even during startup
  # grace, so no request slips out before the grace window ends.
  if [ "$BYPASS" = 1 ] && [ "$BYPASS_KILL_IMMEDIATE" = 1 ]; then
    enforce_kill "bypass"
    exit 0
  fi

  wake_until=$(read_int "$STATE_DIR/wake_until")
  # A corrupt/future timestamp must not suppress enforcement indefinitely.
  if [ "$wake_until" -gt $(( $(now) + WAKE_GRACE )) ]; then
    wake_until=$(( $(now) + WAKE_GRACE ))
    printf '%s' "$wake_until" > "$STATE_DIR/wake_until" 2>/dev/null
  fi
  if [ "$wake_until" -gt 0 ] && [ "$(now)" -lt "$wake_until" ]; then
    log "wake grace ($((wake_until - $(now)))s left); coverage=$(coverage_text) tcp=$HEALTH_TCP http=$HEALTH_HTTP_CODES"
    exit 0
  fi

  if [ $(( $(now) - started )) -lt "$STARTUP_GRACE" ]; then
    log "startup grace ($(( $(now) - started ))s/${STARTUP_GRACE}s); coverage=$(coverage_text) tcp=$HEALTH_TCP http=$HEALTH_HTTP_CODES"
    exit 0
  fi

  key="BAD:$(coverage_text):tcp=$HEALTH_TCP:http=$HEALTH_HTTP_CODES:bypass=$BYPASS:unverified=$CHAIN_UNVERIFIED:audit_failed=$AUDIT_FAILED:fail=$fail"
  last_key=$(cat "$STATE_DIR/last_key" 2>/dev/null || echo "")
  last_ts=$(read_int "$STATE_DIR/last_ts")
  if [ "$key" != "$last_key" ] || [ $(( $(now) - last_ts )) -ge 60 ]; then
    log "unhealthy $key"
    printf '%s' "$key" > "$STATE_DIR/last_key"
    now > "$STATE_DIR/last_ts"
  fi

  if [ "$fail" -ge "$FAIL_THRESHOLD" ]; then
    enforce_kill "health-fail-$fail"
  fi
  exit 0
}

# ---------------------------------------------------------------- main
mkdir -p "$STATE_DIR" 2>/dev/null
# If the configured state dir is missing/unwritable (bad HOME under launchd,
# read-only volume, full disk), fail closed AND keep the machinery running:
# move temp/state files to a writable fallback. Otherwise every tick would
# silently collect no targets, never persist fail_count, and never enforce.
if [ ! -d "$STATE_DIR" ] || ! : > "$STATE_DIR/.write_test" 2>/dev/null; then
  _fb="${TMPDIR:-/tmp}/proxyguard-$(id -u)"
  mkdir -p "$_fb" 2>/dev/null
  STATE_DIR="$_fb"
  log "state dir not writable; using fallback $STATE_DIR"
else
  rm -f "$STATE_DIR/.write_test" 2>/dev/null
fi

TARGETS_FILE="$STATE_DIR/targets.$$"
HITS_FILE="$STATE_DIR/hits.$$"
KILL_LIST="$STATE_DIR/kill.$$"
trap 'rm -f "$TARGETS_FILE" "$HITS_FILE" "$KILL_LIST" 2>/dev/null' EXIT

case "$MODE" in
  state_dir)
    printf '%s\n' "$STATE_DIR"
    exit 0
    ;;
  check|status)
    evaluate
    if [ "$JSON_OUT" = 1 ]; then
      report_json
    else
      print_report
    fi
    [ "$MODE" = check ] && [ "$HEALTHY" != 1 ] && exit 1
    exit 0
    ;;
  once)
    enforce_tick
    ;;
  loop)
    while :; do
      if [ ${#LOOP_ARGS[@]} -gt 0 ]; then
        "${BASH:-/bin/bash}" "$SCRIPT_DIR/guard.sh" --once "${LOOP_ARGS[@]}"
      else
        "${BASH:-/bin/bash}" "$SCRIPT_DIR/guard.sh" --once
      fi
      sleep "$INTERVAL"
    done
    ;;
esac
