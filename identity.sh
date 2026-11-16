#!/bin/bash
# identity.sh — 给 Claude Code 装上「身份闸门」
#
# 目标：本机的时区 / 语言 / 地区 / 位置一律读不到；凡是能读到的时间与地区，
#       都必须和当前出口 IP 一致（geo.sh 写入的 geo.json 是唯一事实来源）。
#
# 用法:
#   identity.sh apply     写入 ~/.claude/settings.json（先备份，可回滚）
#   identity.sh verify    用同一份规则跑 seatbelt 对照实验（只读，不碰 Claude）
#   identity.sh status    打印闸门状态与剩余通道
#   identity.sh revert    从备份恢复
#
# 每条规则都在真机上逐项验证过；机制与残余通道见 docs/identity-gate.md。
# 关键约束（改了会静默失效）:
#   1. seatbelt 只认真实路径：/etc/localtime 必须写 /private/etc/localtime。
#   2. locale / 语言 / 键盘由 cfprefsd 的 XPC 提供，但**关掉它没用**：
#      真正生效的是对 ~/Library/Preferences 整个目录的读拒绝。注意这条只在
#      Claude 官方沙箱里成立——那份 profile 是 (deny default)，cfprefsd
#      不在 mach 白名单里，defaults 只好直接读文件。换成 (allow default)
#      的测试骨架，cfprefsd 会把值端上来，目录 deny 看着就「无效」了。
#      单独封 .GlobalPreferences*.plist 之类的单文件同样无效。
#   3. iokit / sysctl / mach-lookup 规则**无法**从 settings.json 注入——
#      sandbox.filesystem.denyRead 只能表达文件路径。序列号、机型名、MAC、
#      hostname 因此保持可读，属于已知残余通道（见文档 §4）。
#   4. 时区数据库（zoneinfo）是静态世界库，读某个条目并不能反推本机时区；
#      封大洲只会让 TZ=Asia/Shanghai 静默变 UTC、python zoneinfo 报错，
#      所以不封。真正要封的是 /etc/localtime 这个指向本机时区的链接。
#   5. TZ 未注入时，闸门内一切时间退化成 UTC（这是「时区被藏起来」的必然
#      结果，也是可被观察到的矛盾）；geo.sh 的 env.TZ + launchctl setenv
#      负责让这个矛盾不出现。
#   6. sandbox.network.httpProxyPort 只决定沙箱流量走哪个代理，不限制出口；
#      真正锁死出口的是 Clash 的 TUN。
set -u

DEST_DIR="$(cd "$(dirname "$0")" && pwd)"
SETTINGS="$HOME/.claude/settings.json"
BACKUP="$SETTINGS.proxyguard.bak"
CONFIG="${PROXYGUARD_CONFIG:-$DEST_DIR/config.env}"
STATE_DIR="${STATE_DIR:-$HOME/.cache/proxyguard}"
GEO_FILE="$STATE_DIR/geo.json"
MODE="${1:-status}"

PROXY_HOST=127.0.0.1
PROXY_PORT=7897
if [ -f "$CONFIG" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG" >/dev/null 2>&1 || true
fi

say()  { printf 'identity: %s\n' "$*"; }
die()  { printf 'identity: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "需要 $1"; }
need jq

ip_tz() {
  [ -f "$GEO_FILE" ] || return 1
  jq -r '.timezone // empty' "$GEO_FILE" 2>/dev/null
}

# denyRead 清单：seatbelt 判定的真实路径。
# 这里只放「文件型」通道——iokit / sysctl / XPC 无法用 denyRead 表达，
# 也就无法从 settings.json 注入。
deny_paths() {
  cat <<'EOF'
/private/etc/localtime
/Library/Preferences/.GlobalPreferences.plist
/Library/Preferences/com.apple.keyboardtype.plist
/Library/Preferences/com.apple.HIToolbox.plist
/Library/Preferences/com.apple.Keyboard-Settings.extension.plist
/Library/Preferences/com.apple.keyboard.preferences.plist
/Library/Preferences/com.apple.keyboardservicesd.plist
/Library/Preferences/com.apple.menuextra.clock.plist
/private/var/db/locationd
/private/var/log/wifi.log
/private/var/db/.AppleSetupDone
EOF
  cat <<EOF
$HOME/Library/Preferences
$HOME/Library/Containers/com.apple.weather
$HOME/Library/Containers/com.apple.Maps
$HOME/Library/Caches/com.apple.locationd
$HOME/Library/Caches/com.apple.geod
$HOME/Library/Application Support/AddressBook
$HOME/Library/Application Support/CallHistoryDB
$HOME/Library/Application Support/com.apple.sharedfilelist
$HOME/Library/Messages
$HOME/Library/Mail
$HOME/Library/Calendars
$HOME/Library/Safari
$HOME/Library/Keychains
$HOME/Library/IdentityServices
$HOME/.CFUserTextEncoding
$HOME/.netrc
EOF
}

# Read/Grep/Glob 工具绕过 Bash 沙箱（官方文档明说），必须再写一遍权限规则，
# 否则 Claude 用内置 Read 就能把沙箱挡住的东西读回来。
read_deny_rules() {
  cat <<'EOF'
Read(//etc/localtime)
Read(//private/etc/localtime)
Read(//private/var/db/timezone/**)
Read(//private/var/db/locationd/**)
Read(//private/var/log/wifi.log)
Read(//private/var/db/.AppleSetupDone)
Read(//Library/Preferences/.GlobalPreferences.plist)
Read(//Library/Preferences/com.apple.keyboardtype.plist)
Read(//Library/Preferences/com.apple.HIToolbox.plist)
Read(//Library/Preferences/com.apple.keyboard.preferences.plist)
Read(//Library/Preferences/com.apple.keyboardservicesd.plist)
Read(//Library/Preferences/com.apple.menuextra.clock.plist)
EOF
  cat <<EOF
Read(~/Library/Preferences/**)
Read(~/Library/Containers/com.apple.weather/**)
Read(~/Library/Containers/com.apple.Maps/**)
Read(~/Library/Caches/com.apple.locationd/**)
Read(~/Library/Caches/com.apple.geod/**)
Read(~/Library/Application Support/AddressBook/**)
Read(~/Library/Application Support/CallHistoryDB/**)
Read(~/Library/Application Support/com.apple.sharedfilelist/**)
Read(~/Library/Messages/**)
Read(~/Library/Mail/**)
Read(~/Library/Calendars/**)
Read(~/Library/Safari/**)
Read(~/Library/Keychains/**)
Read(~/Library/IdentityServices/**)
Read(~/.CFUserTextEncoding)
Read(~/.netrc)
EOF
}

# iokit / sysctl 这些通道 denyRead 表达不了，只能靠「对话内」的 Bash 规则挡一层。
# 这一层不是内核边界：脚本里直接调 ioreg 仍然能绕过，见文档「残余通道」。
bash_deny_rules() {
  cat <<'EOF'
Bash(ioreg:*)
Bash(system_profiler:*)
Bash(networksetup:*)
Bash(scutil:*)
Bash(dscl:*)
Bash(ipconfig:*)
Bash(airport:*)
Bash(hostname:*)
Bash(uname -n:*)
Bash(ifconfig:*)
EOF
}

# denyRead 生成的那一段：与 Claude Code 的 Dj() 一样，先 (allow file-read*)，
# 再逐条 deny。这是 apply 能表达的全部规则——别再往里加 iokit/sysctl，
# 那些规则 Claude Code 不会从 settings.json 读，加了只会让 verify 说谎。
seatbelt_rules() {
  local p
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    # 目录必须用 subpath，否则只挡住这个目录本身、拦不住里面的文件
    if [ -d "$p" ]; then
      printf '(deny file-read* (subpath "%s"))\n' "$p"
    else
      printf '(deny file-read* (literal "%s"))\n' "$p"
    fi
  done < <(deny_paths)
}

# verify 用的骨架：按 Claude Code 2.1.325 的 Lj() 重建（deny default + 白名单）。
# **不能用 (allow default) 打底**：那样 cfprefsd 的 XPC 是通的，defaults 会从
# cfprefsd 而不是文件拿值，目录 deny 会被绕过，verify 就会谎报「闸门没关上」。
claude_profile() {
  cat <<'EOF'
(version 1)
(deny default (with message "identity-verify"))
(allow process-exec)
(allow process-fork)
(deny process-info* (with message "identity-verify"))
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))
(allow user-preference-read)
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.distributed_notifications@Uv3")
  (global-name "com.apple.FontObjectsServer")
  (global-name "com.apple.fonts")
  (global-name "com.apple.logd")
  (global-name "com.apple.lsd.mapdb")
  (global-name "com.apple.PowerManagement.control")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.coreservices.launchservicesd"))
(allow ipc-posix-shm)
(allow ipc-posix-sem)
(allow iokit-open
  (iokit-registry-entry-class "IOSurfaceRootUserClient")
  (iokit-registry-entry-class "RootDomainUserClient")
  (iokit-user-client-class "IOSurfaceSendRight"))
(allow iokit-get-properties)
(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))
(allow sysctl-read
  (sysctl-name "hw.activecpu") (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cachelinesize_compat") (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cputype") (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max") (sysctl-name "hw.machine")
  (sysctl-name "hw.memsize") (sysctl-name "hw.ncpu") (sysctl-name "hw.packages")
  (sysctl-name "hw.pagesize") (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max") (sysctl-name "hw.vectorunit")
  (sysctl-name "kern.argmax") (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfiles") (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc") (sysctl-name "kern.ngroups")
  (sysctl-name "kern.osproductversion") (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype") (sysctl-name "kern.osversion") (sysctl-name "kern.version")
  (sysctl-name "machdep.cpu.brand_string") (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel")
  (sysctl-name-prefix "kern.proc.all")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "machdep.cpu.")
  (sysctl-name-prefix "net.routetable.")
  (sysctl-name-prefix "kern.procargs"))
(allow distributed-notification-post)
(allow file-ioctl file-read-data file-write-data (require-all (literal "/dev/null") (vnode-type CHARACTER-DEVICE)))
(allow file-ioctl (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/tty"))
(allow pseudo-tty)
(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))
;; trustd.agent：apply 会把它写进 sandbox.network.allowMachLookup
(allow mach-lookup (global-name "com.apple.trustd.agent"))
(allow file-read*)
(allow file-read-metadata (vnode-type DIRECTORY))
(allow file-write* (subpath "/private/tmp") (subpath "/private/var/folders") (literal "/dev/null"))
(allow network*)
(allow system-socket (socket-domain AF_UNIX))
EOF
}

apply() {
  local tz; tz=$(ip_tz) || die "读不到出口 IP 时区（$GEO_FILE）；先让 geo.sh 跑一次，闸门拒绝在未知时区下启用"
  [ -n "$tz" ] || die "geo.json 没有 timezone 字段"
  case "$tz" in
    *[!A-Za-z0-9_/+-]*) die "geo.json 的 timezone 不可信: $tz" ;;
    /*|*..*|*/)         die "geo.json 的 timezone 不可信: $tz" ;;
  esac
  case "$tz" in
    */*) ;;
    *) die "geo.json 的 timezone 缺少大洲前缀: $tz" ;;
  esac
  [ -f "$SETTINGS" ] || die "找不到 $SETTINGS"
  [ -f "$BACKUP" ] || cp -p "$SETTINGS" "$BACKUP" || die "备份失败"

  local deny_json read_json bash_json
  deny_json=$(deny_paths      | jq -R . | jq -s 'map(select(length>0))')
  read_json=$(read_deny_rules | jq -R . | jq -s 'map(select(length>0))')
  bash_json=$(bash_deny_rules | jq -R . | jq -s 'map(select(length>0))')

  # httpProxyPort 只决定沙箱流量走哪个代理（让出口与 IP 一致），
  # 不构成网络隔离——隔离来自 Clash 的 TUN。
  # allowMachLookup 里的 trustd.agent 是 Go CLI（gh / gcloud / kubectl / terraform）
  # 校验证书用的：Claude 的 mach 白名单没有它，Go 程序一律 x509 OSStatus -26276。
  # 这个键对用户 settings 生效（高权限键，只被 project/local settings 限制）。
  local proxy_json='{}'
  if [ "$PROXY_HOST" = "127.0.0.1" ] && [ -n "$PROXY_PORT" ]; then
    proxy_json=$(jq -n --argjson p "$PROXY_PORT" \
      '{httpProxyPort:$p, allowMachLookup:["com.apple.trustd.agent"]}')
  fi

  local tmp="$SETTINGS.identity.$$"
  if ! jq --argjson deny "$deny_json" --argjson rd "$read_json" \
          --argjson bd "$bash_json" --argjson px "$proxy_json" --arg tz "$tz" '
      .env = (.env // {})
      | .env.TZ     = $tz
      | .env.LANG   = "en_US.UTF-8"
      | .env.LC_ALL = "en_US.UTF-8"
      | .sandbox = (.sandbox // {})
      | .sandbox.enabled = true
      | .sandbox.failIfUnavailable = true
      | .sandbox.allowUnsandboxedCommands = false
      | .sandbox.autoAllowBashIfSandboxed = false
      | .sandbox.filesystem = (.sandbox.filesystem // {})
      | .sandbox.filesystem.denyRead = (((.sandbox.filesystem.denyRead // []) + $deny) | unique)
      | .sandbox.network = ((.sandbox.network // {}) + $px + {allowLocalBinding:true})
      | .permissions = (.permissions // {})
      | .permissions.blockReadsOutsideWorkingDirectories = true
      | .permissions.deny = (((.permissions.deny // []) + $rd + $bd) | unique)
    ' "$SETTINGS" > "$tmp"; then
    rm -f "$tmp"; die "写入失败（jq 退出非零）"
  fi
  chmod 600 "$tmp" && mv -f "$tmp" "$SETTINGS" || { rm -f "$tmp"; die "替换失败"; }

  say "已启用：IP 时区 $tz；sandbox denyRead $(printf '%s' "$deny_json" | jq length) 条；权限 deny $(printf '%s' "$read_json$bash_json" | jq -s 'add|length') 条"
  say "备份：$BACKUP"
  say "重启 Claude Code / Claude Desktop 后完整生效"
  say "残余通道：序列号 / 机型名 / MAC / hostname 仍可读（settings.json 注入不了 iokit 与 sysctl 规则）"
}

verify() {
  need sandbox-exec
  need python3
  local tz; tz=$(ip_tz) || tz="America/Los_Angeles"
  VERIFY_PROF=$(mktemp "${TMPDIR:-/tmp}/identity-verify.XXXXXX") || die "mktemp 失败"
  trap 'rm -f "${VERIFY_PROF:-}"' EXIT
  { claude_profile; echo ';; --- identity gate (from settings.json denyRead) ---'; seatbelt_rules; } > "$VERIFY_PROF"

  # 两列都用同一份 Claude 沙箱骨架：闸门外 = 官方默认，闸门内 = 加上 apply 的
  # denyRead。这样这一列差值就是 apply 真正带来的变化。
  # 闸门内必须带上 TZ（settings.json 的 env.TZ 就是这样注入的），否则读不到
  # 本机时区后会退化成 UTC——那是「藏起来」的代价，不是缺陷。
  local base_prof="$VERIFY_PROF.base"
  claude_profile > "$base_prof"

  printf '%-24s %-22s %s\n' "通道" "Claude 沙箱" "沙箱 + apply"
  printf '%-24s %-22s %s\n' "----------------------" "--------------------" "--------------------"
  local row label cmd base gate
  while IFS='|' read -r label cmd; do
    [ -n "$label" ] || continue
    base=$(env -i HOME="$HOME" PATH="$PATH" TZ="$tz" sandbox-exec -f "$base_prof" /bin/sh -c "$cmd" 2>&1 | head -1 | tr '\t' ' ')
    gate=$(env -i HOME="$HOME" PATH="$PATH" TZ="$tz" sandbox-exec -f "$VERIFY_PROF" /bin/sh -c "$cmd" 2>&1 | head -1 | tr '\t' ' ')
    printf '%-24s %-22s %s\n' "$label" "$(cut -c1-22 <<<"${base:-—}")" "$(cut -c1-34 <<<"${gate:-—}")"
  done <<'CHECKS'
TZ 显示|date "+%Z %z"
系统时区链接|readlink /etc/localtime || echo 空
读 localtime|cat /etc/localtime >/dev/null 2>&1 && echo 可读 || echo 拒绝
AppleLocale|defaults read -g AppleLocale 2>&1 | tail -1
系统语言|defaults read -g AppleLanguages 2>&1 | tail -1
键盘/输入法|defaults read com.apple.HIToolbox 2>&1 | tail -1
定位客户端库|plutil -p /var/db/locationd/clients.plist >/dev/null 2>&1 && echo 可读 || echo 拒绝
Wi-Fi 日志|cat /var/log/wifi.log >/dev/null 2>&1 && echo 可读 || echo 拒绝
Wi-Fi 优选网络|networksetup -listpreferredwirelessnetworks en0 2>&1 | sed -n 2p
机型 hw.model|sysctl -n hw.model 2>&1
序列号 ioreg|ioreg -l 2>/dev/null | grep -c IOPlatformSerialNumber
MAC 地址数|ifconfig 2>/dev/null | grep -c ether
电脑名|scutil --get ComputerName 2>&1
CHECKS
  rm -f "$base_prof"
  echo
  echo "闸门内 TZ 应等于 IP 时区（$tz）；文件型通道应为空 / 拒绝。"
  echo "序列号 / 机型名 / MAC / 电脑名 是已知残余通道：它们走 iokit 与 sysctl，"
  echo "settings.json 没有注入这两类规则的入口（权限规则里的 Bash(...) 只在对话内挡一层）。"
  echo "闸门内若不注入 TZ，date 会退化成 UTC——这是本机时区已被藏起来的证据。"
}

# 取值时不能用 `// "unset"`：jq 的 // 把 false 也当空值，会把「显式关掉」
# 显示成「没设置」——而 allowUnsandboxedCommands=false 正是闸门的关键一项。
settings_get() {
  jq -r --arg p "$1" '
    reduce ($p | split(".")[]) as $k (.;
      if type == "object" and has($k) then .[$k] else null end)
    | if . == null then "unset" else tostring end
  ' "$SETTINGS" 2>/dev/null || echo unset
}

status() {
  [ -f "$SETTINGS" ] || die "找不到 $SETTINGS"
  printf '%-26s %s\n' "沙箱" "$(settings_get sandbox.enabled)"
  printf '%-26s %s\n' "denyRead 条数" "$(jq -r '.sandbox.filesystem.denyRead // [] | length' "$SETTINGS")"
  printf '%-26s %s\n' "Read 工具 deny 条数" "$(jq -r '[.permissions.deny // [] | .[] | select(startswith("Read("))] | length' "$SETTINGS")"
  printf '%-26s %s\n' "Bash 行为规则条数" "$(jq -r '[.permissions.deny // [] | .[] | select(startswith("Bash("))] | length' "$SETTINGS")"
  printf '%-26s %s\n' "沙箱出口代理端口" "$(jq -r '.sandbox.network.httpProxyPort // "unset"' "$SETTINGS")"
  printf '%-26s %s\n' "failIfUnavailable" "$(settings_get sandbox.failIfUnavailable)"
  printf '%-26s %s\n' "allowUnsandboxedCommands" "$(settings_get sandbox.allowUnsandboxedCommands)"
  printf '%-26s %s\n' "blockReadsOutsideCWD" "$(settings_get permissions.blockReadsOutsideWorkingDirectories)"
  printf '%-26s %s\n' "env.TZ" "$(jq -r '.env.TZ // "unset"' "$SETTINGS")"
  printf '%-26s %s\n' "env.LANG" "$(jq -r '.env.LANG // "unset"' "$SETTINGS")"
  printf '%-26s %s\n' "trustd.agent (allowMachLookup)" \
    "$(jq -r 'if ((.sandbox.network.allowMachLookup // []) | index("com.apple.trustd.agent")) then "已加入" else "未加入" end' "$SETTINGS")"
  printf '%-26s %s\n' "出口 IP 时区(geo.json)" "$(ip_tz || echo '读不到')"
  command -v claude >/dev/null 2>&1 && \
    printf '%-26s %s\n' "claude sandbox status" "$(claude sandbox status 2>/dev/null | jq -c '{supported,enabled,strictMode}' 2>/dev/null || echo 不可用)"
  echo
  echo "残余通道（settings.json 注入不了 iokit / sysctl 规则）："
  echo "  序列号、机型名、MAC（ifconfig）、hostname 仍可读；"
  echo "  permissions.deny 里的 Bash(ioreg:*) 等规则只在对话内挡一层，脚本可绕过。"
}

revert() {
  [ -f "$BACKUP" ] || die "没有备份 $BACKUP"
  local tmp="$SETTINGS.identity.$$"
  cp -p "$BACKUP" "$tmp" && mv -f "$tmp" "$SETTINGS" || die "恢复失败"
  say "已从 $BACKUP 恢复（重启 Claude Code 生效）"
}

case "$MODE" in
  apply)   apply ;;
  verify)  verify ;;
  status)  status ;;
  revert)  revert ;;
  *)       die "用法: $0 {apply|verify|status|revert}" ;;
esac
