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
#      但「本机用哪个时区 / 哪套语言」这一类**文件型**证据是能封干净的：
#      /Library/Preferences 整目录、~/.cache/proxyguard（geo.json 的
#      system_tz 直接写着真实时区）、~/.claude.json 与 ~/.claude/projects
#      （Claude 自己的 machineID 与全部历史对话）、~/.ssh 私钥、~/.gnupg。
#      封 ~/.ssh/id_* 的代价是沙箱内 git-over-SSH 失效（HTTPS+token 不受影响）。
#      ~/Library/Containers 也要整目录封：`defaults domains` 剩下的 140 个
#      偏好域名**全部**来自这里（实测逐个排除：封 Group Containers / Application
#      Support 都不动，只有封 Containers 才归零），而且里面就是 DingTalk、
#      WeWork 这类第三方 App 的全部本地数据。
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
MODE="${1:-status}"

PROXY_HOST=127.0.0.1
PROXY_PORT=7897
if [ -f "$CONFIG" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG" >/dev/null 2>&1 || true
fi

# STATE_DIR 必须在 source config.env **之后**求值：config.env 是文档里公开可改的
# （README §五），geo.sh / guard.sh 也都先 source 再算路径。早求值会让本脚本去读
# 默认目录的 geo.json，而 geo.sh 写的是自定义目录——闸门于是可能按一个过期的
# 时区启用，那正是闸门要防的「时钟与出口不一致」。
STATE_DIR="${STATE_DIR:-$HOME/.cache/proxyguard}"
GEO_FILE="$STATE_DIR/geo.json"

say()  { printf 'identity: %s\n' "$*"; }
die()  { printf 'identity: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "需要 $1"; }
need jq

# 跟随符号链接链，返回最终的真实文件路径。dotfiles 仓库里很常见
# `~/.claude/settings.json -> ~/dotfiles/claude/settings.json`；用 mv 覆盖这个路径
# 会把**链接本身**换成普通文件，dotfiles 里的源文件永远拿不到闸门，下次重链时
# 闸门就静默丢了。geo.sh 同样跟随（geo.sh 的 settings_target 循环）。
# 用 while 而不是 readlink -f：macOS 的 readlink 没有 -f。
resolve_symlinks() {
  local p=$1 link
  local hops=0
  while [ -L "$p" ]; do
    hops=$((hops+1))
    [ "$hops" -le 40 ] || return 1
    link=$(readlink "$p" 2>/dev/null) || return 1
    [ -n "$link" ] || return 1
    case "$link" in
      /*) p=$link ;;
      *)  p=$(dirname "$p")/$link ;;
    esac
  done
  printf '%s\n' "$p"
}

ip_tz() {
  [ -f "$GEO_FILE" ] || return 1
  jq -r '.timezone // empty' "$GEO_FILE" 2>/dev/null
}

# geo.json 里的时区必须同时满足两件事：字符集干净（挡住把引号/括号塞进
# settings.json 或 seatbelt 的表达），且**真的存在于 zoneinfo**。
# 早期版本只查「必须带大洲前缀」，结果两头都错：UTC / Japan / Hongkong / GB
# 这些 geo.sh 认可、zoneinfo 里真实存在的名字被拒；而 "Foo/Bar" 这种不存在的
# 名字被接受，TZ=Foo/Bar 静默退化成 UTC——正是闸门要防的「时钟与出口不一致」。
valid_tz() {
  local t=$1
  case "$t" in
    ''|/*|*/|*..*) return 1 ;;
    *[!A-Za-z0-9_/+-]*) return 1 ;;
  esac
  [ -f "/usr/share/zoneinfo/$t" ]
}

# denyRead 清单：seatbelt 判定的真实路径。
# 这里只放「文件型」通道——iokit / sysctl / XPC 无法用 denyRead 表达，
# 也就无法从 settings.json 注入。
#
# /Library/Preferences 用**整目录**而不是逐个 plist：实测单独封
# .GlobalPreferences.plist 只挡住 plutil，`defaults read` 照旧从 cfprefsd 拿到
# CN；而 SystemConfiguration/preferences.plist（ComputerName）、
# com.apple.bluetooth.plist（配对耳机 MAC + 名字）、com.apple.timezone.auto.plist
# 也都在这个目录里，逐个列举必然漏。整目录一条覆盖全部。
#
# ~/Library/Containers 同理整目录：`defaults domains` 在只封了 Preferences 之后
# 仍有 140 条，来源就是这里（实测封 Group Containers / Application Support /
# Saved Application State 都不减少，只有封 Containers 才归零）。
#
# ⚠️ 路径不要带通配符：seatbelt 的 literal/subpath 都不展开 glob，这里按真实路径
# 写死。轮转日志要在 read_deny_rules() 和 verify 里单独用 glob 处理。
deny_paths() {
  cat <<'EOF'
/private/etc/localtime
/Library/Preferences
/private/var/db/locationd
/private/var/log/wifi.log
/private/var/db/.AppleSetupDone
EOF
  cat <<EOF
$HOME/Library/Preferences
$HOME/Library/Containers
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
$HOME/.cache/proxyguard
$HOME/.gnupg
$HOME/.ssh/id_rsa
$HOME/.ssh/id_ed25519
$HOME/.docker/config.json
$HOME/.claude.json
$HOME/.claude/projects
$HOME/.claude/sessions
$HOME/.claude/history.jsonl
$HOME/.claude/debug
$HOME/.claude/keysmith
$HOME/.claude/daemon
$HOME/.claude/file-history
EOF
}

# Read/Grep/Glob 工具绕过 Bash 沙箱（官方文档明说），必须再写一遍权限规则，
# 否则 Claude 用内置 Read 就能把沙箱挡住的东西读回来。
#
# **这里的清单必须和 deny_paths() 逐条对应**，因为 Claude Code 的 sandbox 配置
# 构建器会把 permissions.deny 里的每条 Read(...) 折进**同一份** denyRead
# （2.1.325 的 `zT(de?.permissions?.deny,[dt,Be])` → `case"read": Ct.push(yn)`），
# 这里多写一条，Bash 沙箱就多封一条。
#
# 早先这里多写了 `Read(//private/var/db/timezone/**)`，而 zoneinfo 是 TZ 注入的
# 唯一来源：实测那条一加，闸门内 `TZ=America/Los_Angeles date` 从 `PST -0800`
# 变成 `UTC +0000`、python `ZoneInfo()` 直接抛 ZoneInfoNotFoundError——闸门赖以
# 成立的「时间与出口 IP 一致」被自己的 Read 规则打掉了。已删除，别再写回去。
read_deny_rules() {
  local p
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    # 目录要带 /**：Read() 是路径模式匹配，`Read(~/Library/Preferences)` 只挡住
    # 目录本身。denyRead 那边无所谓——Sy() 会把尾部 /** 剥掉
    # （`function Sy(e){return e.replace(/\/\*\*$/,"")||"/"}`），所以两种写法
    # 在 Bash 沙箱里等价，Read 工具侧则需要 / ** 才覆盖内容。
    [ -d "$p" ] && p="$p/**"
    case "$p" in
      "$HOME"/*) printf 'Read(~%s)\n' "${p#"$HOME"}" ;;
      /*)        printf 'Read(/%s)\n' "$p" ;;
    esac
  done < <(deny_paths)
}

# 撤销专用的「可能形态全集」：apply 写进去的是当时 `[ -d ]` 的形态，而 revert
# 往往发生在目录已被删掉之后（比如 ~/.cache/proxyguard 被清理）。届时
# read_deny_rules 只会产出不带 /** 的形态，减不掉当初写的 `Read(~/.../** )`，
# 于是闸门留下一条永远减不掉的残留规则。这里对每条路径两种形态都发，只用于
# **减法**，不影响 apply 写进去的内容。
read_deny_rules_all() {
  local p base
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    base=${p%/}
    for p in "$base" "$base/**"; do
      case "$p" in
        "$HOME"/*) printf 'Read(~%s)\n' "${p#"$HOME"}" ;;
        /*)        printf 'Read(/%s)\n' "$p" ;;
      esac
    done
  done < <(deny_paths)
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

# denyRead 生成的那一段。剖面里 (deny file-read*) 由 Dj() 发出，顺序是：
#   (allow file-read*)                      ← 先全开
#   (deny file-read* …)  ← 你写的 denyRead   ← 再逐条关
#   (allow file-read* …) ← allowWithinDeny   ← 最后按 filesystem.allowRead 重开
#   (allow file-read-metadata (vnode-type DIRECTORY))  ← 仅当 denyRead 非空
# seatbelt 是「后 match 者胜」，所以结尾那组 allow 会不会把闸门重新打开，
# 全看 allowWithinDeny 装了什么。2.1.325 的实测答案：
#   · 普通 Bash 走 vY()→DPo({readConfig})，allowWithinDeny 只来自
#     settings 的 filesystem.allowRead（ky("allow", …)）；我们不写 allowRead，
#     于是它是空数组，Dj() 不发出任何 allow，**deny 胜**。
#   · 只有 ftn()/mtn() 那条「项目 hook 沙箱」把硬编码的 epr（含 /etc/localtime、
#     /var/db/timezone）塞进 allowRead，会重开 localtime。而它跟本闸门不共存：
#     HQe() 里 Jfr() 一旦看到 blockReadsOutsideWorkingDirectories 或任何
#     denyRead/Read deny，就返回 unavailable:"person_read_rules"，
#     项目 hook 干脆**不加沙箱**——所以 epr 永远轮不到生效。
# 也就是说：这里只该有路径 deny。别再往里加 iokit/sysctl 规则，Claude Code 不会
# 从 settings.json 读它们，加了只会让 verify 说谎。

# 单条路径 → 一条 SBPL deny，**与 2.1.325 的 Xa() 完全一致**：
#   function Xa(e){ return e.glob ? `(regex ${…})` : `(subpath ${…})` }
# 生产里 **从不发 (literal …)**。早先按 [ -d ] 决定 literal/subpath 是错的：
# 那让 verify 在「目录还不存在」或「路径是文件」时比生产更严/更松，测的不是生产。
sbpl_deny() {
  case "$1" in
    /private/var/log/wifi.log)
      # 唯一需要覆盖整族的条目。生产里 Dj() 把含 * ? [ ] 的条目判为 glob 并发
      # (regex …)（bc() → Xa()），这里手写等价正则，一次封掉 live + 全部轮转。
      # （deny_paths() 里不放通配符：seatbelt 不展开 glob，且会凭空多出规则。）
      printf '(deny file-read* (regex #"^/private/var/log/wifi\\.log($|\\.[0-9]+\\.bz2$)"))\n' ;;
    *)
      # 与 2.1.325 的 Xa() 一致：非 glob 一律 (subpath …)，生产里从不发 (literal …)。
      printf '(deny file-read* (subpath "%s"))\n' "$1" ;;
  esac
}

seatbelt_rules() {
  local p n=0
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    n=$((n+1))
    sbpl_deny "$p"
  done < <(deny_paths)
  # 与 Dj() 一致：denyRead 非空时，**在 deny 之后**再放开「目录自身元数据」。
  # 这是 Claude 官方沙箱本来就有的行为，不是闸门的漏洞——它让 ls/stat 目录能过，
  # 但里面的文件仍被 deny 挡住。verify 必须原样复现，否则测的不是生产。
  [ "$n" -gt 0 ] && printf '(allow file-read-metadata (vnode-type DIRECTORY))\n'
  return 0
}

# permissions.deny 里的每条 Read(...) 也会被折进**同一份** denyRead
# （`case"read": Ct.push(yn)`），也就是 Read 规则会额外收紧 Bash 沙箱。
# 所以 verify 的「沙箱 + apply」列必须把这一组也发出来，否则测的只是
# filesystem.denyRead 那一半，而生产是两半的并集。
# 早先 verify 只发 deny_paths()，于是那条 `Read(//private/var/db/timezone/**)`
# 在真实 apply 后把 zoneinfo 封了、TZ 静默变 UTC，verify 却仍然全绿。
read_rule_rules() {
  local r p
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    # Read(//abs/path) → /abs/path ；Read(~/rel) → $HOME/rel
    p=${r#Read(}
    p=${p%\)}
    p=${p#\(}
    # 与 Sy() 一致：`function Sy(e){return e.replace(/\/\*\*$/,"")||"/"}`。
    # Read() 侧的 `/**` 在折进 denyRead 时会被剥掉，否则会变成
    # (subpath "…/**")——那是字面星号，一个文件都匹配不到。
    p=${p%'/**'}
    [ -n "$p" ] || p="/"
    case "$p" in
      //*) p=${p#/} ;;          # //private/x → /private/x（去掉一个 /）
      '~/'*) p="$HOME/${p#'~/'}" ;;
    esac
    sbpl_deny "$p"
  done < <(read_deny_rules)
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
(if (defined? 'process-info-listpids) (allow process-info-listpids))
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
;; sysctl 白名单必须与二进制里的 49 项**逐字一致**。少一项的代价不是「读不到」，
;; 而是 Go/LLVM 直接崩：实测漏掉 hw.cacheconfig / hw.pagesize_compat 等 21 项后，
;; gh 报 "failed to get system page size"、node/npm 报 LowLevelAlloc arithmetic
;; overflow、docker 同样崩。这一列是 2.1.325 里 Lj() 的原文顺序。
(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.busfrequency_compat")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cacheconfig")
  (sysctl-name "hw.cachelinesize_compat")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cpufrequency")
  (sysctl-name "hw.cpufrequency_compat")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.l1dcachesize_compat")
  (sysctl-name "hw.l1icachesize_compat")
  (sysctl-name "hw.l2cachesize_compat")
  (sysctl-name "hw.l3cachesize_compat")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.nperflevels")
  (sysctl-name "hw.packages")
  (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "hw.tbfrequency_compat")
  (sysctl-name "hw.vectorunit")
  (sysctl-name "kern.argmax")
  (sysctl-name "kern.bootargs")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfiles")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc")
  (sysctl-name "kern.ngroups")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel")
  (sysctl-name "kern.tcsm_available")
  (sysctl-name "kern.tcsm_enable")
  (sysctl-name "kern.usrstack64")
  (sysctl-name "kern.version")
  (sysctl-name "kern.willshutdown")
  (sysctl-name "machdep.cpu.brand_string")
  (sysctl-name "machdep.ptrauth_enabled")
  (sysctl-name "security.mac.lockdown_mode_state")
  (sysctl-name "sysctl.proc_cputype")
  (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm")
  (sysctl-name-prefix "hw.optional.arm.")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel")
  (sysctl-name-prefix "kern.proc.all")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "machdep.cpu.")
  (sysctl-name-prefix "net.routetable."))
;; Lj() 在这里**先关掉** allow sysctl-read，再单独发一条 deny：
;;   lo("deny",["sysctl-read"],new Set(['(sysctl-name-prefix "kern.procargs")']),Y)
;; procargs 若能读，就能拿别的进程的 KERN_PROCARGS2（argv）。早先把它写在上面
;; 那条 allow 的括号里，等于把 deny 吃掉，verify 会谎报「argv 可读」。
(deny sysctl-read
  (sysctl-name-prefix "kern.procargs"))
;; V8 thread calculations 要写 sysctl。**必须带 (sysctl-name …) 限定**：
;; 裸写 (allow sysctl-write) 会把 sysctl-read 一起放开（seatbelt 里 write 蕴含
;; read），于是 hw.model / kern.hostname / machdep.cpu.brand_string / kern.boottime
;; 全部可读——这正是早先 verify 误报「hw.model 两列都是 Mac16,12」的原因。
;; 二进制 2.1.325 的原文就是限定到 kern.tcsm_enable 一条。
(allow sysctl-write
  (sysctl-name "kern.tcsm_enable"))
(allow distributed-notification-post)
;; keychain 相关服务。securityd.xpc 在上面那条 mach 白名单里，SecurityServer 是另一条。
(allow mach-lookup (global-name "com.apple.SecurityServer"))
;; File I/O on device files
(allow file-ioctl (literal "/dev/null"))
(allow file-ioctl (literal "/dev/zero"))
(allow file-ioctl (literal "/dev/random"))
(allow file-ioctl (literal "/dev/urandom"))
(allow file-ioctl (literal "/dev/dtracehelper"))
(allow file-ioctl (literal "/dev/tty"))
(allow pseudo-tty)
(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))
;; trustd.agent：apply 会把它写进 sandbox.network.allowMachLookup
(allow mach-lookup (global-name "com.apple.trustd.agent"))
(allow file-read*)
;; 注意：Dj() 只在 denyRead 非空时才追加
;;   (allow file-read-metadata (vnode-type DIRECTORY))
;; 而且它排在所有 deny **之后**（后 match 者胜）。所以这一行不能放在这里，
;; 否则 verify 会把「被拒目录的 stat」测成比生产更严——见 seatbelt_rules()。
(allow file-write* (subpath "/private/tmp") (subpath "/private/var/folders") (literal "/dev/null"))
(allow network*)
(allow system-socket (socket-domain AF_UNIX))
EOF
}

apply() {
  local tz; tz=$(ip_tz) || die "读不到出口 IP 时区（$GEO_FILE）；先让 geo.sh 跑一次，闸门拒绝在未知时区下启用"
  [ -n "$tz" ] || die "geo.json 没有 timezone 字段"
  valid_tz "$tz" || die "geo.json 的 timezone 不可信或不存在: $tz"
  [ -f "$SETTINGS" ] || die "找不到 $SETTINGS"
  settings_target=$(resolve_symlinks "$SETTINGS")
  [ -n "$settings_target" ] || die "无法解析 $SETTINGS 的符号链接"

  # 备份只在「第一次安装」时创建，之后一直保留，这样 `revert` 永远回到装闸门
  # **之前**的状态。但备份也可能早就过期了：用户重写过 settings.json，旧备份
  # 还留在原地。此时复用旧备份，等于把一份不含当前配置的文件记成「回滚点」，
  # 以后 revert 会静默丢掉这期间新增/修改的一切。
  #
  # 判据不用 mtime（fs 复制、dotfiles 还原都会保留旧 mtime，不可靠）：当前
  # settings.json 里**没有任何闸门痕迹**时，现有备份就不可能是「装闸门之前」的
  # 那份快照，除非它与当前内容完全一致。这种情况把备份换成当前内容，旧备份
  # 另存一份，绝不静默删除。
  if [ -f "$BACKUP" ] && ! cmp -s "$BACKUP" "$settings_target" \
     && ! jq -e '(.sandbox.filesystem.denyRead // [] | length) > 0
                 or ((.permissions.deny // []) | any(startswith("Read(")))' \
            "$settings_target" >/dev/null 2>&1; then
    stale="$BACKUP.stale.$$"
    keep="$BACKUP.prev.$(date +%Y%m%d%H%M%S)"
    if cp -p "$settings_target" "$stale" \
       && cp -p "$BACKUP" "$keep" \
       && mv -f "$stale" "$BACKUP"; then
      say "备份已更新为当前 settings.json；旧备份保留在 $keep"
    else
      rm -f "$stale" 2>/dev/null
      die "无法更新过期的备份 $BACKUP；为免 revert 回到错误状态，未改动 settings.json"
    fi
  fi
  [ -f "$BACKUP" ] || cp -p "$settings_target" "$BACKUP" || die "备份失败"

  local deny_json read_json bash_json
  deny_json=$(deny_paths      | jq -R . | jq -s 'map(select(length>0))')
  read_json=$(read_deny_rules | jq -R . | jq -s 'map(select(length>0))')
  bash_json=$(bash_deny_rules | jq -R . | jq -s 'map(select(length>0))')

  # httpProxyPort 只决定沙箱流量走哪个代理（让出口与 IP 一致），
  # 不构成网络隔离——隔离来自 Clash 的 TUN。
  # allowMachLookup 里的 trustd.agent 是 Go CLI（gh / gcloud / kubectl / terraform）
  # 校验证书用的：Claude 的 mach 白名单没有它，Go 程序一律 x509 OSStatus -26276。
  # 这个键对用户 settings 生效（高权限键，只被 project/local settings 限制）。
  #
  # ⚠️ 所有数组都要 union，不能靠对象合并：jq 的 `+` 在对象上是浅合并，同名数组
  # 整段替换。早先 allowMachLookup 折在 $px 里，用户原有的 mach 授权会被静默删光。
  local proxy_port='null'
  if [ "$PROXY_HOST" = "127.0.0.1" ] && [ -n "$PROXY_PORT" ]; then
    proxy_port="$PROXY_PORT"
  fi

  local tmp="$settings_target.identity.$$"
  if ! jq --argjson deny "$deny_json" --argjson rd "$read_json" \
          --argjson bd "$bash_json" --argjson port "$proxy_port" --arg tz "$tz" '
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
      | .sandbox.network = (.sandbox.network // {})
      | (if $port == null then . else .sandbox.network.httpProxyPort = $port end)
      | .sandbox.network.allowMachLookup =
          (((.sandbox.network.allowMachLookup // []) + ["com.apple.trustd.agent"]) | unique)
      # allowLocalBinding 只在**没有**显式设过时才补 true。用户明确关了它
      # 就是不要沙箱内进程 listen 本地端口，静默翻回 true 是替他做相反的决定。
      | (if .sandbox.network.allowLocalBinding == null
         then .sandbox.network.allowLocalBinding = true else . end)
      | .permissions = (.permissions // {})
      | .permissions.blockReadsOutsideWorkingDirectories = true
      | .permissions.deny = (((.permissions.deny // []) + $rd + $bd) | unique)
    ' "$settings_target" > "$tmp"; then
    rm -f "$tmp"; die "写入失败（jq 退出非零）"
  fi
  # jq 对**空输入**视作零个文档、退出 0 且不输出任何东西——于是一个 0 字节的
  # settings.json 会让上面「成功」，再把 0 字节装回去并报告「已启用」。必须显式
  # 校验输出非空且是合法 JSON，否则宁可 die 也不写。
  if [ ! -s "$tmp" ] || ! jq -e . "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"; die "jq 输出为空或不是合法 JSON（$SETTINGS 可能已损坏）；未改动任何文件"
  fi
  chmod 600 "$tmp" && mv -f "$tmp" "$settings_target" || { rm -f "$tmp"; die "替换失败"; }

  say "已启用：IP 时区 $tz；sandbox denyRead $(printf '%s' "$deny_json" | jq length) 条；权限 deny $(printf '%s' "$read_json$bash_json" | jq -s 'add|length') 条"
  say "备份：$BACKUP"
  say "重启 Claude Code / Claude Desktop 后完整生效"
  say "残余通道：序列号 / 机型名 / MAC / hostname 仍可读（settings.json 注入不了 iokit 与 sysctl 规则）"
}

verify() {
  need sandbox-exec
  need python3   # CHECKS 里有 python 时区名一行
  local tz tz_source
  if tz=$(ip_tz) && [ -n "$tz" ]; then
    tz_source="geo.json（出口 IP）"
  else
    # 不能假装有一个「IP 时区」。早先这里回落成作者机器的 America/Los_Angeles
    # 再在页脚断言「闸门内 TZ 应等于 IP 时区」，于是在根本没有 geo.json 的状态
    # 下制造出一条通过的结论——而那正是 apply 会拒绝启用的状态。
    tz="UTC"
    tz_source="无 geo.json，用合成值 UTC（不是 IP 时区，本行不代表一致性）"
  fi
  VERIFY_PROF=$(mktemp "${TMPDIR:-/tmp}/identity-verify.XXXXXX") || die "mktemp 失败"
  trap 'rm -f "${VERIFY_PROF:-}" "${VERIFY_PROF:-}.base"' EXIT
  { claude_profile; echo ';; --- identity gate: filesystem.denyRead + permissions.deny Read(...) 的并集，与 apply 写出的一致 ---'
    seatbelt_rules
    read_rule_rules
    echo ';; --- /identity gate ---'
  } > "$VERIFY_PROF"

  # 两列都用同一份 Claude 沙箱骨架：闸门外 = 官方默认，闸门内 = 加上 apply 的
  # denyRead。这样这一列差值就是 apply 真正带来的变化。
  # 闸门内必须带上 TZ（settings.json 的 env.TZ 就是这样注入的），否则读不到
  # 本机时区后会退化成 UTC——那是「藏起来」的代价，不是缺陷。
  local base_prof="$VERIFY_PROF.base"
  claude_profile > "$base_prof"

  printf '%-24s %-22s %s\n' "通道" "Claude 沙箱" "沙箱 + apply"
  printf '%-24s %-22s %s\n' "----------------------" "--------------------" "--------------------"
  local row label cmd base gate
  # CHECKS 是 quoted heredoc，里面的 $HOME/$GEO_FILE 不会被本 shell 展开。行内
  # 因此用占位符，执行前再替换成真实路径——否则 `jq ... "$GEO_FILE"` 会在
  # 子 shell 里拿到空变量、两列都报「Could not open file」，那一行永远测不出东西。
  local cmds; cmds=$(sed "s|GEO_FILE_PATH|$GEO_FILE|g; s|\$HOME|$HOME|g" <<'CHECKS'
TZ 显示|date "+%Z %z"
系统时区链接|readlink /etc/localtime || echo 空
读 localtime|cat /etc/localtime >/dev/null 2>&1 && echo 可读 || echo 拒绝
AppleLocale|defaults read -g AppleLocale 2>&1 | tail -1
系统语言|defaults read -g AppleLanguages 2>&1 | tail -1
系统 Country|defaults read /Library/Preferences/.GlobalPreferences Country 2>&1 | tail -1
键盘/输入法|defaults read com.apple.HIToolbox 2>&1 | tail -1
电脑名(偏好文件)|plutil -extract System.System.ComputerName raw /Library/Preferences/SystemConfiguration/preferences.plist 2>&1 | tail -1
配对蓝牙名|plutil -p /Library/Preferences/com.apple.bluetooth.plist 2>&1 | grep -c BSDName
时区自动设置|plutil -extract Active raw /Library/Preferences/com.apple.timezone.auto.plist 2>&1 | tail -1
定位客户端库|plutil -p /var/db/locationd/clients.plist >/dev/null 2>&1 && echo 可读 || echo 拒绝
Wi-Fi 日志|cat /var/log/wifi.log /var/log/wifi.log.0.bz2 >/dev/null 2>&1 && echo 可读 || echo 拒绝
Wi-Fi 偏好文件|ls $HOME/Library/Preferences/com.apple.wifi* 2>&1 | head -1
机型 hw.model|python3 -I -c 'import ctypes;l=ctypes.CDLL(None,use_errno=True);b=ctypes.create_string_buffer(64);n=ctypes.c_size_t(64);print(b.value.decode() if l.sysctlbyname(b"hw.model",b,ctypes.byref(n),None,0)==0 else "EPERM")' 2>&1
序列号 ioreg|ioreg -l 2>/dev/null | grep -c IOPlatformSerialNumber
MAC 地址数|ifconfig 2>/dev/null | grep -c ether
电脑名|scutil --get ComputerName 2>&1
home 偏好域名数|defaults domains 2>/dev/null | tr ',' '\n' | grep -c '[^[:space:]]'
geo.json 系统时区|jq -r .system_tz GEO_FILE_PATH 2>&1 | tail -1
Claude machineID|jq -r .machineID $HOME/.claude.json 2>&1 | cut -c1-12
Claude 历史目录|ls $HOME/.claude/projects 2>/dev/null | wc -l
SSH 私钥|head -c 20 $HOME/.ssh/id_rsa 2>&1 | tail -1
GPG 密钥环|ls $HOME/.gnupg 2>&1 | head -1
Keychain 条目|security find-generic-password -s gh:github.com 2>&1 | head -1
node 时区(未注入)|env -u TZ node -e "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)" 2>&1 | tail -1
node 时区(已注入)|node -e "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)" 2>&1 | tail -1
python 时区名(未注入)|env -u TZ python3 -I -c "import time;print(time.tzname)" 2>&1 | tail -1
CHECKS
)
  while IFS='|' read -r label cmd; do
    [ -n "$label" ] || continue
    base=$(env -i HOME="$HOME" PATH="$PATH" TZ="$tz" sandbox-exec -f "$base_prof" /bin/sh -c "$cmd" 2>&1 | head -1 | tr '\t' ' ')
    gate=$(env -i HOME="$HOME" PATH="$PATH" TZ="$tz" sandbox-exec -f "$VERIFY_PROF" /bin/sh -c "$cmd" 2>&1 | head -1 | tr '\t' ' ')
    printf '%-24s %-22s %s\n' "$label" "$(cut -c1-22 <<<"${base:-—}")" "$(cut -c1-34 <<<"${gate:-—}")"
  done <<<"$cmds"
  rm -f "$base_prof"
  echo
  echo "TZ 取值来源：$tz_source"
  echo "闸门内 TZ 应等于 IP 时区（$tz）；文件型通道应为空 / 拒绝。"
  echo "机型 hw.model 两列都是 EPERM，不是闸门的功劳：hw.model 不在官方 sysctl 白名单里，"
  echo "官方沙箱本来就拒绝（sysctl -n 在骨架里连允许的名字都报 fmt 错误，所以这里用 sysctlbyname）。"
  echo "序列号 / 机型名 / MAC / hostname 是已知残余通道：它们走 iokit 与 sysctl，"
  echo "settings.json 没有注入这两类规则的入口（权限规则里的 Bash(...) 只在对话内挡一层）。"
  echo "scutil --get ComputerName 返回的是机型名（IOKit），不是个人名：真正来源 configd 不在 mach 白名单里。"
  echo "闸门内若不注入 TZ，date 与 node 会一起退化成 UTC——这是本机时区已被藏起来的证据；"
  echo "两者必须一致退化：node 仍报 America/Los_Angeles 而 date 报 UTC，说明有通道没关。"
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
  local target; target=$(resolve_symlinks "$SETTINGS") || die "无法解析 $SETTINGS 的符号链接"
  local tmp="$target.identity.$$"
  if [ -f "$BACKUP" ]; then
    cp -p "$BACKUP" "$tmp" || die "恢复失败（无法复制备份）"
    [ -s "$tmp" ] && jq -e . "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; die "备份 $BACKUP 不是合法 JSON，拒绝覆盖"; }
    mv -f "$tmp" "$target" || { rm -f "$tmp"; die "恢复失败"; }
    say "已从 $BACKUP 恢复（重启 Claude Code 生效）"
    return 0
  fi
  # 备份是用户可以随手删掉的 dotfile。没有它时不能只会说「没有备份」就退出：
  # 那样闸门就成了关不掉的开关，而 uninstall.sh 还承诺 identity.sh 能关掉它。
  # 这里改为**外科式撤销**——只减掉 apply 自己加进去的那几项（用同一套生成器
  # 算出来，和 apply 写进去的必然一致），不碰用户原有的任何规则。
  # 沙箱开关类键（enabled / failIfUnavailable / allowUnsandboxedCommands 等）
  # 分不清是用户设的还是 apply 设的，一律保留：它们不泄露身份，且方向是更安全的一侧。
  [ -f "$SETTINGS" ] || die "找不到 $SETTINGS，也没有备份 $BACKUP"
  need jq
  local deny_json read_json bash_json tz
  deny_json=$(deny_paths      | jq -R . | jq -s 'map(select(length>0))')
  read_json=$(read_deny_rules_all | jq -R . | jq -s 'map(select(length>0))')
  bash_json=$(bash_deny_rules | jq -R . | jq -s 'map(select(length>0))')
  tz=$(ip_tz 2>/dev/null || true)

  if ! jq --argjson deny "$deny_json" --argjson rd "$read_json" \
          --argjson bd "$bash_json" --arg tz "$tz" '
      .sandbox.filesystem.denyRead =
        ((.sandbox.filesystem.denyRead // []) - $deny)
      | .sandbox.network.allowMachLookup =
        ((.sandbox.network.allowMachLookup // []) - ["com.apple.trustd.agent"])
      | .permissions.deny =
        ((.permissions.deny // []) - $rd - $bd)
      # 只在能证明「这个 TZ 就是闸门写进去的那一个」时才删：拿不到 geo.json
      # 就无法证明，删掉可能正好删了用户自己设的值，那宁可留下并提示。
      | (if $tz != "" and .env.TZ == $tz then del(.env.TZ) else . end)
      | (if .env.LANG  == "en_US.UTF-8" then del(.env.LANG)  else . end)
      | (if .env.LC_ALL == "en_US.UTF-8" then del(.env.LC_ALL) else . end)
      | (if (.sandbox.filesystem.denyRead | length) == 0 then del(.sandbox.filesystem.denyRead) else . end)
      | (if (.sandbox.network.allowMachLookup | length) == 0 then del(.sandbox.network.allowMachLookup) else . end)
      | (if (.permissions.deny | length) == 0 then del(.permissions.deny) else . end)
      | (if (.sandbox.network | length) == 0 then del(.sandbox.network) else . end)
      | (if (.sandbox.filesystem | length) == 0 then del(.sandbox.filesystem) else . end)
      | (if (.sandbox | length) == 0 then del(.sandbox) else . end)
      | (if (.permissions // {} | length) == 0 then del(.permissions) else . end)
      | (if (.env | length) == 0 then del(.env) else . end)
    ' "$target" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "没有备份，且外科式撤销失败；请手工编辑 $SETTINGS"
  fi
  if [ ! -s "$tmp" ] || ! jq -e . "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"; die "外科式撤销输出非法 JSON；未改动任何文件"
  fi
  mv -f "$tmp" "$target" || { rm -f "$tmp"; die "恢复失败"; }
  say "没有备份；已用外科式撤销移除闸门加入的 denyRead / Read() / Bash() / env 条目"
  say "（沙箱开关类键保留：分不清是否由本脚本设置，且它们不泄露身份）"
  if [ -z "$tz" ]; then
    # geo.json 也没了就无法证明 .env.TZ 是闸门写的；留着并说明，而不是静默留一条。
    say "⚠️  读不到 geo.json，无法判断 .env.TZ 是否由闸门写入，已保留：$(jq -r '.env.TZ // "未设置"' "$target")"
  fi
  say "重启 Claude Code 生效"
}

case "$MODE" in
  apply)   apply ;;
  verify)  verify ;;
  status)  status ;;
  revert)  revert ;;
  *)       die "用法: $0 {apply|verify|status|revert}" ;;
esac
