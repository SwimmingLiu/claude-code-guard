# 身份闸门（identity gate）

Claude Code 能读本机的东西，网络层（代理 / TUN）一点都管不到：它读的是文件、XPC、sysctl 和 IOKit。
这份文档记录**哪些通道存在、哪些关掉了、靠什么规则关的、哪些是刻意留着的**，
每条结论都来自本机 `sandbox-exec` 对照实验（macOS 26 / Claude Code 2.1.325）。

- 实现：`identity.sh`（`apply` / `verify` / `status` / `revert`）
- 前置：`geo.sh` 已写出 `~/.cache/proxyguard/geo.json`（出口 IP 时区是唯一事实来源）
- 生效范围：Claude Code 的 **Bash / PowerShell / Monitor** 子进程（官方沙箱的边界）
  + **Read / Grep / Glob** 内置工具（靠 `permissions.deny` 规则，另一条路径）

---

## 1. 三列对照：不装沙箱 / Claude 官方沙箱 / 沙箱 + 闸门

`identity.sh apply` 能写进 `settings.json` 的只有**文件路径**和**权限规则**。
下表的三列就是这么来的：B 列是 Claude Code 官方沙箱自带的 profile（按其二进制里
`Lj()` 逐条重建，59 条 sysctl 白名单、11 个 mach 服务、`(allow file-read*)` …），
C 列 = B 列 + `apply` 写入的 `denyRead`。

| 通道 | 实测读取方式 | 无沙箱 | Claude 沙箱 | 沙箱 + apply | 谁关的 |
|---|---|---|---|---|---|
| 系统时区链接 | `readlink /etc/localtime` | `…/Asia/Shanghai` | `…/Asia/Shanghai` | **空** | `denyRead /private/etc/localtime` |
| 系统时区内容 | `cat /etc/localtime` | 可读 | 可读 | **拒绝** | 同上 |
| 语言 / 地区 | `defaults read -g AppleLocale` | `en_CN` | `en_CN` | **域不存在** | `denyRead ~/Library/Preferences` |
| 系统语言 | `defaults read -g AppleLanguages` | `en-CN, zh-Hans-CN` | 同左 | **域不存在** | 同上 |
| 键盘 / 输入法 | `defaults read com.apple.HIToolbox` | 可读 | 可读 | **域不存在** | 同上 |
| 定位客户端库 | `plutil -p /var/db/locationd/clients.plist` | 可读 | 可读 | **拒绝** | `denyRead /private/var/db/locationd` |
| Wi-Fi 日志 | `cat /var/log/wifi.log` | 可读 | 可读 | **拒绝** | `denyRead /private/var/log/wifi.log` |
| Wi-Fi 优选网络 | `networksetup -listpreferredwirelessnetworks en0` | 列表 | 报错 | 报错 | 沙箱的 mach 白名单（**不是**闸门） |
| 机型 sysctl | `sysctl -n hw.model` | `Mac16,12` | **拒绝** | 拒绝 | 沙箱的 sysctl 白名单（`hw.model` 不在里面） |
| 序列号 | `ioreg -l \| grep IOPlatformSerialNumber` | 1 | **1** | **1** | ✗ 残余 |
| 机型名 | `system_profiler SPHardwareDataType` | `MacBook Air` | 同左 | 同左 | ✗ 残余 |
| MAC 地址 | `ifconfig \| grep ether` | 11 | 11 | 11 | ✗ 残余 |
| 电脑名 | `scutil --get ComputerName` | 个人名 | `MacBook Air` | `MacBook Air` | 沙箱（部分） |
| 主机名 | `hostname` | `xxx.local` | 同左 | 同左 | ✗ 残余 |
| 写偏好 | `defaults write …` | 可写 | **拒绝** | 拒绝 | 沙箱（cfprefsd 写不在白名单） |

**结论：`apply` 真正关掉的是「时区 / 语言 / 地区 / 键盘 / 位置 / Wi-Fi 日志」这一条主轴。
序列号、机型名、MAC、主机名读得到，因为它们是 IOKit / sysctl，而 `settings.json` 没有
注入这两类规则的入口。**

`identity.sh verify` 跑的就是这张表的 B/C 两列：两列都用按 Claude 二进制里 `Lj()`
重建的 `(deny default)` + 白名单骨架，唯一差别是 C 列多出 apply 写入的那组 deny。
（第一版 verify 用 `(allow default)` 打底，把 locale 测成「无效」——那是假阴性，
见 §2。）

---

## 2. 四条曾经写错、现已实测推翻的说法

留在这里，防止以后有人「修回去」。

### ✗「locale 走 XPC，必须 deny cfprefsd，文件 deny 无效」——**取决于测试骨架**

这条曾经在两份**不同骨架**的 profile 上得出相反结论，两边都是真的：

| 骨架 | 只加 `deny ~/Library/Preferences` | 只加 `deny cfprefsd.agent` |
|---|---|---|
| `(deny default)` + 白名单（= Claude 官方沙箱） | **域不存在** ✓ | `en_CN`（无效） |
| `(allow default)`（= 随手写的测试骨架） | `en_CN`（无效） | **域不存在** ✓ |

原因是取值的两条路：cfprefsd 的 XPC 能通就走 XPC，走不通才退回直接读文件。
Claude 的 profile 是 `(deny default)`，cfprefsd **不在**它的 mach 白名单里，
所以**文件 deny 就是主锁，XPC 根本不用碰**——而且也从 `settings.json` 碰不到。

**教训：verify 必须用 Claude 真实的 profile 形状 `(deny default)` + 白名单。**
第一版 `verify` 用 `(allow default)` 打底，把 locale 这一行测成了「闸门无效」，
是假阴性；`identity.sh` 里的 `claude_profile()` 就是为此按二进制里的 `Lj()` 重建的。

同一个教训也适用于单文件规则：只封 `.GlobalPreferences*.plist`、`com.apple.HIToolbox.plist`
这些**单个文件**全部无效（实测四组都漏），只有整目录 `subpath` 有效。

### ✗「必须封 hw.model / 要按名封，否则会漏」

`hw.model` **不在** Claude 官方沙箱的 sysctl 白名单里，本来就拒绝（见 §1 表）。
`identity.sh` 再封一次是冗余的——而且从 `settings.json` 也根本封不了。
真正不能做的是**整类** `(deny sysctl-read)`：实测 `ps`、`uname`、`python platform`、
`node`、`npm` 全挂（`LowLevelAlloc arithmetic overflow`）。

### ✗「按大洲封 zoneinfo，就能不让它知道真实时区」

zoneinfo 是**静态世界时区库**：读 `Asia/Shanghai` 只说明这个条目存在，不说明本机在用。
封掉非 IP 大洲的代价是实打实的：

```
TZ=Asia/Shanghai date      → UTC +0000     （静默错，不报错）
python3 ZoneInfo("Asia/Shanghai") → PermissionError
```

而且只在「TZ 没注入」时才起作用——而 TZ 没注入时 `date` 已经因为 localtime 被封
退化成 UTC。换句话说它只是在 UTC 之上再加一层工具损坏。**已删除。**

---

## 3. 时区的正确做法：封 localtime，注入 TZ，别动 zoneinfo

`/etc/localtime` 是唯一指向「本机真实时区」的路径（`/etc` → `/private/etc` 同一 inode，
两个都封）。封掉之后：

- `readlink /etc/localtime` → 空；`cat` → 拒绝；`ls -l` 的元数据仍能看到链接目标
  （`file-read-metadata` 目录例外所致），所以 `permissions.deny` 里另有 `Bash(...)` 规则兜底。
- `date`、`Intl.DateTimeFormat()`、Python `astimezone()` 在 **TZ 未设置**时全部退化为 **UTC**。
  这是「本机时区已被藏起来」的必然结果，也是可被观察到的矛盾。
- 注入 `TZ=America/Los_Angeles`（`geo.sh` 写 `settings.json` 的 `env.TZ`，
  `launchctl setenv TZ` 管 GUI 应用）后，三者一致输出 `PST -0800` / `America/Los_Angeles`。

所以闸门**依赖 TZ 注入**：`apply` 会读 `geo.json` 写 `env.TZ`；读不到 IP 时区时拒绝启用。

---

## 4. 残余通道（明确不做）

| 通道 | 为什么留着 | 想封的代价 |
|---|---|---|
| 序列号（`ioreg -l`） | IOKit，`settings.json` 注入不了 `(deny iokit-get-properties)` | 用 seatbelt 包装脚本启动 `claude` 可以封，但**外层一旦带 deny，Claude 自己的内层沙箱就 `sandbox_apply: Operation not permitted`**，所有 Bash 命令失效——两条路不共存 |
| 机型名 / MAC | 同上（`system_profiler`、`ifnet`） | 同上 |
| 主机名（`kern.hostname`） | 封它会打死 `ps`、`python`、`node`、`npm`（实测 `PermissionError` / 崩溃） | 不可接受 |
| `dscl ... RealName` | 沙箱已让它失败（opendirectoryd 白名单只有 libinfo/membership） | — |
| 用户名（家目录路径、`ls -l` 属主） | 路径天然带用户名 | 改名 / 换家目录 |
| `ls -l /etc/localtime` 的链接目标 | 目录元数据例外 | `permissions.deny` 的 `Bash(...)` 规则在对话内挡一层 |

`permissions.deny` 里的 `Bash(ioreg:*)`、`Bash(system_profiler:*)`、`Bash(ifconfig:*)` 等
是**对话内**的规则，不是内核边界：Claude 若把命令写进脚本执行仍可绕过。
它们的价值是让 Claude 不会顺手去读，而不是防御恶意代码。

---

## 5. 与出口 IP 的一致性

`apply` 从 `geo.json` 读 `timezone`，写进 `env.TZ`。当前出口 `38.98.190.130`
（Las Vegas, Nevada, US）→ `America/Los_Angeles`，闸门内 `date` 稳定输出 `PST -0800`。

`sandbox.network.httpProxyPort=7897` 让沙箱内进程的 `HTTPS_PROXY` 指向本机 Clash，
**但它不构成网络隔离**：Claude Code 只有在设置了 `allowedDomains` 或 `denyAllNetwork`
时才会生成 `(deny network*)`，否则 profile 里是 `(allow network*)`。真正的出口锁定
来自 Clash 的 TUN（见 README §四）。

---

## 6. 和其它工具的已知冲突

打开 Claude Code 官方沙箱（`apply` 做的事）本身就会带来下面这些，**与闸门规则无关**：

- **Go 写的 CLI 无法校验证书**：沙箱的 mach 白名单没有 `com.apple.trustd.agent`，
  `gh api`、`gcloud`、`terraform`、`kubectl` 报 `x509: OSStatus -26276`。
  `apply` 会把 `trustd.agent` 加进 `sandbox.network.allowMachLookup`（旧版本可能忽略该键）。
- **Keychain 用不了**：`security find-generic-password` 被拒（`securityd.xpc` 不在白名单），
  `gh auth status` 报 token 无效。用 `GH_TOKEN` 环境变量；git over SSH 不受影响。
  `~/Library/Keychains` 仍保留在 `denyRead` 里——keychain 数据库文件在沙箱内本来就可读，
  这是真正需要挡住的东西。
- **`open -a App` 失败**（-10810），`osascript` 可用。
- **Homebrew** 的 here-doc 临时文件被拒（沙箱缺 `TMPDIR` 写权限，与闸门无关）。
- `permissions.blockReadsOutsideWorkingDirectories = true` 后，内置文件工具只能读工作目录；
  需要多目录时用 `/add-dir`。

---

## 7. 操作

```bash
./identity.sh verify    # 只读对照实验：同一份 denyRead，闸门外 vs 闸门内
./identity.sh apply     # 写入 ~/.claude/settings.json（自动备份为 .proxyguard.bak）
./identity.sh status    # 查看当前闸门与残余通道
./identity.sh revert    # 从备份恢复
```

`install.sh` 会把 `identity.sh` 一并安装到
`~/Library/Application Support/proxyguard/`，但**不会自动 apply**——
修改 Claude Code 设置属于用户决定，安装脚本只负责把工具放到位并打印用法。
`uninstall.sh --purge` 会先 `revert` 再删除。
