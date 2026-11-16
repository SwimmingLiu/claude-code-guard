# 身份闸门（identity gate）

Claude Code 能读本机的东西，网络层（代理 / TUN）一点都管不到：它读的是文件、XPC、sysctl 和 IOKit。
这份文档记录**哪些通道存在、哪些关掉了、靠什么规则关的、哪些是刻意留着的**，
每条结论都来自本机 `sandbox-exec` 对照实验（macOS 26 / Claude Code 2.1.325）。

- 实现：`identity.sh`（`apply` / `verify` / `status` / `revert`）
- 前置：`geo.sh` 已写出 `~/.cache/proxyguard/geo.json`（出口 IP 时区是唯一事实来源）
- 生效范围：Claude Code 的 **Bash / PowerShell / Monitor** 子进程（官方沙箱的边界）
  + **Read / Grep / Glob** 内置工具（靠 `permissions.deny` 规则，另一条路径）
- 代价（都是实测的，见 §6）：沙箱内 **git over SSH 与 keychain 不可用**、
  项目 hook 不再被沙箱包裹。HTTPS + token 的正常开发流程不受影响。

---

## 1. 三列对照：不装沙箱 / Claude 官方沙箱 / 沙箱 + 闸门

`identity.sh apply` 能写进 `settings.json` 的只有**文件路径**和**权限规则**。
下表的三列就是这么来的：B 列是 Claude Code 官方沙箱自带的 profile（按其二进制里
`Lj()` 逐条重建，50 条具名 sysctl + 10 条前缀、14 个 mach 服务、
`(allow network*)` …），C 列 = B 列 + `apply` 写入的 `denyRead`。

| 通道 | 实测读取方式 | 无沙箱 | Claude 沙箱 | 沙箱 + apply | 谁关的 |
|---|---|---|---|---|---|
| 系统时区链接 | `readlink /etc/localtime` | `…/Asia/Shanghai` | `…/Asia/Shanghai` | **空** | `denyRead /private/etc/localtime` |
| 系统时区内容 | `cat /etc/localtime` | 可读 | 可读 | **拒绝** | 同上 |
| 语言 / 地区 | `defaults read -g AppleLocale` | `en_CN` | `en_CN` | **域不存在** | `denyRead ~/Library/Preferences` |
| 系统语言 | `defaults read -g AppleLanguages` | `en-CN, zh-Hans-CN` | 同左 | **域不存在** | 同上 |
| 键盘 / 输入法 | `defaults read com.apple.HIToolbox` | 可读 | 可读 | **域不存在** | 同上 |
| 系统 Country | `defaults read /Library/Preferences/.GlobalPreferences Country` | `CN` | `CN` | **域不存在** | `denyRead /Library/Preferences` |
| 电脑名（偏好文件） | `plutil -extract System.System.ComputerName raw …/SystemConfiguration/preferences.plist` | 真名 | 真名 | **拒绝** | 同上 |
| 配对蓝牙（名字+MAC） | `plutil -p /Library/Preferences/com.apple.bluetooth.plist \| grep -c BSDName` | `1` | `1` | `0` | 同上 |
| 时区自动设置 | `plutil -extract Active raw …/com.apple.timezone.auto.plist` | `true` | `true` | **拒绝** | 同上 |
| 定位客户端库 | `plutil -p /var/db/locationd/clients.plist` | 可读 | 可读 | **拒绝** | `denyRead /private/var/db/locationd` |
| Wi-Fi 日志 | `cat /var/log/wifi.log` | 可读 | 可读 | **拒绝** | `denyRead /private/var/log/wifi.log` |
| Wi-Fi 偏好文件 | `ls ~/Library/Preferences/com.apple.wifi*` | 列出 | 列出 | **不存在** | `denyRead ~/Library/Preferences` |
| Wi-Fi 优选网络 | `networksetup -listpreferredwirelessnetworks en0` | 列表 | 失败 | 失败 | 不是闸门：该命令要 `AuthorizationCreate`，沙箱内恒失败（-60008） |
| 机型 sysctl | `sysctlbyname("hw.model")`（`sysctl -n` 在此骨架里连允许的名字也报 `fmt` 错误，见 §2） | `Mac16,12` | **EPERM** | EPERM | 沙箱的 sysctl 白名单（`hw.model` 不在里面） |
| 序列号 | `ioreg -l \| grep IOPlatformSerialNumber` | `LRH…` | **`LRH…`** | **`LRH…`** | ✗ 残余（IOKit） |
| 机型名 | `system_profiler SPHardwareDataType` | `MacBook Air` / `Mac16,12` | 同左 | 同左 | ✗ 残余 |
| MAC 地址 | `ifconfig \| grep ether` | 11 | 11 | 11 | ✗ 残余 |
| 电脑名（XPC） | `scutil --get ComputerName` | 个人名 | **`MacBook Air`**（机型名，非个人名） | 同左 | 沙箱把真正来源 configd 挡在外面，只剩 IOKit 的机型名 |
| 主机名 | `hostname` / `kern.hostname` | `xxx.local` | **`xxx.local`** | 同左 | ✗ 残余（白名单里具名允许） |
| 偏好域名清单 | `defaults domains \| tr ',' '\n' \| grep -c '[^[:space:]]'` | 638 | 638 | **0** | `denyRead ~/Library/Containers` |
| proxyguard geo.json | `jq -r .system_tz ~/.cache/proxyguard/geo.json` | `Asia/Shanghai` | 同左 | **拒绝** | `denyRead ~/.cache/proxyguard` |
| Claude machineID | `jq -r .machineID ~/.claude.json` | 值 | 同左 | **拒绝** | `denyRead ~/.claude.json` |
| Claude 历史对话 | `ls ~/.claude/projects` | 18 项 | 18 项 | **拒绝** | `denyRead ~/.claude/projects` |
| SSH 私钥 | `head -c 20 ~/.ssh/id_rsa` | 私钥头 | 同左 | **拒绝** | `denyRead ~/.ssh/id_rsa` |
| GPG 密钥环 | `ls ~/.gnupg` | 可读 | 同左 | **拒绝** | `denyRead ~/.gnupg` |
| 写偏好 | `defaults write …` | 可写 | **拒绝** | 拒绝 | 沙箱没给 `~/Library/Preferences` 的 `file-write*`（与 cfprefsd 无关，见 §2） |
| Keychain 条目 | `security find-generic-password -s gh:github.com` | 找得到 | 找得到 | **找不到** | `denyRead ~/Library/Keychains`（`securityd.xpc` 在 mach 白名单里，见 §2） |

**结论：`apply` 真正关掉的是「时区 / 语言 / 地区 / 键盘 / 位置 / Wi-Fi 日志 / 偏好域名清单」
这一条主轴，外加 Claude 自己的 machineID、历史对话、SSH 私钥、GPG 密钥环、
`~/Library/Containers`（第三方 App 的全部本地数据）和 keychain 条目。
序列号、机型名、MAC、主机名读得到，因为它们是 IOKit / sysctl，而 `settings.json` 没有
注入这两类规则的入口。**


`identity.sh verify` 跑的就是这张表的 B/C 两列：两列都用按 Claude 二进制里 `Lj()`
重建的 `(deny default)` + 白名单骨架，唯一差别是 C 列多出 apply 写入的那组 deny。
（第一版 verify 用 `(allow default)` 打底，把 locale 测成「无效」——那是假阴性，
见 §2。）

---

## 2. 曾经写错、现已实测推翻的说法

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

**测这一行要用 `sysctlbyname()`，不能用 `sysctl -n`。** Claude 沙箱里 `/usr/sbin/sysctl`
对**任何**名字都报 `sysctl: sysctl fmt -1 1024 1: Operation not permitted`——包括白名单里
明写着允许的 `hw.ncpu`、`kern.ostype`。原因不是规则，而是 `sysctl` 取整张 MIB 的方式
在这个骨架里不成立。所以「`sysctl -n hw.model` 两列都报错」证明不了闸门关掉了机型；
`verify` 用 python 的 `ctypes.sysctlbyname("hw.model")`，才有 `Mac16,12` / `EPERM` 的对照。


### ✗「按大洲封 zoneinfo，就能不让它知道真实时区」

zoneinfo 是**静态世界时区库**：读 `Asia/Shanghai` 只说明这个条目存在，不说明本机在用。
封掉非 IP 大洲的代价是实打实的：

```
TZ=Asia/Shanghai date      → UTC +0000     （静默错，不报错）
python3 ZoneInfo("Asia/Shanghai") → PermissionError
```

而且只在「TZ 没注入」时才起作用——而 TZ 没注入时 `date` 已经因为 localtime 被封
退化成 UTC。换句话说它只是在 UTC 之上再加一层工具损坏。**已删除。**

### ✗「`(allow sysctl-write)` 只影响写」——**错了，它把读也一起放开**

这是 verify 曾经谎报「`hw.model` 两列都读到 `Mac16,12`」的原因。seatbelt 里
`sysctl-write` **蕴含** `sysctl-read`（只要名字匹配），所以裸写：

```
(allow sysctl-write)          → hw.model / kern.hostname / machdep.cpu.brand_string
                                / kern.boottime 全部可读
```

而 2.1.325 二进制里官方模板的原文是**带名字限定**的一条：

```
(allow sysctl-write
  (sysctl-name "kern.tcsm_enable"))
```

改成限定写法后，上述 sysctl 重新变成 `Operation not permitted`，而 `node`、
`gh`、`python3` 全部照常工作（实测 node v24.22.2、gh 2.89.0）。**必须保留限定。**

### ✗「`ls -l /etc/` 的目录元数据例外会泄漏 localtime 的链接目标」

实测（闸门内）：`ls -l /etc/` 打印的 localtime 行**没有** `-> target`，只有
`lrwxr-xr-x 1 root wheel 39 … localtime` 和一行 `ls: /etc//localtime: Operation not permitted`；
`ls -l /private/etc/localtime`、`stat -f %Y`、`readlink` 全部拒绝。原因是
`ls` 对每个条目做 lstat，那条 `(allow file-read-metadata (vnode-type DIRECTORY))`
只放开「目录自身」，不放开目录里这个符号链接。

唯一的残余是**大小字段 39**（链接目标的字符串长度，`/var/db/timezone/zoneinfo/Asia/Shanghai`
正好 39 字节）。它不足以定出时区——39 字节的 zoneinfo 路径有一大把。

**但这条例外本身要复现对**：`Dj()` 只在 `denyRead` 非空时才追加
`(allow file-read-metadata (vnode-type DIRECTORY))`，而且排在所有 deny **之后**。
`identity.sh` 的 `seatbelt_rules()` 现在按这个顺序发；早先写在骨架顶部，
会让 verify 把被拒目录的 stat 测得比生产更严。

### ✗「`~/Library/Preferences` 一关，偏好域名就没了」

只封它，`defaults domains` 从 638 条降到 **140** 条。剩下这 140 条的来源是
`~/Library/Containers`——实测逐个排除：加封 `Group Containers`、`Application Support`、
`Saved Application State` 都不减少，**只有封 `Containers` 才归零**。
容器目录本来也不该让 Claude 读：715 个 App 容器、22 GB，里面是 DingTalk、WeWork
这类第三方 App 的全部本地数据。`deny_paths()` 因此整目录封。

（计数命令要用 `defaults domains | tr ',' '\n' | grep -c '[^[:space:]]'`。
`defaults domains` 把整份清单打在**一行**里，`grep -c ,` 只数行、永远输出 1，
不是「域名个数」——早先文档写的 636 就是这么来的一个从未实测过的数字。）

### ✗「`~/.config/gh/hosts.yml` 值得封」

里面只有 `user:` 和 `git_protocol:`，**没有 token**（token 在 keychain，
沙箱里本来就取不到）。而 `user:` 就是用户名，`$HOME` 路径 `/Users/<用户名>` 早就带出来了。
代价却是 `gh` 完全启动不了：

```
failed to create root command: failed to read configuration:
  open ~/.config/gh/hosts.yml: operation not permitted
```

没有净收益、有实打实的代价，**已从 deny 列表移除**。

### ✗「`/var/db/timezone` 是个要额外封的时区后门」

这个目录里**没有** `localtime` 条目（只有 `zoneinfo`、`tz`、`tz_latest`、`icutz`），
本机时区唯一的路就是 `/etc/localtime` 那个符号链接。封掉之后闸门内
`env -u TZ date` 输出 `UTC +0000`，而允许读 localtime 的对照组输出 `CST +0800`——
对照组证明这个测试骨架是有效的，不是「什么都测不出来」。

### ✗「`defaults write` 被挡是因为 cfprefsd 不在白名单」

cfprefsd 确实不在白名单里（profile 里 `grep -c cfprefsd` = 0），但**那不是原因**：
把骨架原样加上一条 `(allow file-write* (subpath "~/Library/Preferences"))`，
`defaults write` 立刻成功并在磁盘上写出 `.plist`——说明 `defaults` 本来就在直读直写
文件，只是 profile 没给这个目录**任何**写权限。同理，读能成功也不是靠 XPC。

### ✗「`gh` 取不到 token 是因为 `securityd.xpc` 不在白名单」

`com.apple.securityd.xpc` **在** `Lj()` 的 14 个具名 mach 服务里（`SecurityServer`
另有一条）。闸门内 keychain 失效的真正原因是 `~/Library/Keychains` 被 `denyRead`
封了——`security list-keychains` 在闸门内只剩 `/Library/Keychains/System.keychain`，
登录钥匙串整条消失；而 `securityd.xpc` 的 mach 通道一直是通的。

（实测：`security find-generic-password -s gh:github.com` 在官方沙箱里能找到条目，
加上 `~/Library/Keychains` 的 deny 后报「找不到」；`gh auth status` 同上，
从 `✓ Logged in … (keyring)` 变成 `X Failed to log in … (default)`。）

### ✗「`ps` 在沙箱里失败是因为 `kern.hostname` 被白名单放行 / 被 deny」

两条都不成立。`/bin/ps` 是 **setuid root**（`-rwsr-xr-x`）：seatbelt 拒绝在沙箱内
exec 一个 setuid 程序，所以 `/bin/ps` 连启动都不行（`execvp() … Operation not permitted`），
跟 sysctl 规则毫无关系——把 profile 里所有 `process-info*` 规则删掉，`/bin/ps` 照样失败，
而同一个二进制去掉 setuid 位拷一份就能跑。

同理，**`kern.hostname` 不是「封了就打死 `ps`/`python`/`npm`」那个开关**（那是整类
`(deny sysctl-read)` 的后果）。单独 `(deny sysctl-read (sysctl-name "kern.hostname"))` 的
实测代价是：`uname -a` 报错、`hostname` 报错、`python socket.gethostname()` 抛
`PermissionError`、`npm --version` **断言崩溃**（`node_os.cc` 的 `os.hostname()`）；
`node`、`git`、`gh`、`curl`、`python3 -c 'print(1)'` 全部正常。因为 `npm` 会崩，
闸门不封它，`hostname` 仍列为残余通道。

---

## 3. 时区的正确做法：封 localtime，注入 TZ，别动 zoneinfo

`/etc/localtime` 是唯一指向「本机真实时区」的路径（`/etc` → `/private/etc` 同一 inode，
两个都封）。封掉之后：

- `readlink /etc/localtime` → 空；`cat` → 拒绝；`ls -l /etc/` 只剩条目名和大小 39，
  **看不到**链接目标，`ls -l /private/etc/localtime` 和 `stat -f %Y` 也都是 EPERM
  （详见 §2 里对这条的更正）。
- `date`、`Intl.DateTimeFormat()`、Python `astimezone()` 在 **TZ 未设置**时全部退化为 **UTC**。
  这是「本机时区已被藏起来」的必然结果，也是可被观察到的矛盾。
- 注入 `TZ=America/Los_Angeles`（`geo.sh` 写 `settings.json` 的 `env.TZ`，
  `launchctl setenv TZ` 管 GUI 应用）后，三者一致输出 `PST -0800` / `America/Los_Angeles`。

所以闸门**依赖 TZ 注入**：`apply` 会读 `geo.json` 写 `env.TZ`；读不到 IP 时区时拒绝启用。

### 为什么「deny 之后还有一条 allow」不会把闸门重新打开

Claude Code 生成 macOS 剖面的 `Dj()` 按这个顺序发规则：

```
(allow file-read*)                        ← 先全开
(deny file-read* …)                        ← settings 里的 denyRead
(allow file-read* …)                       ← allowWithinDeny = filesystem.allowRead
(allow file-read-metadata (vnode-type DIRECTORY))   ← 仅当 denyRead 非空
```

seatbelt 是**后 match 者胜**，所以第三条会不会重开闸门，全看 `allowWithinDeny` 装了什么。
2.1.325 的答案：

- **普通 Bash** 走 `vY()` → `DPo({readConfig})`，`allowWithinDeny` 只来自用户 settings
  的 `filesystem.allowRead`。`identity.sh` 不写 `allowRead`，所以它是空数组，
  `Dj()` **不发出任何 allow**，deny 胜。
- **只有项目 hook 的沙箱**（`ftn()` → `mtn()`）把硬编码的 `epr`
  （`/etc/passwd`、`/etc/localtime`、`/var/db/timezone` 等 14 条）塞进 `allowRead`，
  会重开 localtime。而它跟本闸门**不共存**：`HQe()` 里的 `Jfr()` 一旦看到
  `blockReadsOutsideWorkingDirectories` 或任何 `denyRead` / `Read(...)` deny，
  就返回 `unavailable:"person_read_rules"`，项目 hook 干脆**不加沙箱**。
  `apply` 正好写了 `blockReadsOutsideWorkingDirectories = true`，所以 `epr` 永远轮不到生效。

---

## 4. 残余通道（明确不做）

| 通道 | 为什么留着 | 想封的代价 |
|---|---|---|
| 序列号（`ioreg -l`） | IOKit，`settings.json` 注入不了 `(deny iokit-get-properties)` | 用 seatbelt 包装脚本启动 `claude` 可以封，但**外层一旦带 deny，Claude 自己的内层沙箱就 `sandbox_apply: Operation not permitted`**，所有 Bash 命令失效——两条路不共存 |
| 机型名 / MAC | 同上（`system_profiler`、`ifnet`） | 同上 |
| 主机名（`kern.hostname`） | 单独封它的实测代价：`uname -a` / `hostname` / `python socket.gethostname()` 失败，**`npm` 断言崩溃** | 不可接受 |
| 电脑名（`scutil --get ComputerName`） | 真正来源 configd **不在** `Lj()` 的 mach 白名单里，沙箱内这个命令只剩 IOKit 的机型名（`MacBook Air`），读不到个人名 | — |
| `dscl ... RealName` | 沙箱已让它失败（opendirectoryd 白名单只有 libinfo/membership） | — |
| 用户名（家目录路径、`ls -l` 属主） | 路径天然带用户名 | 改名 / 换家目录 |

`permissions.deny` 里的 `Bash(ioreg:*)`、`Bash(system_profiler:*)`、`Bash(ifconfig:*)` 等
是**对话内**的规则，不是内核边界：Claude 若把命令写进脚本执行仍可绕过。
它们的价值是让 Claude 不会顺手去读，而不是防御恶意代码。

---

## 5. 与出口 IP 的一致性

`apply` 从 `geo.json` 读 `timezone`，写进 `env.TZ`。当前出口 `38.98.190.130`
（Las Vegas, Nevada, US）→ `America/Los_Angeles`，闸门内 `date` 稳定输出 `PST -0800`。

`sandbox.network.httpProxyPort=7897` 让沙箱内进程的 `HTTPS_PROXY` 指向本机 Clash，
**但它不构成网络隔离**：只有当 `sandbox.network.allowedDomains` 被设置时，
`Lj()` 才不写 `(allow network*)`；否则 profile 里就是裸的 `(allow network*)`。
（`denyAllNetwork` 不是 `settings.json` 的键——它是 SDK 的 per-exec 选项，
`Lj()` 收到的 `needsNetworkRestriction` 来自 `allowedDomains` / SDK 入参两条路。
全部合法的 `sandbox.network` 键只有 `allowedDomains`、`deniedDomains`、
`allowUnixSockets`、`allowAllUnixSockets`、`allowLocalBinding`、`allowMachLookup`、
`httpProxyPort`、`socksProxyPort`、`allowManagedDomainsOnly`、`strictAllowlist`。）
真正的出口锁定来自 Clash 的 TUN（见 README §九）。

---

## 6. 和其它工具的已知冲突

打开 Claude Code 官方沙箱（`apply` 做的事）本身就会带来下面这些，**与闸门规则无关**：

- **Go 写的 CLI 无法校验证书**：沙箱的 mach 白名单没有 `com.apple.trustd.agent`，
  `gh api`、`gcloud`、`terraform`、`kubectl` 报 `x509: OSStatus -26276`。
  `apply` 会把 `trustd.agent` 加进 `sandbox.network.allowMachLookup`（旧版本可能忽略该键）。
  注意 `Lj()` 只在 `enableWeakerNetworkIsolation` 启用时才自带这一条，所以显式写进
  `allowMachLookup` 是必要的。
- **项目 hook 不再被沙箱包起来**：Claude Code 的 hook 沙箱（`ftn()`/`mtn()`）在
  `HQe()` 里一旦看到 `blockReadsOutsideWorkingDirectories` 或任何 `denyRead` /
  `Read(...)` deny，就判定 `person_read_rules` 并**放弃包裹**，hook 直接以普通进程运行。
  `apply` 写的正是这两类规则，所以 `.claude/settings.json` 里的项目 hook 会失去这一层。
  这是上游的设计取舍（它认为「用户自己已经在读路径上设了限制，它就不再叠一层」），
  不是闸门的 bug；但要知道它发生了。
- **`git over SSH` 用不了**：`~/.ssh/id_rsa` / `id_ed25519` 被封，`Permission denied (publickey)`。
  `known_hosts` 没封，所以主机校验不受影响。HTTPS + token 完全不受影响。
- **`gh` 能启动但 token 取不到**：`~/Library/Keychains` 的 `denyRead` 让登录钥匙串整条
  不可见（`security list-keychains` 只剩系统钥匙串），`gh auth status` 报
  `The token in default is invalid`。要用 `GH_TOKEN` 环境变量。
  （**不要**去封 `~/.config/gh/hosts.yml`——封了 `gh` 连启动都失败，而它里面没有 token，见 §2。）
- **Keychain 用不了**：`security find-generic-password` 在闸门内找不到条目
  （原因同样是 `~/Library/Keychains` 的 `denyRead`，**不是** mach 白名单：
  `com.apple.securityd.xpc` 一直在里面，见 §2）。这条 deny 是刻意的——钥匙串数据库
  文件在官方沙箱里本来就可读，闸门要挡的正是这个。
- **`open -a App` 失败**（-10810），`osascript` 可用。
- **Homebrew** 的 here-doc 临时文件被拒（沙箱缺 `TMPDIR` 写权限，与闸门无关）。
- **封 `~/Library/Containers` 之后**，沙箱里的 App 容器数据一律读不到；
  如果你有脚本要读某个 App 的容器，把那个容器路径用 `filesystem.allowRead` 单独放回去。
- `permissions.blockReadsOutsideWorkingDirectories = true` 后，内置文件工具只能读工作目录；
  需要多目录时用 `/add-dir`。

---

## 7. 操作

```bash
./identity.sh verify    # 只读对照实验：同一份 denyRead，闸门外 vs 闸门内
./identity.sh apply     # 写入 ~/.claude/settings.json（自动备份为 .proxyguard.bak）
./identity.sh status    # 查看当前闸门与残余通道
./identity.sh revert    # 从备份恢复；备份没了也能用（外科式撤销）
```

`revert` 优先用备份整份恢复。备份是用户可以随手删掉的 dotfile，所以没有备份时它不会
罢工：用**同一套生成器**算出 `apply` 加进去的那些条目（denyRead / `Read(...)` /
`Bash(...)` / `env.TZ`·`LANG`·`LC_ALL`），逐条减掉，用户原有的规则一条不动
（对每条路径的「带 `/**`」和「不带」两种形态都减，所以 `~/.cache/proxyguard` 已被删掉时
也清得干净）。沙箱开关类键（`enabled` / `failIfUnavailable` / `allowUnsandboxedCommands`
等）分不清是不是 `apply` 设的，保留——它们不泄露身份，方向也是更安全的一侧。

`install.sh` 会把 `identity.sh` 一并安装到
`~/Library/Application Support/proxyguard/`，但**不会自动 apply**——
修改 Claude Code 设置属于用户决定，安装脚本只负责把工具放到位并打印用法。
`uninstall.sh --purge` 会先 `identity.sh revert`；只有在**确认**闸门已关掉之后才删除
`$DEST`。关不掉时（没有备份、没有 `identity.sh`、jq 缺失）它保留工具并打印手工关闭的
步骤，而不是报一个没发生过的「已清除」。
