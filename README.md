# proxyguard

Claude Desktop / Claude Code 的出口守卫。

策略是 fail-closed：只要 Claude 链路的出口没有被 Clash Verge 覆盖，或者代理/网络本身不可用，就按顺序杀掉 `magpie` 网关和 Claude 进程，阻止它们继续发起请求。默认只杀进程，不关 Wi-Fi。

## 一、当前实测结论（2026-11-15）

| 对象 | 实测出口 | 判定 |
| --- | --- | --- |
| Claude Desktop | 主进程 `Claude` + `Claude Helper`；`NetworkService` 连接 `127.0.0.1:7897`，模型/网页流量在 mihomo 侧走 `claude code（链式）` | 走 Clash Verge |
| Claude Code | CLI → `127.0.0.1:3425`（magpie）→ `127.0.0.1:7897`（mihomo mixed-port）→ 节点 | 走 Clash Verge |
| Antify | 已安装，`com.lester.Antify.AntifyCore` 系统扩展 active；是按应用透明代理 + 内容过滤 + kill switch，上游只有 `clash-proxy 127.0.0.1:7897`；Claude Desktop 主进程直连 7897，其派生的 curl/ssh 经 Antify 转发到 7897；Claude Code/magpie 不经 Antify | Clash 的中间层，不是独立出口；最终仍是 Clash |

结论：**两个客户端的最终出口都是 Clash Verge；Antify 不是独立出口，它自己的代理上游也是 Clash 的 `127.0.0.1:7897`，只为 Claude Desktop 的部分派生进程做转发，Claude Code/magpie 不经过它。** Antify 的配置里 `virtualDNSIP = 198.18.0.1`，与 Clash Verge TUN 的 `198.18.0.1/30` 相同，二者不能同时接管 TUN；它的扩展类型也不含 packet-tunnel。

### 证据与复现命令

系统代理：

```bash
scutil --proxy
```

当前 HTTP/HTTPS/SOCKS 均为 `127.0.0.1:7897`，Exceptions 包含 `127.0.0.1` 与内网段。

Clash Verge 运行时（mihomo 由 root 启动，普通用户的 `lsof` 看不到它的监听 socket，所以用 `netstat` / HTTP 探测）：

```bash
curl -sS --unix-socket "/var/run/clash-verge-service/users/$(id -u)/verge-mihomo.sock" \
  http://localhost/configs | jq '{mode, "mixed-port": ."mixed-port", tun}'
```

当前 `tun.enable=true`，设备 `utun1024`，地址 `198.18.0.1/30`，`auto-route=true`，`dns-hijack=["any:53"]`，IPv6 地址 `fdfe:dcba:9876::1/126`；IPv4 用 `1.0.0.0/8`、`2/7` … `128.0/1` 的分段路由覆盖全部可路由地址（`0.0.0.0/8` 仍走物理默认路由，该段不承载真实目的地址），IPv6 用 `100::/8` … `8000::/1` 覆盖全球单播；`route -n get` 抽查 `1.1.1.1`、`64.1.1.1`、`128.1.1.1`、`223.5.5.5` 全部落到 TUN。

正在走的连接与规则链：

```bash
curl -sS --unix-socket "/var/run/clash-verge-service/users/$(id -u)/verge-mihomo.sock" \
  http://localhost/connections \
| jq -c '.connections[]? | select((.metadata.processPath // "")|test("Claude|magpie|antify";"i"))
         | {proc:(.metadata.processPath|split("/")|last), host:.metadata.host, chains}' | head
```

实测到：

- `Claude Helper` → `claude.ai`：`claude code（链式） > 🛡️ 静态IP出口 > ☑️ 手动切换 > 🚀 节点选择 > 🤖 OpenAi`
- `magpie` → `chatgpt.com`：同一条 `claude code（链式）` 链
- `magpie` → `jpn.cdn.moxuna.com` / `hub.oaifree.com`：同一条链，最后一跳为 `🐟 漏网之鱼`
- `magpie-bun` → `gateway.qwenwork.cn`、`magpie` → `betteryou.top`：`DIRECT > 🎯 全球直连`

最后两条是 magpie 自己的其他上游（qwen / 国内站点），不是 Claude 模型流量；Claude / Anthropic / OpenAI 相关的主机在当前连接里全部走代理链。

出口按要求固定为 **`🛡️ 静态IP出口`**：mihomo 里该 Selector 只有两个成员，`claude code（链式）`（alive，当前选中）和 `claude code`（Error），`🚀 节点选择` 与 `☑️ 手动切换` 都指向它。当前 Claude/magpie 连接的实际链是 `claude code（链式） > 🛡️ 静态IP出口 > 🚀 节点选择 > 🤖 OpenAi`，即都经过 `静态IP出口`。守卫把“链里没有 `静态IP出口`”视为未走代理（`REQUIRED_CHAIN`），即使 TUN 承载或别的节点可用。

Antify 侧：`ps` 可见 `Antify`（52490）与 root 的 `AntifyCore`（52508，0.0.89 `activated enabled`）。扩展声明 `TransparentProxyProvider` 与 `AntifyFilterProvider`，没有 packet-tunnel；配置里的代理上游只有 `clash-proxy` = `127.0.0.1:7897`。`netstat -anv -p tcp` 显示 AntifyCore 有 9–10 条到 7897 的 ESTABLISHED（doubao/feishu/weixin/multica 等）。Claude Desktop 的 `NetworkService` 直连 7897；它派生的 `com.apple.curl` 有 9 条到 anthropic.com 的流量，Antify 记为 `outcome=proxied`、`rulekind=hostInherit`，即这部分经 Antify 转到 7897。Claude Code 的 magpie 链路没有 Antify 规则（magpie 规则于 2026-10-25 删除，loopback 被 `bypassPrivateNetworks` 绕过），CLI 只连 3425。General `defaultMode` 在 21:37:44 从 Proxy 改为 Direct，但 Claude Desktop/Helper 的按应用规则仍是 proxy + killSwitch。无论哪条路，最终出口都是 mihomo 7897。

## 二、守卫怎么判断

`guard.sh --once` 每个 tick 做以下检查：

1. **mihomo API**：unix socket 可读，`/configs` 返回 `mode`；记录 `mode`、`mixed-port`、`tun.enable`、`tun.device`、`find-process-mode`。全局 `mode=direct` 直接判为旁路；`find-process-mode=off` 时无法把连接归因到进程，规则审计按"未验证"处理。
2. **TUN 覆盖**：设备存在且有 `inet` 地址；再用 `route -n get` 抽查 `1.1.1.1`、`64.1.1.1`、`128.1.1.1`、`223.5.5.5`，四个探针都必须落到该 TUN 设备。不假定具体的路由表形状（Clash 这里是 `1.0.0.0/8 .. 128.0.0.0/1`，不是字面上的 `0/1`）。API 短暂失败时会用上次确认的设备名，再用 `ifconfig` 与路由复验；API 明确返回 `tun.enable=false` 时不回退。
3. **物理链路**：默认路由所在接口必须 `status: active`；Wi-Fi 关闭/拔网线时即使 TUN 路由还在，也判为断网。
4. **系统代理**：`scutil --proxy` 中 HTTPS / HTTP / SOCKS 任一启用，地址为 `127.0.0.1`，端口在 `7897 7898 7899` 内。
5. **代理健康**：`nc` 连 `127.0.0.1:<mixed-port>`（优先用 mihomo 报告的 `mixed-port`，缺失时用 `PROXY_PORT`）；TUN 已覆盖且控制面正常时默认跳过 HTTP 探测（`HEALTH_UNDER_TUN=0`，探测结果不再决定健康），以保持 tick 在 1 秒级；否则通过代理请求两个 URL（`gstatic generate_204` 与 `api.anthropic.com`），最多两轮；2xx–4xx（407 除外）算可达。
6. **目标进程**：按可执行文件（`ps -p PID -o comm=`）分类，不匹配命令行里的任意子串：`Claude.app` 主进程、Claude Helper 及其 `disclaimer`/crashpad 子进程、`claude-code` CLI（含 Claude-3p 下的 `claude.app`）、`magpie` / `magpie-bun` 网关；`node`/`bun`/`deno` 进程再看参数里是否为 `@anthropic-ai/claude-code`。只排除守卫自己的 `guard.sh`/`install.sh`/`uninstall.sh` 进程。
7. **旁路审计**：对每个目标进程跑 `lsof -nP -iTCP -iUDP -a -p PID`，凡带 `->` 且远端不是 loopback、也不是内网/链路本地地址（`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`fe80::/10`、`fc00::/7`）的 socket，记为外部连接。内网地址本身被 macOS 代理 ExceptionsList 排除，不是 Anthropic 请求；`ps`/`lsof` 不可用时直接判不健康。
8. **规则链审计**：读取 mihomo `/connections`，对 `processPath` 匹配 Claude/magpie/Antify/node/bun 且主机匹配 `CLAUDE_HOST_RE` 的活跃连接检查链：`chains[0] == DIRECT` 记为未代理；链中不含 `REQUIRED_CHAIN`（默认 `🛡️ 静态IP出口`）同样记为未代理（`no-required-exit`）。`node`/`bun` 只在主机匹配时才计入，用来覆盖以 node 形式启动的 CLI。另外报告 Claude/magpie/Antify 进程到 **名单外** 主机的 DIRECT 连接（如 magpie 的国内模型上游），默认只显示 `other direct: N (report only ...)`，不计入健康判定；`KILL_ANY_DIRECT=1` 时按旁路处理。`processPath` 为空的 Claude 主机连接算"未验证"。

判定：

- 健康 = 物理链路 up **且**（TUN 覆盖且控制面正常，或 TCP 可达且 HTTP 探测可达）**且** 没有规则直连/出口不符 **且**（TUN 覆盖 **或**（系统代理已启用 **且** 没有外部连接））**且** 规则审计可以完成、`ps`/`lsof` 可用。
- 出口必须包含 `REQUIRED_CHAIN`；链中缺少该组的一律标成 `no-required-exit` 并按旁路处理。
- **验证不了就不算覆盖。** 还有 Claude 进程在跑时，如果规则链审计无法完成（控制面读不到、缺 `jq`、mihomo 没有进程归因），按不健康处理并走失败阈值；`REQUIRE_CHAIN_AUDIT=0` 才退回"信任 TUN 覆盖"的降级模式。
- **IPv6 也算覆盖的一部分。** TUN 设备必须在 IPv4 与 IPv6 探针上都接住路由；只覆盖 IPv4 的 TUN 不算完全覆盖。
- **系统代理的 ExceptionsList 若包含 Claude/OpenAI 域名（或 `*`）**，系统代理不算这些主机的覆盖。
- TUN 覆盖时，不把外部连接当作旁路：那是 TUN 在正常承载；但 `chains[0] == DIRECT` 的连接仍算旁路。
- 系统代理覆盖但有外部连接 = 应用绕过了代理，立即杀（`BYPASS_KILL_IMMEDIATE=1`）；规则直连同样立即杀。
- 无覆盖、代理不可达、断网：连续失败 `FAIL_THRESHOLD` 个 tick 后杀。
- 本次开机后守卫第一次运行起的前 `STARTUP_GRACE` 秒只记录不杀，给 Clash Verge 留启动时间；直连旁路是例外，发现即杀。

## 三、杀谁、按什么顺序

1. `magpie` / `magpie-bun`（真正的出口网关）先 TERM。
2. 等 1 秒，Claude Desktop 主进程、Claude Helper、`claude-code` CLI TERM。
3. 等 2 秒，重新收集进程，仍在的 KILL。

`KILL_GATEWAY=0` 可把 magpie 排除在杀名单外。`ENFORCE=0` 或 `DRY_RUN=1` 时只写日志，不发信号。`CUT_NETWORK=1` 会额外执行 `networksetup -setairportpower en0 off`，这是整机断网，默认关闭；当前没有 Claude 链进程时不会切网。

杀掉之后，即使代理恢复，守卫也不会自动重启 Claude；需要手动重新打开。这是有意的：恢复前的启动请求仍然不是“经代理”的。

## 四、依赖

macOS 自带 `bash`、`curl`、`nc`、`lsof`、`route`、`netstat`、`sysctl`。另需 `jq`（Homebrew）解析 mihomo API；`install.sh` 会检查并在缺失时拒绝安装。运行期缺少 `jq` 时 `MIHOMO_OK=0`、规则链审计不可用；在 `REQUIRE_CHAIN_AUDIT=1`（默认）下，只要 Claude 进程在跑就会被判为未验证并在两个 tick 后击杀——这是 fail-closed 的预期行为。

## 五、文件

| 文件 | 作用 |
| --- | --- |
| `guard.sh` | 守卫本体；不带参数等于 `--check`；支持 `--check` / `--status` / `--once` / `--loop` / `--simulate=unhealthy\|direct\|bypass`；未知参数或未知模拟模式以退出码 2 拒绝。`--json` 让 `--check`/`--status` 输出 JSON，`--state-dir` 打印实际状态目录 |
| `geo.sh` | 出口 IP 身份：查 `ipinfo.io`，校验后写 `geo.json`，注入 `TZ`、关闭 Claude Code 遥测开关；`--force` 立即刷新，`--print` 只读缓存，`--quiet` 供守卫调用 |
| `identity.sh` | 身份闸门：`apply` 写 `~/.claude/settings.json`（沙箱 + 权限规则，先备份）、`verify` 跑 seatbelt 对照实验、`status`、`revert` |
| `docs/identity-gate.md` | 身份闸门的设计与实测记录：三列通道矩阵、四条被推翻的说法、残余通道 |
| `config.env.example` | 配置模板，安装时复制为 `config.env` |
| `com.swimmingliu.proxyguard.plist` | launchd 模板，每 10 秒跑一次 `--once` |
| `install.sh` | 安装到 `~/Library/Application Support/proxyguard/` 并加载 LaunchAgent；先校验、后替换，加载失败会回滚上一份 `guard.sh`/`geo.sh`/`identity.sh` |
| `uninstall.sh` | 卸载；`--purge` 同时删除配置、状态与日志 |
| `app/main.swift` | 菜单栏可视化软件 ProxyGuard.app 的源码（Swift，Command Line Tools 即可编译） |
| `build-app.sh` | 编译并 ad-hoc 签名到 `dist/ProxyGuard.app` |
| `install-app.sh` | 安装到 `~/Applications/ProxyGuard.app` 并启动 |

运行期路径：

- 配置：`~/Library/Application Support/proxyguard/config.env`
- 上一版守卫：`~/Library/Application Support/proxyguard/guard.sh.prev`（安装失败回滚用，可删）
- 日志：`~/Library/Logs/proxyguard.log`（超过 1 MB 自动截断保留尾部 200 KB）
- 状态：`~/.cache/proxyguard/`（fail 计数、boot id、启动时间、锁；可在配置里用 `STATE_DIR` 改）
- 状态报告：`~/.cache/proxyguard/last_report.json`（每个 `--once` tick 原子覆盖一份，菜单栏软件读它）
- IP 身份：`~/.cache/proxyguard/geo.json`（每 `GEO_REFRESH` 秒刷新；时间、地区、坐标、运营商、时区注入状态）与 `geo_attempt`（上次尝试时间，失败时用于退避）
- Claude Code 设置备份：`~/.claude/settings.json.proxyguard.bak`（首次写入 `TZ`/遥测开关前留一份；`identity.sh revert` 也从这里恢复）
- launchd 输出：`~/Library/Logs/proxyguard.launchd.log` / `.err.log`

## 六、安装

**当前状态：LaunchAgent `com.swimmingliu.proxyguard` 已安装并在运行**（2026-11-16 起，每 10 秒一次 `--once`）。重装会 `bootout` 旧 agent 再加载新的，并重置宽限计时。

先确认当前是健康的，并且你看得懂它会杀什么：

```bash
cd /Users/swimmingliu/data/crackProject/claude-code/proxyguard
bash guard.sh --check
```

退出码 0 表示 `HEALTHY/PROXIED`；1 表示当前不健康（安装后会在阈值后开始杀进程）。

安装：

```bash
bash install.sh
```

安装会先把 `guard.sh`、`geo.sh`、配置和 plist 复制成暂存文件并校验（`bash -n`、`plutil -lint`、装后配置 dry run），然后 `bootout` 旧 agent、重置已配置 `STATE_DIR` 里的状态、原子替换文件、`launchctl bootstrap`；如果加载失败，会把上一份 `guard.sh`、`geo.sh` 和 plist 一起放回并重试，仍失败则以非零退出码告诉你 agent 没有在运行。它不会因为当前状态不健康而拒绝安装。安装还会清空旧 fail 计数/宽限状态，使 30 秒宽限从安装时的首次 tick 重新计算。

> 安装后如果代理正好不可用，先有 30 秒启动宽限；宽限期后连续两个 tick（约 20 秒）就会杀掉 magpie、Claude Desktop，以及正在运行本会话的 Claude Code；一旦发现直连旁路，宽限期内也会立即杀。确认这一点再执行。

`install.sh` 也会把 `identity.sh` 装到同一目录，但**不会自动 apply**：修改 Claude Code 设置是用户的决定。装好后先跑 `./identity.sh verify` 看对照表，再决定是否 `apply`（见 §10.1）。

## 七、验证与测试

单次检查，不杀：

```bash
bash guard.sh --check
bash guard.sh --status
```

模拟三种故障。模拟轮次在取锁和读写状态之前就分流：打印完整报告、`targets` 和 `would-send` 击杀计划，不受阈值和宽限限制，也不修改 fail 计数、`last_run`、`wake_until` 或宽限状态；不加 `--allow-sim-kill` 时不会发信号（仍建议显式 `DRY_RUN=1`）：

```bash
DRY_RUN=1 bash guard.sh --simulate=unhealthy --once
DRY_RUN=1 bash guard.sh --simulate=direct --once
DRY_RUN=1 bash guard.sh --simulate=bypass --once
```

看它打算杀谁：

```bash
tail -n 20 ~/Library/Logs/proxyguard.log
```

验证 launchd：

```bash
launchctl print "gui/$(id -u)/com.swimmingliu.proxyguard" | sed -n '1,25p'
```

## 八、配置

配置是 shell 变量，安装后编辑 `~/Library/Application Support/proxyguard/config.env`，下一个 tick 生效（`--loop` 模式下需要重启循环）。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PROXY_HOST` / `PROXY_PORT` | `127.0.0.1` / `7897` | Clash Verge mixed-port；探测时优先用 mihomo 报告的 `mixed-port` |
| `PROXY_PORTS` | `7897 7898 7899` | 系统代理允许的端口集合 |
| `HEALTH_URLS` | gstatic + api.anthropic.com | 经代理探测的 URL |
| `HEALTH_TIMEOUT` | `5` | 单次 curl 超时（秒）；另加 `--connect-timeout 2` |
| `HEALTH_UNDER_TUN` | `0` | `0` = TUN 覆盖且控制面正常时不再要求代理探测成功；`1` = 始终要求 |
| `WAKE_GRACE` | `15` | 检测到睡眠/唤醒间隙后额外只记录不杀的秒数 |
| `INTERVAL` | `10` | `--loop` 间隔；launchd 的 `StartInterval` 固定为 10 |
| `FAIL_THRESHOLD` | `2` | 连续失败多少个 tick 后杀 |
| `STARTUP_GRACE` | `30` | 本次开机后首次运行起只记录不杀的秒数（直连旁路除外） |
| `ENFORCE` | `1` | `0` = 只记录，不杀 |
| `DRY_RUN` | `0` | `1` = 不杀、不断网，只写 `would-send` |
| `ALLOW_TUN` | `1` | 把 TUN 覆盖视为完全代理（用四个路由探针验证） |
| `VERIFY_CHAINS` | `1` | 读取 mihomo `/connections`，检查规则是否 DIRECT |
| `REQUIRE_CHAIN_AUDIT` | `1` | 审计无法完成（且还有 Claude 进程）时按未验证/不健康处理；`0` = 退回信任 TUN 覆盖 |
| `CLAUDE_HOST_RE` | anthropic/claude/openai/chatgpt | 规则链检查的主机范围 |
| `CHAIN_DIRECT_KILL` | `1` | 规则为 DIRECT 时按旁路处理 |
| `KILL_ANY_DIRECT` | `0` | `1` = Claude 链进程到名单外主机的 DIRECT 连接也算旁路；`0` 只在报告里显示 `other direct` |
| `REQUIRED_CHAIN` | `🛡️ 静态IP出口` | 唯一可接受的出口组；链中没有它即视为未代理。设为空字符串关闭这一要求 |
| `KILL_GATEWAY` | `1` | 是否连 magpie 一起杀 |
| `BYPASS_KILL_IMMEDIATE` | `1` | 发现外部直连/规则直连立即杀，不等阈值 |
| `CUT_NETWORK` | `0` | `1` = 同时关 Wi-Fi（整机） |
| `WIFI_DEVICE` | `en0` | Wi-Fi 设备名 |
| `STATE_DIR` / `LOG_FILE` | `~/.cache/proxyguard` / `~/Library/Logs/proxyguard.log` | 状态与日志路径 |
| `MIHOMO_SOCK_OVERRIDE` | 空 | 手动指定 mihomo 控制 socket；空 = 先用 Clash Verge 每用户路径，再查运行中 mihomo 的 `-ext-ctl-unix` |
| `GEO_ENABLED` / `GEO_REFRESH` | `1` / `600` | 是否维护 IP 身份、刷新间隔（秒） |
| `GEO_ADDRESS` | 空 | 你提供的地址；设置后作为面板“地区”的唯一来源（时间仍按 IP） |
| `GEO_WRITE_CC_ENV` | `1` | 是否写入 Claude Code 的 `TZ` 并强制关闭遥测开关 |

只想观察、不想让它动手时，把 `ENFORCE=0` 或 `DRY_RUN=1` 写进 `config.env`，或直接卸载 LaunchAgent。

## 九、已知边界

- **TUN 模式是唯一严密的模式。** 这里 TUN 同时接管 IPv4 与 IPv6 的全球路由，应用即使忽略系统代理也会被 Clash 接住；守卫用 mihomo API 确认 TUN 与路由存在。
- **只有系统代理、没有 TUN 时，存在检测窗口。** 那个模式下守卫靠 `lsof` 每 10 秒审计一次：一个在两次审计之间建立又关闭的直连可能漏掉，所以“发现直连立即杀”仍不是防火墙级的阻断。要绝对阻止直连，应保持 Clash Verge 的 TUN 开启。
- **Clash 当前 `allow-lan=true`，监听 `*:7897/7898/7899`。** 局域网内其他设备也能使用这个代理；守卫只约束本机的 Claude 进程，不改变 Clash 的监听范围。若不需要，关闭 allow-lan。
- **Claude 派生的子进程不在杀名单。** Claude Desktop 会 spawn `curl`/`ssh` 等；当前 Antify 的 `spawnedProcessesInherit` 把它们转到 Clash 7897。若这条规则被关闭，守卫的 `lsof` 审计看不到它们，需要把它们加入目标匹配或依赖 TUN。
- **进程范围是“按可执行文件匹配的平铺名单”，不是进程树。** `collect_targets` 只读 `ps -axo pid=,comm=`（`guard.sh:506`），按 `kind_of_comm`（`guard.sh:468`）判断命中，不读 ppid/pgid/sess，也不做 `pgrep -P` 递归：Claude 派生的 `zsh`/`bash`/`curl`/`python3` 既不在目标表里，也不会被 `audit_sockets` 逐个 `lsof`（`guard.sh:554`）。击杀同样是逐个 PID（`kill_list`，`guard.sh:835`），杀掉 Claude 主进程后子进程会留下并继续运行。能覆盖到它们的只有两条旁路：(1) TUN 在路由层接管全部出口；(2) Antify 的 `spawnedProcessesInherit` 把它们塞进 7897。两条都不在时，子进程的直连对守卫不可见。
- **“个人信息”（地址/时间）由两层负责：`geo.sh` 注入，`identity.sh` 拦截。** 守卫本身不监听任何系统调用，`geo.sh` 只做注入（`launchctl setenv TZ`，`geo.sh:133`，以及 `~/.claude/settings.json` 的 `env`：`TZ` 与四个遥测开关），面板上的 IP/地区/坐标/时间是读 `geo.json` 的展示值。拦截是另一件事，由 `identity.sh` 写进 Claude Code 的沙箱与权限规则完成（见下一节）。两者都不需要时，闸门默认不启用。
- **只审计 TCP 与已连接的 UDP。** `lsof -iTCP -iUDP` 能看到 TCP 和连向固定远端的 UDP；未连接的 UDP socket 没有远端地址，不在审计范围。Clash TUN 开启时 UDP 同样被接管；TUN 关闭时 QUIC 流可能绕过系统代理。
- **规则直连只覆盖可归因的活跃连接。** 守卫检查 `processPath` 匹配 Claude/magpie/Antify、主机匹配 `CLAUDE_HOST_RE` 的活跃连接；若 mihomo 没有进程归因（`find-process-mode` 关闭或受限），匹配 Claude 主机但 `processPath` 为空的连接会被判为"未验证"并走失败阈值，而不是当作已代理。主机为空、只有 IP、或连接在两次检查之间建立并关闭时仍可能漏掉。需要绝对阻断时保持 TUN，或把 `CLAUDE_HOST_RE` 扩大到实际使用的模型域名。
- **进程审计失败也算不健康。** `ps`/`lsof` 不可用或 `ps` 执行失败时，守卫不会把"没收集到目标"当成"没有 Claude 在跑"，而是直接判为不健康。
- **出口组名是硬编码匹配。** `REQUIRED_CHAIN` 必须与 mihomo 里显示的组名完全一致（含 emoji）；在 Clash Verge 里重命名 `🛡️ 静态IP出口` 会让所有 Claude 连接判为 `no-required-exit` 并被杀，改名前先同步配置。面板的“出口组”一行会去掉名字里的 emoji 再显示，避免和行首的 ✓ 混淆。
- **只承认 Clash 作为出口。** Antify 的上游也是 Clash 7897；如果你以后换成完全不同的代理（不再经过 Clash），守卫会判定无覆盖并杀 Claude。要支持它，需要把该代理的 TUN 设备/本地端口/规则链接入判断。
- **Antify 的过滤器/kill switch 不在守卫的判断里。** 它可能阻断某些流，但守卫只判断“流量是否经 Clash 代理”；Antify 阻断不等于直连泄漏，反之亦然。
- **睡眠唤醒 / Clash 重启**：唤醒后如果代理还没恢复，最多两个 tick（约 20 秒）后开始杀；`STARTUP_GRACE` 只覆盖开机后的第一次启动，不覆盖每次唤醒。
- **内网连接不算旁路。** `10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`fe80::/10`、`fc00::/7` 与 loopback 一样被排除；macOS 的系统代理 ExceptionsList 本来也绕过这些地址，本地 MCP/开发服务不会被误杀。Clash 的 fake-ip 段 `198.18.0.0/15` 同样排除：它是 TUN 内部地址，不是真实出口。
- **mihomo API 不可用时不再默认信任 TUN。** 守卫仍会用上次确认的 TUN 设备 + 实时路由与 IPv6 复验来确认 TUN 覆盖，但规则链审计无法进行；默认 `REQUIRE_CHAIN_AUDIT=1`，只要还有 Claude 进程在跑，"出口组无法验证" 就按不健康处理，两个 tick 后开始杀。设为 `0` 才退回旧的降级模式（TUN 覆盖即可）。
- **睡眠唤醒有 15 秒宽限。** 相邻 tick 间隔超过 60 秒时视为睡眠/唤醒，清零失败计数并给 `WAKE_GRACE` 秒只记录窗口，避免合盖再打开就杀。
- **日志与状态是用户级权限**；`config.env` 会被 `source`，能写这个文件的人能以你的身份执行代码，保持目录权限为当前用户。
- **不修改 Clash 配置、不加防火墙规则、不重启代理**；它只做“检测 + 杀进程”，恢复代理需要你自己或 Clash Verge 完成。

## 十、IP 身份（时间 / 地区 / 位置）

`geo.sh` 把「当前出口 IP 对应的一整套公开信息」固定下来，交给 Claude Code / Claude Desktop 使用，并显示在面板上。它不读设备定位：来源只有出口 IP 查询（默认 `https://ipinfo.io/json`，只经 Clash 混合端口 `127.0.0.1:7897` 发出，没有直连回退）和你在 `config.env` 里写的 `GEO_ADDRESS`。

守卫在本次判定写完后，以独立子进程触发一次（最多每 `GEO_REFRESH` 秒，默认 600；失败也会缓存本次尝试，不会在每个 10 秒 tick 重试，也绝不阻塞判定）：

1. 查询并校验 `ip`、`country`、`timezone`（时区必须在 `/usr/share/zoneinfo` 里存在），任何一项不合法就放弃本次写入，保留上一份；
2. 写 `~/.cache/proxyguard/geo.json`（原子替换）；
3. `launchctl setenv TZ <时区>`——之后启动的 GUI 应用（含 Claude Desktop、由桌面端拉起的 Claude Code）继承该时区；
4. 用 `jq` 合并 `~/.claude/settings.json` 的 `env`：写入 `TZ`，并把 `DISABLE_TELEMETRY`、`DISABLE_ERROR_REPORTING`、`DO_NOT_TRACK`、`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` 强制设为 `"1"`；首次修改前备份为 `settings.json.proxyguard.bak`。保留原文件权限；如果 `settings.json` 是符号链接，改写它指向的文件，链接本身保留；替换失败会明确报错并以非零退出，不会谎报成功。

当前实测：出口 `38.98.190.130`，Las Vegas, Nevada, US，邮编 89158，坐标 36.1750,-115.1372，AS174 Cogent Communications，时区 `America/Los_Angeles`；`launchctl getenv TZ` 已为 `America/Los_Angeles`，Claude Code 设置里的 `TZ` 与遥测开关均已写入。

边界与行为：

- **不改系统时区。** 面板会显示「系统时区：Asia/Shanghai（不修改系统）」。这样只影响 Claude 链的应用环境，不会改整台 Mac 的时钟；需要系统级一致时再手动 `sudo systemsetup -settimezone`。
- **重启后生效。** `launchctl setenv` 和 `settings.json` 的 `TZ` 都作用于新启动的进程；已经在跑的 Claude Desktop / Claude Code 需要重启才会看到新时区。
- **位置以 IP 为准，设备定位从不读取。** 设置了 `GEO_ADDRESS` 时，面板「地区」改为显示你提供的地址（标记为“用户地址”），时间仍跟随 IP；没有设置时显示 IP 的城市/州/国家。
- **遥测开关只覆盖 Claude Code 的设置项。** Claude Desktop 自身的遥测不由这些变量控制；守卫能做的是保证它的流量只能走代理。
- **geo 失败不影响健康判定，也不拖慢判定。** 查询在判定和报告写完之后以独立子进程运行，失败只写日志（`geo_attempt` 记录尝试时间，`GEO_REFRESH` 后再试）；`fail_count`、击杀逻辑完全不受影响，面板显示上一份缓存及其时间。

### 10.1 身份闸门（identity.sh）

`geo.sh` 负责“给什么”，`identity.sh` 负责“不让读什么”。网络层管不到本机读取：Claude Code 能直接读 `/etc/localtime`、`defaults read -g AppleLocale`、`/var/db/locationd`、`ioreg`，这些都必须在内核/权限层关掉，否则注入的 `TZ` 只是一层随时可被绕过的环境变量。

```bash
./identity.sh verify    # 只读对照实验：同一组规则，闸门外 vs 闸门内
./identity.sh apply     # 写入 ~/.claude/settings.json（先备份为 .proxyguard.bak）
./identity.sh status    # 当前闸门状态与残余通道
./identity.sh revert    # 从备份恢复
```

闸门由两条互补的路径组成，缺一不可：

- **Bash / PowerShell / Monitor** 走 Claude Code 官方沙箱。`apply` 打开 `sandbox.enabled`、`failIfUnavailable`、关闭 `allowUnsandboxedCommands`，并把文件型通道写进 `sandbox.filesystem.denyRead`；同时设置 `sandbox.network.httpProxyPort=7897`，让沙箱内的流量走 Clash，并把 `com.apple.trustd.agent` 加进 `sandbox.network.allowMachLookup`（否则 `gh`/`gcloud` 这类 Go CLI 全部校验证书失败）。
- **Read / Grep / Glob 内置工具**绕过 Bash 沙箱（官方文档明说），所以同一份清单一式两份写成 `permissions.deny` 的 `Read(...)` 规则，并打开 `permissions.blockReadsOutsideWorkingDirectories`。

**`settings.json` 能表达的只有文件路径和权限规则。** 序列号、机型名、MAC、主机名走的是 IOKit 与 sysctl，没有注入入口——它们是**已知残余通道**，`permissions.deny` 里的 `Bash(ioreg:*)`、`Bash(system_profiler:*)` 等只在对话内挡一层，脚本可绕过。

**关键设计（每条都来自本机实测，改了会静默失效）：**

- 时区封 `/private/etc/localtime` 这个链接，**不封 zoneinfo 大洲**。zoneinfo 是静态世界库，读某个条目不能反推本机时区；封大洲只会让 `TZ=Asia/Shanghai` 静默变 UTC、`ZoneInfo()` 报错，纯属工具损坏。
- 闸门内若不注入 `TZ`，`date`/`Intl` 全部退化为 **UTC**——这是「本机时区被藏起来」的必然结果，也是可被观察到的矛盾。所以 `apply` 会从 `geo.json` 读时区写进 `env.TZ`，读不到就拒绝启用；当前出口 `America/Los_Angeles`，闸门内稳定输出 `PST -0800`。
- locale / 语言 / 键盘靠 **`denyRead` 整个 `~/Library/Preferences`**。它只在 Claude 的 `(deny default)` 骨架里生效（cfprefsd 不在 mach 白名单，`defaults` 只好直读文件）；单封 `.GlobalPreferences*.plist` 无效。`verify` 因此必须用真实骨架，用 `(allow default)` 会把这一行测成假阴性。
- `sandbox.network.httpProxyPort` **不构成网络隔离**——Claude Code 只在设了 `allowedDomains`/`denyAllNetwork` 时才生成 `(deny network*)`。真正锁死出口的是 Clash 的 TUN（见 §四）。
- **打开沙箱本身有代价**：Keychain 用不了（`gh auth status` 报 token 无效，但 `~/Library/Keychains` 保留在 denyRead 里——数据库文件本来就该挡；要用 `GH_TOKEN`）、`open -a` 失败、Homebrew 的临时文件被拒。git over SSH、python/node 的 TLS 不受影响。

**残余通道**（详见 `docs/identity-gate.md` §4）：MAC 地址（`ifconfig`）、`hostname` / `kern.hostname`（封了会打死 `ps`/`python`/`npm`）、序列号与机型名（IOKit）、以及家目录路径本身携带的用户名。`dscl ... RealName` 已被沙箱挡住。

`install.sh` 会把 `identity.sh` 一并安装到 `~/Library/Application Support/proxyguard/`，但**不会自动 apply**——修改 Claude Code 设置属于用户决定，安装脚本只把工具放到位并打印用法；`uninstall.sh --purge` 会先 `identity.sh revert` 再删除。

## 十一、菜单栏软件（ProxyGuard.app）

可视化层，不重复实现任何检查逻辑。菜单栏一个盾牌图标，颜色表示状态：绿色 = 代理正常，红色 = 未走代理，橙色 = 超过 90 秒没有新报告（守护可能没在跑），灰色 = 守护未安装。报告过期时面板判决变成「现状未知」并转橙，副标题写「报告 N 分钟前 · 上次确认：…」，与图标一致；故障原因同时改用过去时（「曾检测到…」）。

点开是一个浮在菜单栏下方的面板（`NSPanel`，不抢焦点；再点盾牌关闭，应用在前台时 Esc 也可关闭）。面板跟随系统浅色/深色外观实时重绘，不缓存颜色快照；窗口高度受屏幕限制时，卡片主体可滚动，底部按钮栏固定可见，滚动条只在真正滚动时出现（见下）。整个界面只用 SF Symbols 图标（模板图像，随外观着色），没有位图素材：

- 顶部是一枚状态盾徽：绿色 `checkmark.shield.fill` = 代理正常，红色 `exclamationmark.shield.fill` = 未走代理，橙色 `clock.badge.exclamationmark` = 报告过期；旁边是判决、覆盖方式（如 `TUN(utun1024)`）、报告距今多久、连续失败计数，以及“刚刚实时检查”胶囊；
- 八项检查的逐项结果：控制面、TUN 覆盖、系统代理、代理连通、规则审计、出口组、Claude 进程数、外部连接。每行左侧是状态灯：✓ 圆 = 通过，✗ 圆 = 失败（含「未验证按失败处理」），! 圆 = 降级/待确认，– 圆 = 不适用（如 TUN 未覆盖但系统代理已覆盖），ⓘ 圆 = 纯信息（进程数）；中间是分类图标，右侧是文字值（不带第二个图标；失败/告警项的值用语义色，通过项保持普通文字）；一条细线把“有没有覆盖”和“出口对不对”两组分开；
- **IP 身份卡片**：IP、地区/邮编、坐标、运营商、时区与当地时间、系统时区（是否一致）、TZ 注入状态、遥测是否关闭、定位策略（设备定位从不读取），每行带字段图标，底部标注来源与更新时间；
- 故障原因列表（只在不健康时出现，标题带警示图标；健康时整卡隐藏，不占位）；
- Claude 链进程清单（kind + pid + 命令行，按 kinds 配 `macwindow` / `puzzlepiece.extension` / `terminal` / `arrow.left.arrow.right` 图标；名称列按最长 `kind pid` 实测定宽，命令行从左端截断、保留文件名；可见 4 行，更长的列表滚动，标题上注明“列表可滚动”；每行一个 VoiceOver 元素，读作“kind pid 命令”）；不健康时这张卡排在 IP 身份卡之前，因为“哪个进程在直连”才是当时要找的答案；
- 底栏：“立即检查”是唯一的填色主按钮（强调色胶囊，回车键等效），旁边“刷新 IP 身份”“打开日志”“退出 ProxyGuard”三个无边框图标按钮（30pt 点击区，悬停提示与 VoiceOver 标签都是完整动作名）；右侧是“强制执行 / 仅观察”开关，带 `lock.shield` 图标，悬停说明开启后会杀 magpie / Claude 进程；
- 面板永不成为 key window，所以主按钮的填充色是自绘的（`NSButton.bezelColor` 在这种面板里会被画成非活动灰），按钮本身仍是标准 `NSButton`，保留点击、键盘等效与无障碍语义；
- “立即检查”实时跑一次 `guard.sh --status --json`（只读，不杀进程），期间按钮变成“检查中…”并换成循环箭头图标；面板打开时每 10 秒自动刷新一次；
- “刷新 IP”立即跑一次 `geo.sh --force` 并刷新卡片；
- “强制执行 / 仅观察”开关：改 `config.env` 的 `ENFORCE` 并用 `launchctl kickstart -k` 重启守护；关闭强制执行需在 4 秒内再点一次确认（不弹窗、不抢焦点，提示出现在开关右侧）；
- “日志”打开 `proxyguard.log`。

命令行也能打开面板：`~/Applications/ProxyGuard.app/Contents/MacOS/ProxyGuard --show`（写一个触发文件，运行中的实例 0.5 秒内响应）。

数据来源：守护每个 tick 把 JSON 报告原子写入 `last_report.json`；软件每 5 秒读一次文件，不自己轮询代理。所以关掉软件不影响保护，软件只是观察者。

编译与安装（只需 Command Line Tools，不需要 Xcode）：

```bash
cd /Users/swimmingliu/data/crackProject/claude-code/proxyguard
bash build-app.sh        # 产物 dist/ProxyGuard.app
bash install-app.sh      # 装到 ~/Applications 并启动
```

三个无界面自检：`--selftest` 解码当前报告；`--selftest-ui` 离屏构建面板并排版一次，检查底栏宽度、底栏是否始终在面板内、进程列表的可滚动范围，以及 AppKit 滚动条确已移除、滚动胶囊静止时隐藏且可点击穿透、在列表顶/底两端确实贴住可视区顶/底、刷新不误亮、停止滚动后自行消失；`--selftest-motion` 采样 Core Animation 的 presentation 值，检查入场缩放与顶边锚定、主按钮按下/回弹、退出淡出与退出途中重开的连续性（设置 `PROXYGUARD_REDUCE_MOTION=1` 时检查动效全部走瞬时路径）。

动效只有三种：面板入场（220ms 从顶边向下展开 + 淡入，首次打开时头部与卡片按 40ms 错峰上浮）、主动作按下反馈（下沉到 0.965，80ms 按下 / 120ms 回弹）、状态变化的唯一提示（只在数值真的变化且面板可见时播放）；关闭比打开快（140ms，加速曲线），关闭途中再点盾牌会作废这次关闭并从当前透明度续播，不闪没。系统开启“减弱动态效果”时全部直接呈现最终状态。滚动条不是 AppKit 的：两个滚动视图都关掉了 `hasVerticalScroller`，右侧 3pt 胶囊只在内容偏移真的变化时淡入（打开面板而内容溢出时闪一下，之后停 1 秒淡出），静止时不占任何视觉空间，也不拦截点击；位置按可视区在文档中的比例计算，面板主体与进程列表的文档翻转方向不同，两种坐标空间都做了断言。

## 十二、卸载

停止并移除 LaunchAgent，保留配置和日志：

```bash
bash uninstall.sh
```

连同配置、状态、日志一起删除：

```bash
bash uninstall.sh --purge
```

`--purge` 会先执行 `identity.sh revert`（把 `~/.claude/settings.json` 从备份恢复、撤掉身份闸门）再删除目录；不带参数时保留目录，并提示闸门仍在 `~/.claude/settings.json` 里、如何单独撤销。只想撤闸门但保留守卫：

```bash
bash identity.sh revert
```

只想临时停用而不卸载：

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.swimmingliu.proxyguard.plist"
```

或者把 `ENFORCE=0` 写进配置，保留观测日志。菜单栏软件是独立进程，卸载守护不会退出它；要一并移除：

```bash
pkill -f 'ProxyGuard.app/Contents/MacOS/ProxyGuard'
rm -rf "$HOME/Applications/ProxyGuard.app"
```
