# Cloudflare-Omni

[English](#english) | [中文](#中文)

<a id="中文"></a>
## 中文

一个跑在 Cloudflare Workers 上的订阅聚合与转换服务：把多个节点链接和订阅链接整合成一个统一订阅，按客户端自动输出对应格式，并可针对部署在 Cloudflare 上的 edgeTunnel 服务做优选 IP / 优选域名替换。

本项目由 **Muse 全权创建**（代码原创编写）。架构思路参考了上游开源项目 [cmliu/CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB)（作者 cmliu，Apache-2.0 协议；该项目已归档停更，汇聚功能已并入 [edgetunnel](https://github.com/cmliu/edgetunnel)），感谢 cmliu 的开源工作。本项目未逐字复制上游代码。

### 功能

- **聚合**：`LINK`（节点链接）+ `LINKSUB`（订阅 URL）合并为一个订阅；订阅 URL 并行拉取（8 秒超时，单个失败不影响整体）。
- **订阅解析**：支持 base64、明文链接列表、Clash YAML、sing-box JSON 四种订阅格式。
- **协议解析**：vless、vmess、trojan、shadowsocks、hysteria、hysteria2、tuic、snell、anytls、wireguard、socks、http，统一解析为内部节点对象；解析失败的单条跳过并计数。
- **去重**：按 `协议 + 服务器 + 端口 + 凭证` 去重；同名节点自动加后缀。
- **edgeTunnel 优选（核心功能）**：对命中 `EDGETUNNEL_HOSTS`（或内置 `*.trycloudflare.com` / `*.workers.dev`）的节点，可把连接地址替换为优选 IP 或优选域名，同时保留原始域名的 TLS SNI 与 Host 头；替换过的节点名追加 `(优选)`。
- **输出格式**：`base64`（默认）、`raw`、`clash`（原生生成 Mihomo YAML）、`singbox`（原生生成 sing-box JSON）；其它格式（surge / quanx / loon / shadowrocket）可转发到 `SUBAPI` 转换后端，未配置时回退 base64。
- **鉴权**：`TOKEN` 主口令 + 固定访客 token `MD5(TOKEN)` + 按日轮换访客 token `MD5(TOKEN + UTC 日期 YYYY-MM-DD)`；未鉴权只返回落地页，不暴露节点。口令可放在路径里（`/sub/<TOKEN>`、`/admin/<TOKEN>`），也可放在 `?token=` 或 `Authorization: Bearer` 头里。
- **在线优选 IP 列表**：`IPLIST` 配置多个 `.txt` 列表地址（每行一个，如 GitHub raw 链接或别人分享的 IP 列表），每小时拉取一次缓存，自动并入优选候选池（KV 库优先于在线列表）。
- **IP 自动区域识别**：管理页对未标注的 IP 一键识别归属地，标签格式为 `[国旗]-[国家简写]-[城市]-[序号]`，例如 `🇺🇸-US-LAX-01`；带标签的优选 IP 被选中后，节点名直接换成该标签。
- **缓存**：Cache API 缓存聚合结果，TTL 由 `SUBUPTIME`（小时）控制；`?nocache=1` 绕过缓存。
- **健康检查**：`GET /health` 返回 `{"status":"ok"}`。
- **前端**：落地页、订阅页、管理页均支持系统深色模式（`color-scheme: light dark`），表单与表格按无障碍与响应式规范优化。

### 部署

#### 方式一：Dashboard 粘贴（最快）

1. 打开 Cloudflare Dashboard → Workers & Pages → Create → Create Worker。
2. 把 `src/index.js` 的全部内容粘贴进编辑器，点 Deploy。
3. 在 Worker 的 Settings → Variables 里添加环境变量（见下表），至少填 `TOKEN` 和 `LINK`。
4. 访问 `https://<你的 worker 域名>/health`，看到 `{"status":"ok"}` 即部署成功。

#### 方式二：wrangler

```bash
git clone <your-repo-url> cloudflare-omni
cd cloudflare-omni
npm install
# 本地调试：创建 .dev.vars 填入环境变量（不要提交）
npx wrangler dev
# 部署
npm run deploy
```

GitHub Actions 自动部署：push 到 `main` 即触发 `.github/workflows/deploy.yml`，需在仓库 Secrets 里配置 `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`。

### 环境变量

| 变量 | 必填 | 默认 | 说明 |
| --- | --- | --- | --- |
| `TOKEN` | 否 | 空（公开） | 访问口令。留空则无需鉴权。 |
| `LINK` | 否 | 空 | 节点链接与订阅链接，每行一个。 |
| `LINKSUB` | 否 | 空 | 额外的订阅 URL，每行一个。 |
| `SUBAPI` | 否 | 空 | 外部订阅转换后端（如自建 psub），留空则只用内置转换。 |
| `SUBNAME` | 否 | `Cloudflare-Omni` | 订阅文件名。 |
| `SUBUPTIME` | 否 | `6` | 缓存小时数。 |
| `PREFER_IP` | 否 | 空 | edgeTunnel 优选 IP，逗号分隔，取第一个。 |
| `PREFER_DOMAIN` | 否 | 空 | edgeTunnel 优选域名。 |
| `EDGETUNNEL_HOSTS` | 否 | 空 | 视为 edgeTunnel 的域名列表，逗号分隔；内置已含 `*.trycloudflare.com` 与 `*.workers.dev`。 |
| `IPLIST` | 否 | 空 | 在线优选 IP 列表地址，每行一个 `.txt` 链接；每行格式 `ip`、`ip#region` 或 `ip#region#label`。每小时拉取缓存，自动并入优选候选池。 |

### 查询参数

| 参数 | 说明 |
| --- | --- |
| `token` | 访问口令（主口令 / 固定访客 token / 当日访客 token）。也可写在路径里：`/sub/<TOKEN>`。 |
| `target` | 输出格式：`base64`（默认）、`raw`、`clash`、`singbox`、`surge`、`quanx`、`loon`、`shadowrocket`。优先于 User-Agent 自动识别。 |
| `ip` / `preferIp` | 优选 IP，替换 edgeTunnel 节点的连接地址。 |
| `ip=auto` | 从 KV 的 IP 库自动挑选优选 IP（忽略 `PREFER_IP` 环境变量）。 |
| `region` | 配合自动挑选，优先指定地区的 IP（如 `HK`）。 |
| `domain` / `preferDomain` | 优选域名，替换 edgeTunnel 节点的连接地址。`ip` 与 `domain` 都给时 IP 优先。 |
| `nocache` | `=1` 时绕过缓存，强制重新聚合。 |

User-Agent 自动识别：含 `clash` / `mihomo` / `stash` → clash；含 `sing-box` → singbox；含 `surge` → surge；含 `quantumult` → quanx；含 `loon` → loon；含 `shadowrocket` → shadowrocket；其余 → base64。

### edgeTunnel 优选示例

假设你的 edgeTunnel 节点域名是 `edgetunnel.example.com`，优选 IP 为 `104.21.5.6`：

```
https://<worker域名>/sub?token=<TOKEN>&target=clash&ip=104.21.5.6
```

效果：该节点的连接地址改为 `104.21.5.6`，但 TLS SNI 与 Host 头仍为 `edgetunnel.example.com`，节点名变为 `原名(优选)`。也可以用优选域名：

```
https://<worker域名>/sub?token=<TOKEN>&target=clash&domain=cf.example.com
```

或直接在环境变量里配置 `PREFER_IP` / `PREFER_DOMAIN`，则所有请求默认生效。也可以在 `EDGETUNNEL_HOSTS` 里加自己的域名，例如 `EDGETUNNEL_HOSTS=edgetunnel.example.com,node.example.org`。

### KV 存储、管理页与 IP 库

用 Cloudflare KV（绑定名 `OMNI_KV`）持久化配置与 IP 库，改配置不用再重新部署。

#### 创建与绑定

```bash
npx wrangler kv namespace create OMNI_KV
```

把返回的 `id` 填到 `wrangler.toml` 的 `kv_namespaces` 里（替换 `REPLACE_WITH_KV_NAMESPACE_ID`），再部署。也可以在 Dashboard → Workers → 你的 Worker → Settings → Variables → KV Namespace Bindings 里绑定，变量名填 `OMNI_KV`。

不绑定 KV 也可以用：Worker 仍可正常工作，只是配置与 IP 库功能不可用（管理接口写操作返回 503，优选只认环境变量与查询参数）。

#### 管理页

用主口令打开（口令在路径里，`TOKEN` 可为字母、数字、`-`、`_`、`.`、`~` 等非特殊符号的任意字符）：

```
https://<worker域名>/admin/<TOKEN>
```

也可以用 `?token=<TOKEN>` 或 `Authorization: Bearer <TOKEN>`，三者等价。管理页上方是配置表单（各配置项 + 保存，含在线优选 IP 列表 `iplist`），下方是 IP 库管理（表格列出 ip / 地区 / 备注 / 延迟 / 启用，支持单条新增 / 编辑 / 删除、批量导入、导出 JSON），再下方是在线 IP 列表（只读，显示 `IPLIST` 拉取结果与来源地址）。

#### IP 自动区域识别

IP 库里没有备注的 IP 可以一键识别归属地：表格每行有「识别」按钮，新增表单有「识别该 IP 归属地」按钮，另有「一键识别全部未标注 IP」批量处理。识别后标签格式为 `[国旗]-[国家简写]-[城市]-[序号]`，例如 `104.21.0.1`（旧金山）识别为 `🇺🇸-US-SFO-01`，序号按同一国家+城市已有条数递增。识别结果会写回该条的 `region`（国家简写）与 `label`。

带标签的优选 IP 被选中后，节点名直接换成该标签（例如 `🇺🇸-US-LAX-01`），而不是追加 `(优选)`；没有标签时仍追加 `(优选)`。`?ip=` 显式指定的 IP 若在 IP 库/在线列表里有标签，也会用该标签命名。

配置优先级：请求参数 > KV 配置 > 环境变量 > 默认值。KV 里的 token 若存在则作为管理口令与订阅主口令（覆盖环境变量 TOKEN）。

#### 管理 API（均需主口令，`?token=` 或 `Authorization: Bearer <token>`；访客 token 不可用；未配置任何 TOKEN 时返回 403）

| 接口 | 说明 |
| --- | --- |
| `GET /admin` | 管理页 HTML。 |
| `GET /admin/<TOKEN>` | 管理页 HTML（口令在路径里）。 |
| `GET /api/config` | 返回生效配置（KV 与环境变量合并后，token 掩码为 `********`）。 |
| `POST /api/config` | JSON 保存配置子集；`subuptime` 须为 1–168 的整数，其余为字符串或字符串数组。返回保存后的生效配置（token 掩码）。 |
| `GET /api/ips` | 返回 IP 库数组；支持 `?region=` 与 `?enabled=1/0` 过滤。 |
| `POST /api/ips` | JSON 数组，整体替换 IP 库（校验 IP 合法、去重、补 `updatedAt`）。 |
| `PUT /api/ips` | JSON 对象，单条新增或更新（按 ip 匹配）。 |
| `DELETE /api/ips?ip=1.2.3.4` | 删除指定 IP。 |
| `POST /api/ips/import` | `text/plain`，每行一个 IP，格式 `ip`、`ip#region`、`ip#region#label`，批量追加（已存在则跳过），返回 `{added, skipped}`。 |
| `POST /api/ips/detect` | JSON `{"ip": "1.2.3.4"}` 或 `{"ips": [...]}`，识别归属地并返回标签（见上节），失败的 IP 列在 `failed` 里。一次最多 100 个。 |
| `GET /api/ips/online` | 返回 `IPLIST` 在线列表当前拉到的 IP（只读，不存 KV），每条带 `source` 来源地址；支持 `?region=` 与 `?enabled=1/0` 过滤。 |

#### IP 库格式与优选规则

每条：`{ip, region, label, latency, enabled, updatedAt}`。`ip` 为 IPv4/IPv6，`region` 为地区/国家（如 HK/US/JP，可空），`label` 为备注（可空），`latency` 为毫秒数（可空），`enabled` 默认为 `true`，`updatedAt` 为 ISO 时间（保存时自动补）。

自动挑选规则（edgeTunnel 节点，且请求未带 `?ip=` / `?preferIp=`、也未配 `PREFER_IP` 环境变量时）：从优选候选池中挑选。候选池 = KV 的 IP 库 + `IPLIST` 在线列表拉到的 IP（同一 IP 以 KV 库为准）。挑选时优先 `?region=` 指定的地区、仅 `enabled` 的条目、延迟最小者优先、否则取第一条；挑到则按现有优选逻辑替换，带标签的 IP 会把节点名换成标签，否则标注 `(优选)`。`?ip=auto` 可显式要求从候选池自动挑选（忽略 `PREFER_IP` 环境变量）。候选池为空且无 `?ip=` 时行为与原来一致（不替换）。

### 常见问题

**Q: 打开首页只看到落地页，没有订阅？**
A: 未带 `token` 时只返回落地页。请在地址后加 `/sub/你的TOKEN` 或 `?token=你的TOKEN`（或用访客 token）。

**Q: 访客 token 怎么算？**
A: 固定访客 token = `MD5(TOKEN)`；当日访客 token = `MD5(TOKEN + 当天 UTC 日期)`，日期格式 `YYYY-MM-DD`，例如 `MD5(mysecret2026-11-24)`。可用 `echo -n "TOKEN2026-11-24" | md5sum` 计算。

**Q: 上游订阅拉取失败（管理页统计里“订阅失败”不为 0）？**
A: 先确认上游地址本身能打开。特别注意：**订阅地址必须用域名，不能直接写 IP 地址**——Cloudflare Workers 拒绝直接请求 IP 字面地址（Cloudflare 错误 1003 “Direct IP access not allowed”），例如 `http://129.225.156.182:23469/...` 会失败，改成 `http://osaka.bob.kdns.fr:23469/...` 这种域名形式就能正常拉取。端口没有限制，IPv6 字面地址同样会被拦截。

**Q: 订阅刷新后节点数变少了？**
A: 可能是某个上游订阅拉取失败（8 秒超时）或个别节点解析失败。打开已鉴权的首页可看到统计（直连数、订阅成功/失败数、解析失败数）。

**Q: 优选替换后节点连不上？**
A: 优选 IP 必须真实可达且对应服务在监听；同时确认客户端的 SNI 没有被覆盖——本服务会把原始域名写进 SNI（原节点无 SNI 时自动补），不要再手动改 SNI。

**Q: surge / quanx / loon 返回的是 base64？**
A: 这些格式需要 `SUBAPI` 转换后端。未配置 `SUBAPI` 时会自动回退 base64，并在响应头 `X-Fallback: base64` 注明。

**Q: 节点名后面多了 `(优选)` / `(2)` 是什么？**
A: `(优选)` 表示该节点被优选 IP/域名替换过；`(2)`、`(3)` 是同名节点自动加的去重后缀。

### 致谢

- 上游项目：[cmliu/CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB)（作者 cmliu，Apache-2.0）——本项目参考了它的架构思路，感谢 cmliu 的开源工作。
- 本项目由 Muse 全权创建，代码原创编写。

---

<a id="english"></a>
## English

A subscription aggregator & converter running on Cloudflare Workers: merge multiple node links and subscription URLs into one unified subscription, output in the format each client expects, and rewrite edgeTunnel (Cloudflare-hosted) nodes to a preferred IP / domain.

This project was **created entirely by Muse** (the code is original work). Its architecture is inspired by the upstream open-source project [cmliu/CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB) (by cmliu, Apache-2.0; that project is archived, and its aggregation features were merged into [edgetunnel](https://github.com/cmliu/edgetunnel)) — thanks to cmliu for the open-source work. No upstream code was copied verbatim.

### Features

- **Aggregation**: `LINK` (node links) + `LINKSUB` (subscription URLs) merged into one subscription; upstream subscriptions are fetched in parallel (8s timeout each, one failure never aborts the run).
- **Subscription parsing**: base64, plaintext link lists, Clash YAML, and sing-box JSON.
- **Protocol parsing**: vless, vmess, trojan, shadowsocks, hysteria, hysteria2, tuic, snell, anytls, wireguard, socks, http — all parsed into one normalized node object; unparsable lines are skipped and counted.
- **Dedupe**: by `protocol + server + port + credential`; duplicate names get a numeric suffix.
- **edgeTunnel preferred IP / domain (core feature)**: for nodes whose server matches `EDGETUNNEL_HOSTS` (or the built-in `*.trycloudflare.com` / `*.workers.dev`), the connect address can be replaced with a preferred IP or domain while the original domain is kept as TLS SNI and Host header; replaced nodes get a `(优选)` suffix in their name.
- **Output formats**: `base64` (default), `raw`, `clash` (native Mihomo YAML), `singbox` (native sing-box JSON); other formats (surge / quanx / loon / shadowrocket) are forwarded to a `SUBAPI` converter backend, falling back to base64 when it is not configured.
- **Auth**: master `TOKEN`, fixed guest token `MD5(TOKEN)`, and daily rotating guest token `MD5(TOKEN + UTC date "YYYY-MM-DD")`; unauthenticated requests only get a landing page — no nodes are exposed. The token can go in the path (`/sub/<TOKEN>`, `/admin/<TOKEN>`), in `?token=`, or in an `Authorization: Bearer` header.
- **Online preferred-IP lists**: `IPLIST` names one `.txt` list URL per line (e.g. a GitHub raw link or a list shared by someone else); lists are fetched hourly and cached, then merged into the preferred-IP candidate pool (the KV library wins over online entries).
- **IP region auto-detection**: in the admin page, one click detects the location of an unlabelled IP; the label is `[flag]-[country code]-[city]-[serial]`, e.g. `🇺🇸-US-LAX-01`. A picked IP that carries a label renames the node to that label.
- **Cache**: Cache API caches aggregated results, TTL from `SUBUPTIME` (hours); `?nocache=1` bypasses it.
- **Health check**: `GET /health` returns `{"status":"ok"}`.
- **Frontend**: landing, subscription and admin pages follow the system dark mode (`color-scheme: light dark`), with accessible, responsive forms and tables.

### Deployment

#### Option A: paste in the Dashboard (fastest)

1. Cloudflare Dashboard → Workers & Pages → Create → Create Worker.
2. Paste the entire contents of `src/index.js` into the editor and Deploy.
3. Under the Worker's Settings → Variables, add the environment variables (see table below); at minimum `TOKEN` and `LINK`.
4. Visit `https://<your-worker-domain>/health` — `{"status":"ok"}` means it works.

#### Option B: wrangler

```bash
git clone <your-repo-url> cloudflare-omni
cd cloudflare-omni
npm install
# Local dev: create .dev.vars with your variables (do not commit it)
npx wrangler dev
# Deploy
npm run deploy
```

GitHub Actions auto-deploy: pushing to `main` triggers `.github/workflows/deploy.yml`; configure the repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

### Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `TOKEN` | No | empty (public) | Access password. Empty = no auth required. |
| `LINK` | No | empty | Node links and subscription URLs, one per line. |
| `LINKSUB` | No | empty | Extra subscription URLs, one per line. |
| `SUBAPI` | No | empty | External subscription-converter backend (e.g. self-hosted psub). Empty = built-in conversion only. |
| `SUBNAME` | No | `Cloudflare-Omni` | Subscription file name. |
| `SUBUPTIME` | No | `6` | Cache TTL in hours. |
| `PREFER_IP` | No | empty | Preferred IP for edgeTunnel nodes (comma-separated, first one wins). |
| `PREFER_DOMAIN` | No | empty | Preferred domain for edgeTunnel nodes. |
| `EDGETUNNEL_HOSTS` | No | empty | Extra domains treated as edgeTunnel, comma-separated. Built-in: `*.trycloudflare.com` and `*.workers.dev` are always treated as edgeTunnel. |
| `IPLIST` | No | empty | Online preferred-IP list URLs, one `.txt` link per line; each line is `ip`, `ip#region` or `ip#region#label`. Fetched hourly and cached, merged into the preferred-IP candidate pool. |

### Query parameters

| Parameter | Description |
| --- | --- |
| `token` | Access token (master / fixed guest / daily guest). Can also go in the path: `/sub/<TOKEN>`. |
| `target` | Output format: `base64` (default), `raw`, `clash`, `singbox`, `surge`, `quanx`, `loon`, `shadowrocket`. Takes priority over User-Agent detection. |
| `ip` / `preferIp` | Preferred IP, replaces the connect address of edgeTunnel nodes. |
| `ip=auto` | Auto-pick a preferred IP from the KV IP library (ignores the `PREFER_IP` env var). |
| `region` | With auto-pick, prefer IPs from this region (e.g. `HK`). |
| `domain` / `preferDomain` | Preferred domain, replaces the connect address of edgeTunnel nodes. When both `ip` and `domain` are given, IP wins. |
| `nocache` | `=1` bypasses the cache and forces re-aggregation. |

User-Agent auto-detection: `clash` / `mihomo` / `stash` → clash; `sing-box` → singbox; `surge` → surge; `quantumult` → quanx; `loon` → loon; `shadowrocket` → shadowrocket; anything else → base64.

### edgeTunnel preferred IP / domain examples

Suppose your edgeTunnel node is at `edgetunnel.example.com` and the preferred IP is `104.21.5.6`:

```
https://<worker-domain>/sub?token=<TOKEN>&target=clash&ip=104.21.5.6
```

Effect: the node's connect address becomes `104.21.5.6`, while TLS SNI and the Host header stay `edgetunnel.example.com`, and the node name becomes `original name(优选)`. Or use a preferred domain:

```
https://<worker-domain>/sub?token=<TOKEN>&target=clash&domain=cf.example.com
```

You can also set `PREFER_IP` / `PREFER_DOMAIN` as environment variables to apply by default, and add your own domains to `EDGETUNNEL_HOSTS`, e.g. `EDGETUNNEL_HOSTS=edgetunnel.example.com,node.example.org`.

### KV storage, admin page & IP library

Cloudflare KV (binding `OMNI_KV`) persists configuration and the IP library, so settings can change without redeploying.

#### Create and bind

```bash
npx wrangler kv namespace create OMNI_KV
```

Put the returned `id` into the `kv_namespaces` block in `wrangler.toml` (replacing `REPLACE_WITH_KV_NAMESPACE_ID`) and redeploy. Or bind it in Dashboard → Workers → your Worker → Settings → Variables → KV Namespace Bindings, with the variable name `OMNI_KV`.

Without a KV binding the Worker still works, but config and IP-library features are unavailable (management write endpoints return 503; preferred IPs only come from env vars and query params).

#### Admin page

Open with the master token (the token goes in the path; it may contain any characters that are not URL-special, such as letters, digits, `-`, `_`, `.`, `~`):

```
https://<worker-domain>/admin/<TOKEN>
```

`?token=<TOKEN>` and `Authorization: Bearer <TOKEN>` work the same way. The page has a configuration form on top (all settings + save, including the online preferred-IP lists `iplist`), IP-library management below (table of ip / region / label / latency / enabled, with per-row add / edit / delete, bulk import, and JSON export), and a read-only online IP list section showing the `IPLIST` fetch results with their source URLs.

#### IP region auto-detection

Unlabelled IPs in the library can be detected with one click: a "Detect" button per row, a "Detect this IP" button in the add/edit form, and a "Detect all unlabelled" bulk action. The label is `[flag]-[country code]-[city]-[serial]`, e.g. `104.21.0.1` (San Francisco) becomes `🇺🇸-US-SFO-01`; the serial increments within the same country+city group. The result is written back to the entry's `region` (country code) and `label`.

A picked preferred IP that carries a label renames the node to that label (e.g. `🇺🇸-US-LAX-01`) instead of appending `(优选)`; without a label the `(优选)` suffix is still used. An explicit `?ip=` that matches a known IP in the library or an online list also uses that IP's label for the node name.

Config priority: request parameter > KV config > environment variable > default. A token stored in KV becomes both the management password and the subscription master token (overriding the `TOKEN` env var).

#### Management API (all require the master token via `?token=` or `Authorization: Bearer <token>`; guest tokens do not work; 403 when no TOKEN is configured at all)

| Endpoint | Description |
| --- | --- |
| `GET /admin` | Admin page HTML. |
| `GET /admin/<TOKEN>` | Admin page HTML (token in the path). |
| `GET /api/config` | Effective config (KV merged over env vars), token masked as `********`. |
| `POST /api/config` | JSON body, saves a subset of config fields; `subuptime` must be an integer 1–168, others are strings or string arrays. Returns the effective config after saving (token masked). |
| `GET /api/ips` | IP library array; supports `?region=` and `?enabled=1/0` filters. |
| `POST /api/ips` | JSON array, replaces the whole IP library (validates IPs, dedupes, fills `updatedAt`). |
| `PUT /api/ips` | JSON object, adds or updates a single entry (matched by ip). |
| `DELETE /api/ips?ip=1.2.3.4` | Deletes the given IP. |
| `POST /api/ips/import` | `text/plain`, one IP per line, formats `ip`, `ip#region`, `ip#region#label`; appends in bulk (existing entries skipped), returns `{added, skipped}`. |
| `POST /api/ips/detect` | JSON `{"ip": "1.2.3.4"}` or `{"ips": [...]}`, detects locations and returns labels (see above); IPs that fail are listed in `failed`. At most 100 per call. |
| `GET /api/ips/online` | The IPs currently fetched from the `IPLIST` online lists (read-only, not stored in KV), each with its `source` URL; supports `?region=` and `?enabled=1/0` filters. |

#### IP library format and auto-pick rules

Each entry: `{ip, region, label, latency, enabled, updatedAt}`. `ip` is an IPv4/IPv6 address, `region` a region/country (e.g. HK/US/JP, optional), `label` a note (optional), `latency` in milliseconds (optional), `enabled` defaults to `true`, `updatedAt` is an ISO timestamp (filled automatically on save).

Auto-pick rules (edgeTunnel nodes, when the request carries no `?ip=` / `?preferIp=` and no `PREFER_IP` env var is set): pick from the preferred-IP candidate pool, which is the KV IP library plus the IPs fetched from the `IPLIST` online lists (the KV library wins for a duplicate IP). Picking prefers the `?region=` region, only `enabled` entries, lowest latency first, otherwise the first entry; a picked IP is applied with the existing preferred-IP logic, and a labelled IP renames the node to its label instead of marking it `(优选)`. `?ip=auto` explicitly requests an automatic pick from the pool (ignoring the `PREFER_IP` env var). With an empty pool and no `?ip=`, behaviour is unchanged (no replacement).

### FAQ

**Q: The homepage only shows a landing page, no subscription?**
A: Without a `token` only the landing page is returned. Append `/sub/YOUR_TOKEN` or `?token=YOUR_TOKEN` (or a guest token) to the URL.

**Q: How are guest tokens computed?**
A: Fixed guest token = `MD5(TOKEN)`; daily guest token = `MD5(TOKEN + current UTC date)`, date format `YYYY-MM-DD`, e.g. `MD5(mysecret2026-11-24)`. Compute with `echo -n "TOKEN2026-11-24" | md5sum`.

**Q: IP detection fails or returns the wrong city?**
A: Detection tries three free providers in turn (ipwho.is, ipapi.co, ipinfo.io), because Cloudflare's egress IPs are blocked by some of them. City names use common IATA codes (Los Angeles → LAX, San Francisco → SFO); cities outside the built-in map use the uppercased city name. A detected label can be edited by hand before saving.

**Q: An upstream subscription fails to fetch ("订阅失败" is not 0 in the dashboard stats)?**
A: First check that the upstream URL opens at all. Important: **subscription URLs must use a domain name, not a raw IP address** — Cloudflare Workers refuse direct requests to IP literals (Cloudflare error 1003 "Direct IP access not allowed"). For example, `http://129.225.156.182:23469/...` fails, while `http://osaka.bob.kdns.fr:23469/...` fetches fine. Ports are not restricted; IPv6 literals are blocked the same way.

**Q: Fewer nodes after refreshing the subscription?**
A: An upstream subscription may have failed to fetch (8s timeout) or individual nodes failed to parse. The authenticated homepage shows the stats (direct nodes, subscriptions ok/failed, parse failures).

**Q: A node fails to connect after preferred-IP replacement?**
A: The preferred IP must be reachable and actually serving the node. Also make sure the client does not override SNI — this service writes the original domain into SNI (adding it when the node had none), so do not change SNI manually.

**Q: surge / quanx / loon return base64?**
A: Those formats need a `SUBAPI` converter backend. Without `SUBAPI` the service falls back to base64 and marks the response with `X-Fallback: base64`.

**Q: What do the `(优选)` / `(2)` suffixes in node names mean?**
A: `(优选)` means the node was replaced with a preferred IP/domain; `(2)`, `(3)` are automatic suffixes for duplicate names.

### Acknowledgments

- Upstream project: [cmliu/CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB) (by cmliu, Apache-2.0) — this project took architectural inspiration from it; thanks to cmliu for the open-source work.
- This project was created entirely by Muse, and its code is original work.

## License

Apache-2.0 — see [LICENSE](LICENSE).
