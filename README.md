# Cloudflare-Omni

[English](#english) | [中文](#中文)

<a id="中文"></a>
## 中文

一个跑在 Cloudflare Workers 上的订阅聚合与转换服务：把多个节点链接和订阅链接整合成一个统一订阅，按客户端自动输出对应格式，并可针对部署在 Cloudflare 上的 edgeTunnel 服务做优选 IP / 优选域名替换。

### 功能

- **聚合**：`LINK`（节点链接）+ `LINKSUB`（订阅 URL）合并为一个订阅；订阅 URL 并行拉取（8 秒超时，单个失败不影响整体）。
- **订阅解析**：支持 base64、明文链接列表、Clash YAML、sing-box JSON 四种订阅格式。
- **协议解析**：vless、vmess、trojan、shadowsocks、hysteria、hysteria2、tuic、snell、anytls、wireguard、socks、http，统一解析为内部节点对象；解析失败的单条跳过并计数。
- **去重**：按 `协议 + 服务器 + 端口 + 凭证` 去重；同名节点自动加后缀。
- **edgeTunnel 优选（核心功能）**：对命中 `EDGETUNNEL_HOSTS`（或内置 `*.trycloudflare.com` / `*.workers.dev`）的节点，可把连接地址替换为优选 IP 或优选域名，同时保留原始域名的 TLS SNI 与 Host 头；替换过的节点名追加 `(优选)`。
- **输出格式**：`base64`（默认）、`raw`、`clash`（原生生成 Mihomo YAML）、`singbox`（原生生成 sing-box JSON）；其它格式（surge / quanx / loon / shadowrocket）可转发到 `SUBAPI` 转换后端，未配置时回退 base64。
- **鉴权**：`TOKEN` 主口令 + 固定访客 token `MD5(TOKEN)` + 按日轮换访客 token `MD5(TOKEN + UTC 日期 YYYY-MM-DD)`；未鉴权只返回落地页，不暴露节点。
- **缓存**：Cache API 缓存聚合结果，TTL 由 `SUBUPTIME`（小时）控制；`?nocache=1` 绕过缓存。
- **健康检查**：`GET /health` 返回 `{"status":"ok"}`。

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

### 查询参数

| 参数 | 说明 |
| --- | --- |
| `token` | 访问口令（主口令 / 固定访客 token / 当日访客 token）。 |
| `target` | 输出格式：`base64`（默认）、`raw`、`clash`、`singbox`、`surge`、`quanx`、`loon`、`shadowrocket`。优先于 User-Agent 自动识别。 |
| `ip` / `preferIp` | 优选 IP，替换 edgeTunnel 节点的连接地址。 |
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

### 常见问题

**Q: 打开首页只看到落地页，没有订阅？**
A: 未带 `token` 时只返回落地页。请在地址后加 `?token=你的TOKEN`（或用访客 token）。

**Q: 访客 token 怎么算？**
A: 固定访客 token = `MD5(TOKEN)`；当日访客 token = `MD5(TOKEN + 当天 UTC 日期)`，日期格式 `YYYY-MM-DD`，例如 `MD5(mysecret2026-11-24)`。可用 `echo -n "TOKEN2026-11-24" | md5sum` 计算。

**Q: 订阅刷新后节点数变少了？**
A: 可能是某个上游订阅拉取失败（8 秒超时）或个别节点解析失败。打开已鉴权的首页可看到统计（直连数、订阅成功/失败数、解析失败数）。

**Q: 优选替换后节点连不上？**
A: 优选 IP 必须真实可达且对应服务在监听；同时确认客户端的 SNI 没有被覆盖——本服务会把原始域名写进 SNI（原节点无 SNI 时自动补），不要再手动改 SNI。

**Q: surge / quanx / loon 返回的是 base64？**
A: 这些格式需要 `SUBAPI` 转换后端。未配置 `SUBAPI` 时会自动回退 base64，并在响应头 `X-Fallback: base64` 注明。

**Q: 节点名后面多了 `(优选)` / `(2)` 是什么？**
A: `(优选)` 表示该节点被优选 IP/域名替换过；`(2)`、`(3)` 是同名节点自动加的去重后缀。

---

<a id="english"></a>
## English

A subscription aggregator & converter running on Cloudflare Workers: merge multiple node links and subscription URLs into one unified subscription, output in the format each client expects, and rewrite edgeTunnel (Cloudflare-hosted) nodes to a preferred IP / domain.

### Features

- **Aggregation**: `LINK` (node links) + `LINKSUB` (subscription URLs) merged into one subscription; upstream subscriptions are fetched in parallel (8s timeout each, one failure never aborts the run).
- **Subscription parsing**: base64, plaintext link lists, Clash YAML, and sing-box JSON.
- **Protocol parsing**: vless, vmess, trojan, shadowsocks, hysteria, hysteria2, tuic, snell, anytls, wireguard, socks, http — all parsed into one normalized node object; unparsable lines are skipped and counted.
- **Dedupe**: by `protocol + server + port + credential`; duplicate names get a numeric suffix.
- **edgeTunnel preferred IP / domain (core feature)**: for nodes whose server matches `EDGETUNNEL_HOSTS` (or the built-in `*.trycloudflare.com` / `*.workers.dev`), the connect address can be replaced with a preferred IP or domain while the original domain is kept as TLS SNI and Host header; replaced nodes get a `(优选)` suffix in their name.
- **Output formats**: `base64` (default), `raw`, `clash` (native Mihomo YAML), `singbox` (native sing-box JSON); other formats (surge / quanx / loon / shadowrocket) are forwarded to a `SUBAPI` converter backend, falling back to base64 when it is not configured.
- **Auth**: master `TOKEN`, fixed guest token `MD5(TOKEN)`, and daily rotating guest token `MD5(TOKEN + UTC date "YYYY-MM-DD")`; unauthenticated requests only get a landing page — no nodes are exposed.
- **Cache**: Cache API caches aggregated results, TTL from `SUBUPTIME` (hours); `?nocache=1` bypasses it.
- **Health check**: `GET /health` returns `{"status":"ok"}`.

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

### Query parameters

| Parameter | Description |
| --- | --- |
| `token` | Access token (master / fixed guest / daily guest). |
| `target` | Output format: `base64` (default), `raw`, `clash`, `singbox`, `surge`, `quanx`, `loon`, `shadowrocket`. Takes priority over User-Agent detection. |
| `ip` / `preferIp` | Preferred IP, replaces the connect address of edgeTunnel nodes. |
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

### FAQ

**Q: The homepage only shows a landing page, no subscription?**
A: Without a `token` only the landing page is returned. Append `?token=YOUR_TOKEN` (or a guest token) to the URL.

**Q: How are guest tokens computed?**
A: Fixed guest token = `MD5(TOKEN)`; daily guest token = `MD5(TOKEN + current UTC date)`, date format `YYYY-MM-DD`, e.g. `MD5(mysecret2026-11-24)`. Compute with `echo -n "TOKEN2026-11-24" | md5sum`.

**Q: Fewer nodes after refreshing the subscription?**
A: An upstream subscription may have failed to fetch (8s timeout) or individual nodes failed to parse. The authenticated homepage shows the stats (direct nodes, subscriptions ok/failed, parse failures).

**Q: A node fails to connect after preferred-IP replacement?**
A: The preferred IP must be reachable and actually serving the node. Also make sure the client does not override SNI — this service writes the original domain into SNI (adding it when the node had none), so do not change SNI manually.

**Q: surge / quanx / loon return base64?**
A: Those formats need a `SUBAPI` converter backend. Without `SUBAPI` the service falls back to base64 and marks the response with `X-Fallback: base64`.

**Q: What do the `(优选)` / `(2)` suffixes in node names mean?**
A: `(优选)` means the node was replaced with a preferred IP/domain; `(2)`, `(3)` are automatic suffixes for duplicate names.

## License

Apache-2.0 — see [LICENSE](LICENSE).
