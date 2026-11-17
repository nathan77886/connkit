# Protocol settings and MCP tools

All tools use a registered `connection_id`; callers cannot replace the target credentials or proxy route. Every call reloads connection grants and encrypted settings. Settings are entered as JSON on the Connections page. Editing metadata with a blank settings field preserves the existing settings; replacing settings replaces the complete object.

Results are limited to 1 MiB of serialized JSON. Default result count is 100, maximum 1,000. Calls default to 30 seconds; set `timeout_seconds` between 1 and 120. Truncated results explicitly report `truncated`. A single native driver value can occupy more memory before the serialized result limit is checked; these limits are not a sandbox for hostile servers.

A configured connection authorizes its supported operations for callers who have access to that connection. There are no per-connection read/write, shell-execution or desktop-input switches. The calling agent chooses whether to inspect or modify according to the user's task instructions; ConnKit does not interpret prompts. Target database roles, Redis ACLs, MongoDB roles, Kubernetes RBAC, SSH accounts and cloud OAuth scopes remain effective. Legacy `allow_write`, `allow_exec` and `allow_rdp_input` settings are ignored. No tool automatically retries a potentially completed write.

## SQL: SQLite, MySQL and PostgreSQL

SQLite:

```json
{"path":"/targets/example.db"}
```

The file must already exist at an absolute path, without a proxy. Mount target files separately from the configuration volume. ConnKit refuses its own configuration database, including symlink and hardlink aliases. `db_query`, `db_tables` and `db_schema` open in read-only/query-only mode and use an SQLite authorizer to deny mutation, attachment and extension loading.

MySQL / PostgreSQL:

```json
{"host":"db.example.net","port":5432,"database":"app","username":"agent","password":"replace-me","tls":true}
```

Omit `port` for the default (3306 or 5432). Optional `ca_pem`, `client_cert_pem`, and `client_key_pem` support a private CA and client authentication. With TLS enabled, server identity verification is mandatory. Both drivers route TCP connections through the selected proxy. PostgreSQL hostname resolution is left to the route; SOCKS5/CONNECT can resolve at the proxy. Each call creates and closes its own pool, so changes take effect immediately.

| Tool | Arguments beyond connection_id |
| --- | --- |
| `db_tables` | Optional `limit` |
| `db_schema` | `table`, optional `limit` |
| `db_query` | `query`, `params` array, optional `limit` |
| `db_execute` | `query`, `params` array |

Queries run inside read-only transactions on MySQL and PostgreSQL; SQLite has separate driver enforcement. This does not make a privileged target account safe for arbitrary SQL or functions with external side effects. The database account determines privileges; callers choose `db_query` or `db_execute` according to the task. Multiple statements are disabled by the MySQL driver and PostgreSQL prepared statement mode. JSON integer parameters are decoded exactly into int64; larger integers must be supplied as explicit strings. Decimal parameters are passed as decimal strings to avoid float64 rounding. Placeholders retain native syntax: `?` for SQLite/MySQL and `$1`, `$2` for PostgreSQL. No target schema migration occurs.

Example: `{"connection_id":1,"query":"SELECT id, name FROM users WHERE id = $1","params":[42],"limit":20}`.

## SSH and SFTP

```json
{"host":"server.example.net","port":22,"username":"agent","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n...","host_key":"ssh-ed25519 AAAA..."}
```

A pinned `host_key` is required. `password` is an alternative to `private_key`; encrypted private keys use `private_key_passphrase`.

- `ssh_exec`: `command` string. Returns bounded stdout/stderr, exit code and truncation flag. Arbitrary shell commands carry the permissions of the SSH account.
- `sftp_read`: `path`; returns at most 512 KiB as base64 with a truncation flag.
- File upload uses the separate [S3-staged transfer tools](file-transfers.md).

`connection_test` performs SSH authentication without executing a command; its response explicitly says the operation was not tested.

## HTTPS

```json
{"base_url":"https://api.example.net/v1/","token":"replace-me","headers":{"Accept":"application/json"}}
```

`https_request` accepts a relative `path` (including query string), `method`, and text `body`. Use `items?limit=20` under a `/v1/` base. Absolute URLs, different origins and paths escaping the configured base are rejected. Authentication is configured by the operator (`token`, `username`/`password`, or `headers`); callers cannot inject headers. Optional CA/client certificate fields use the SQL TLS format. Redirects return their status without being followed. Response headers are restricted to content type/length, ETag and last-modified; cookies and authorization headers are excluded.

GET, HEAD, OPTIONS, POST, PUT, PATCH and DELETE are available on authorized connections. A server can still implement side effects on GET; choose endpoints and target credentials accordingly. HTTP status is returned even for errors; check both status and content.

`connection_test` uses HEAD at the base URL by default. Set `test_path` to a relative read endpoint to perform an authenticated GET there instead. The configured base-path/origin limits still apply. The upstream status and body are returned unchanged: HTTP 200 alone does not prove API success.

### Cloudflare API Token (HTTPS)

For an existing scoped API token, use the `https` adapter and `https_request`. This is separate from the official MCP OAuth connection below. Register an API token in encrypted connection settings:

```json
{"base_url":"https://api.cloudflare.com/client/v4/","test_path":"user/tokens/verify","token":"replace-me","headers":{"Accept":"application/json","Content-Type":"application/json"}}
```

`connection_test` now calls `GET /client/v4/user/tokens/verify`. Require HTTP 200, `success:true`, and `result.status:active`. This confirms token validity, not permissions for every product. Use `zones?per_page=50` and inspect each zone's `permissions`; follow `result_info` pagination. DNS records use `zones/<zone_id>/dns_records?per_page=50`.

For example, a DNS create uses `https_request` with `method:POST`, `path:zones/<zone_id>/dns_records`, and a JSON `body`. Registration does not authorize changes to arbitrary domains. DNS read/edit scope does not grant Workers, Pages, Tunnel, or account-level custom-domain permissions. The upstream token remains the final scope boundary. Do not test write permissions by creating or modifying production DNS records; inspect granted permissions instead.

For a legacy Global API Key, configure encrypted `headers` containing `X-Auth-Email` and `X-Auth-Key` instead of `token`, and choose a permitted read probe such as `zones?per_page=1`. Prefer scoped API tokens. This HTTPS Token connection has no OAuth renewal; expired credentials return the upstream error without direct fallback or retries.

References: [Token verification](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/), [API keys](https://developers.cloudflare.com/fundamentals/api/get-started/keys/).

### Cloudflare official MCP (browser OAuth)

Create a **new** connection with type `cloudflare_mcp`. No API token or endpoint is entered:

```json
{"timeout_seconds":30}
```

Save it, click **Authorize**, then **Sign in / authorize**. ConnKit redirects the current browser tab to the same official endpoint used by Codex: `https://mcp.cloudflare.com/mcp`. Choose the requested DNS/R2 permissions in the authorization dialog. ConnKit validates them against official discovery metadata and requests `offline_access` when advertised so the grant can be renewed. Cloudflare handles login and consent; its authorization screen determines the account and product permissions. This does not import Codex's cached credentials or reuse a DDNS token.

The redirect URI is the Admin browser origin plus `/oauth/cloudflare/callback`; keep the same origin and browser tab throughout the flow. Use an HTTPS Admin origin when available. Localhost and explicit private-IP HTTP origins are supported for LAN installations, subject to Cloudflare accepting the registered redirect URI. No public callback listener is required: the browser returns to Admin, which completes the exchange through its authenticated API. Each flow expires after ten minutes, is tied to the initiating Admin session, and uses S256 PKCE and one-use state. A new flow for the same connection replaces the previous flow.

Credentials, refresh tokens and pending flows are encrypted in ConnKit's shared configuration store. Refresh is persisted and serialized across Admin/MCP instances; all upstream traffic uses the connection's current proxy route. Callback codes are removed from browser history, and the bundled Nginx callback location disables query-string access logging and referrers. Apply equivalent logging/referrer rules to any additional reverse proxy. Disconnect removes both saved credentials and pending flows; revoke the app in Cloudflare itself to revoke the upstream grant. Deleting a connection removes its local OAuth data.

| Tool | Input and behavior |
| --- | --- |
| `cloudflare_tools` | `connection_id`, optional `page_cursor`; returns upstream tool schemas and `nextCursor` |
| `cloudflare_call` | `connection_id`, `tool_name`, `tool_arguments` (JSON object); returns the upstream MCP result, including `isError` |
| `connection_test` | Initializes the official MCP and lists tools using saved OAuth credentials |

MCP tool calls use the connection's saved OAuth grant without additional write/execute flags. The calling agent follows the user's task scope; upstream Cloudflare account/product permissions still apply. Existing connection grants, anonymous-listener policy, time/output bounds and metadata-only call audit still apply. Credentials, code and arguments are not recorded in the audit. Remote calls and token exchanges are not retried automatically. Expired or revoked grants require renewed browser authorization if refresh fails.

Tool discovery proves MCP authentication only. After authorization, inspect the actual visible zones and R2 accounts through the official tools and confirm `coinpaas.com` and the intended account. Do not change DNS, R2 bindings or application configuration merely to test permissions. Existing HTTPS Token connections remain separate and are not converted or overwritten.


## 1Panel v2

The `onepanel` connection type uses a registered panel origin, credentials and proxy route. This is the panel HTTP API/WebSocket protocol, independent of the server's SSH credentials.

```json
{"base_url":"https://panel.example:8090","entrance":"private-entry","username":"panel-user","password":"replace-me","allow_http":false,"timeout_seconds":30}
```

Use the origin only in `base_url`; put the security entrance path in `entrance`. HTTPS verifies the server certificate; optional `ca_pem`, `client_cert_pem` and `client_key_pem` use the normal TLS configuration. A legacy HTTP panel requires `allow_http:true`; this permits unencrypted HTTP/WS only for this connection and never changes other protocol adapters. Redirects are refused, and both API and WebSocket traffic use the configured proxy without direct fallback.

Authentication options, in priority order:

- `api_key`: the panel's API key, signed with the timestamp/token scheme required by 1Panel. MD5 is used only for this upstream wire protocol.
- `session_cookie`: an existing authenticated browser cookie header, encrypted with the other settings. Renew it when the panel session expires.
- `username` and `password`: 1Panel v2 browser login with the panel public-key cookie and RSA-wrapped AES password encryption. A private cookie jar is created for each invocation; no cookies, passwords or upstream error bodies are returned. CAPTCHA/MFA challenges fail explicitly; the adapter does not bypass them or automatically retry login. Use an API key or authenticated session cookie for such panels.

| Tool | Arguments beyond connection_id |
| --- | --- |
| `connection_test` | Authenticates and performs a bounded `containers/search` read |
| `onepanel_request` | Relative API path (e.g. `containers/search`), `method`, optional JSON `body` |
| `onepanel_logs` | Container name/ID in `container`, optional `limit` (tail lines, max 1000); last 15 minutes, no follow |
| `onepanel_exec` | Container ID in `container`, shell command in `command` |

Panel API and container commands use the registered account permissions. Authentication and terminal paths are reserved for the protocol adapter and cannot be called through `onepanel_request`. API-key and anonymous-listener connection grants still apply before any upstream request. ConnKit does not create a least-privilege account in the upstream panel.

The terminal tool opens `/bin/sh` inside the chosen container through the panel WebSocket. It returns bounded combined PTY output and the shell exit code only after receiving a unique completion marker. Disconnects, timeouts and output overflow before that marker are **unknown command outcomes**: no automatic retry, and closing the socket does not guarantee the upstream command stopped. Interactive host terminals, file uploads, 1Panel v1 and CAPTCHA solving are not implemented. Reading a container file uses POST `containers/files/content` with a JSON body such as `{"containerID":"...","path":"/app/main.py"}`. Responses can contain target secrets; metadata-only auditing does not persist response bodies or submitted commands.

## Redis

```json
{"host":"redis.example.net","port":6379,"database":"0","username":"agent","password":"replace-me","tls":true}
```

- `redis_scan`: optional `cursor`, `pattern`, `limit`; returns keys and next cursor. Redis COUNT is a hint and may return more keys. Continue until the cursor is zero.
- `redis_read`: `command`, `args` strings. Supported commands: TYPE, EXISTS, TTL, PTTL, STRLEN, LLEN, SCARD, ZCARD, HLEN, bounded GETRANGE (nonnegative start/end), HGET.
- `redis_command`: arbitrary `command` and `args`. Use a constrained Redis ACL.

Standalone Redis is supported. Cluster/Sentinel discovery and streaming commands are not provided. Driver command retries are disabled. TLS is applied inside the route-aware dialer, with certificate and hostname verification.

## MongoDB

```json
{"uri":"mongodb://mongo.example.net:27017/?authSource=admin","database":"app","username":"agent","password":"replace-me","tls":true}
```

Use `mongodb://`; `mongodb+srv://` is rejected until DNS discovery routing is implemented. Credentials can be included in the encrypted URI. When using separate `username`/`password`, the configured `database` is used as the authentication source; use URI credentials for a separate authSource. Native topology node connections all use the route dialer. Invalid-certificate/hostname TLS options are rejected. Driver read and write retries are disabled.

Tools: `mongo_collections`, `mongo_find`, `mongo_count`, `mongo_aggregate`, `mongo_insert`, `mongo_update`, `mongo_delete`.

Find/count use `collection` and optional `filter` as an Extended JSON string. Find also accepts `limit`. Aggregate uses a `pipeline` Extended JSON array string and supports `$out` and `$merge`. Output stages remain last; the response row limit does not limit documents written by a pipeline. Output documents use canonical Extended JSON strings. Insert uses `document`; update uses `filter` plus an update-operator `document`; delete uses `filter`. Update/delete affect one matching document.

## Kubernetes

```json
{"base_url":"https://kubernetes.example.net:6443/","token":"replace-me","ca_pem":"-----BEGIN CERTIFICATE-----\n..."}
```

Use a service-account token or client certificate configured directly. Kubeconfig executable authentication plugins are not executed.

- `k8s_get`: `path`, e.g. `/api/v1/namespaces/default/pods`. List requests use a 100-resource limit; follow the server's `metadata.continue` token in a subsequent path query.
- `k8s_logs`: exact pod `/log` path; caps tail lines and bytes, without following.
- `k8s_apply`: exact resource path and YAML/JSON `body`; uses server-side apply with field manager `connkit`, without forcing ownership conflicts.
- `k8s_delete`: exact resource path.

Only `/api/`, `/apis/` and `/version` paths are accepted. Proxy, exec, attach and portforward subresources are rejected. Watch/follow streams are disabled. Kubernetes RBAC controls accessible namespaces, resources and verbs. The adapter returns API status and body for the caller to inspect; HTTP 403 does not count as business success even though the transport completed.

## RDP

RDP uses a headless FreeRDP 2 worker bundled into the Admin and MCP images. No extra service or exposed backend port is needed. Credentials enter the worker over a private pipe; backend logs are discarded. Every network connection from the worker is restricted to its loopback relay. The relay uses the existing route dialer, including direct, SOCKS5, HTTP/HTTPS CONNECT and SSH proxy chains. Server redirection cannot replace that route.

Encrypted connection settings:

```json
{"host":"windows.example.net","port":3389,"username":"operator","password":"replace-me","domain":"","certificate_sha256":"64-hexadecimal-character-leaf-certificate-sha256","timeout_seconds":30}
```

The SHA-256 pin must be obtained and confirmed through a trusted channel before saving. Self-signed certificates are supported by explicit leaf-certificate pinning. All certificates, including CA-issued certificates, must match the saved pin. Pinning is the trust anchor; it does not perform PKI hostname/expiry validation. Certificate changes fail closed; there is no automatic acceptance or insecure mode. Domain is optional; use the actual Windows account, without guessing.

`connection_test` always performs TCP, X.224 RDP negotiation and pinned TLS verification. Its result separates `tcp_connected`, `protocol_negotiated`, `selected_protocol`, `tls_verified`, `user_authenticated` and `desktop_session`. Missing username or password yields `stage: negotiated_unauthenticated`, `credentials_missing: true`, and `user_authenticated: false`. When both credentials exist, FreeRDP performs NLA in authentication-only mode, then exits; success returns `stage: authenticated` and **does not request a desktop**. Legacy unencrypted RDP and non-NLA user authentication are not supported. Failures distinguish missing pin/credentials, route/TCP, negotiation, certificate mismatch, TLS failure, backend authentication/connection failure and timeout. Some FreeRDP errors combine authentication and connection failure; a numeric FreeRDP status is included without upstream logs.

Every desktop tool requires `connection_id`. The only optional opening parameters are resolution; callers cannot supply an address, credential, proxy, backend command or environment.

| Tool | Parameters beyond connection_id | Result |
| --- | --- | --- |
| `rdp_open` | `width` (default 1024, 640–1280), `height` (default 768, 480–1024) | Private `session_id`, confirmed authentication/desktop activation, limits and input permission |
| `rdp_screenshot` | `session_id` | `mime_type: image/png`, `data_base64`, actual FreeRDP framebuffer source |
| `rdp_input` | `session_id`, `action`, action-specific parameters below | `input_sent`; this confirms submission, application effect needs observation |
| `rdp_close` | `session_id` | `closed`; disconnects and reaps the worker, without forcing Windows logoff |

Input is available to callers authorized for the desktop session. Actions: `mouse_move` with `x,y`; `mouse_button` with `x,y,button` (`left`, `right`, `middle`) and `down` boolean; `key` with set-1 `scan_code` (1–511, extended bit 0x100) and `down`. Send key/button releases explicitly. Text paste, clipboard, audio, drive redirection and automatic reconnect are not provided. A screenshot excludes the separately transmitted cursor image. A session with no received desktop frame returns a clear error rather than a placeholder image; screenshot can then be retried. Do not automatically retry input with an unknown outcome.

Sessions bind to the API-key identity or, on the anonymous listener, the immediate peer IP, plus the connection. Anonymous callers from the same peer IP share that identity; use API keys for distinct users. Permissions are checked on each call. A one-second sweeper rechecks grants, key expiry, saved anonymous CIDRs, connection settings and proxy-chain changes, and closes revoked sessions. An active call is bounded by the operation timeout and may finish before sweep cleanup. Default operation timeout is 30s (configured range 1–120s), idle expiry 120s, absolute session lifetime 600s. Maximum four desktops per MCP process, two per caller, 1280×1024 framebuffer, 700,000 PNG bytes and 1 MiB serialized result. Oversized screenshots fail explicitly. A closed or disconnected session cannot be reopened by its old ID. Process shutdown closes all workers and route sockets. The process-wide Compose limits are 768 MiB RAM, two CPUs and 128 PIDs; the image health check checks the database-backed MCP health endpoint. FreeRDP is a per-session child process rather than a persistent backend container.

Example MCP `tools/call` parameter objects:

```json
{"name":"connection_test","arguments":{"connection_id":3}}
{"name":"rdp_open","arguments":{"connection_id":3,"width":1024,"height":768}}
{"name":"rdp_screenshot","arguments":{"connection_id":3,"session_id":"<returned-session-id>"}}
{"name":"rdp_input","arguments":{"connection_id":3,"session_id":"<returned-session-id>","action":"mouse_move","x":480,"y":360}}
{"name":"rdp_close","arguments":{"connection_id":3,"session_id":"<returned-session-id>"}}
```

Saving changed connection settings invalidates existing sessions. Reopen after changing settings. Do not include credentials or screenshots in audit logs; existing metadata-only MCP audit applies to all four tools.

## Management and audit

The Admin UI provides connection tests, editable API key grants/expiry/enabled state, anonymous listener CIDRs and a call list. Saved CIDRs take effect on the next request and intersect with process `CONNKIT_MCP_TRUSTED_CIDRS`; immediate TCP peer addresses are used. Empty CIDR lists add no restriction.

`connection_test` is also available through MCP. It performs database/Redis/MongoDB ping, SSH authentication, HTTPS HEAD or Kubernetes `/version`. Its response shows what was actually checked. Real queries, commands and application behavior require separate acceptance.

Every MCP tool call persists actor/key ID, connection ID (where supplied/resolvable), tool name, duration and status. Arguments, credentials, upstream error text and result bodies are excluded. Calls are recorded before execution; a crash can leave `running`. A canceled call is marked `unknown`; an error response can still follow a completed remote mutation. Inspect target state before retrying. Calls are listed in descending ID order, 100 at a time, with `before` pagination. Retention/automatic deletion is not implemented.

## Remaining work and verification boundary

Kubernetes exec/port-forward/watch, MongoDB SRV, Redis Cluster/Sentinel, structured protocol-specific settings forms, schema validation at save time, connection groups and per-tool key grants remain future work.

Automated local tests cover RDP negotiation/TLS pinning, missing credentials, authentication-worker failure, timeout and cleanup, session ownership, input validation, count/idle limits and revocation, plus SQLite reads/writes, parameter binding, output limits, configuration-file isolation, HTTPS with real TLS fixtures, target restrictions, redirects, proxy failure without fallback, MCP tool registration/audit, live CIDR policy, key lifecycle, proxy chains and S3/SSH file delivery. Run `./scripts/test-native-fixtures.sh` to create disposable loopback-only MySQL and Redis containers, test native driver authentication/operations and permissions, then remove the fixtures. It requires Docker and never uses existing database services.

Tests use isolated fixtures, not the operator's real databases, Kubernetes cluster or cloud bucket. Validate target accounts, proxy routes, provider compatibility and application results before deployment.

### Alibaba Cloud RPC (HTTPS)

Use `type: https`, a regional root endpoint, and encrypted `aliyun_rpc` settings:

```json
{"base_url":"https://ecs.cn-shanghai.aliyuncs.com","aliyun_rpc":{"service":"ecs","region_id":"cn-shanghai","access_key_id":"...","access_key_secret":"..."}}
```

`service` supports `ecs`, `vpc`, and `hbr`. Each connection fixes its region, endpoint and API version. Optional `security_token` supports an existing STS session; expiry is returned by the upstream API, without credential refresh or retries. Use a RAM credential with the permissions required by the task.

Call `https_request` with a query path such as `?Action=DescribeInstances&InstanceIds=%5B%22i-example%22%5D`. ConnKit signs each request using Alibaba Cloud RPC signature v1.0 (HMAC-SHA1), timestamp and random nonce. Actions requested by the caller are signed without a read-only allowlist; upstream RAM permissions decide what is allowed. GET and POST are supported with parameters in the URL query. Request bodies, duplicate query parameters, credential/region/version overrides and alternate endpoints are rejected. The HTTP method is included in the RPC signature. GET is not treated as proof that an Alibaba Cloud action is read-only.

`connection_test` performs `DescribeRegions` for ECS/VPC and `DescribeVaults` for HBR. Inspect the returned HTTP status and JSON `Code`/`Success`; a successful connection test is not backup acceptance. Transport errors omit the signed URL. Existing proxy, TLS, response size limits and metadata-only auditing apply.
