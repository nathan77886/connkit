# Protocol settings and MCP tools

All tools use a registered `connection_id`; callers cannot replace the target credentials or proxy route. Every call reloads connection grants and encrypted settings. Settings are entered as JSON on the Connections page. Editing metadata with a blank settings field preserves the existing settings; replacing settings replaces the complete object.

Results are limited to 1 MiB of serialized JSON. Default result count is 100, maximum 1,000. Calls default to 30 seconds; set `timeout_seconds` between 1 and 120. Truncated results explicitly report `truncated`. A single native driver value can occupy more memory before the serialized result limit is checked; these limits are not a sandbox for hostile servers.

`allow_write` defaults to false. `allow_exec` defaults to false and permits arbitrary SSH or Redis commands when enabled. These are connection-wide grants: every caller authorized for that connection receives its enabled capabilities. Use separate connections and target accounts when callers need different permissions. SQL database roles, Redis ACLs, MongoDB roles, Kubernetes RBAC and SSH accounts remain the final permission boundary. No tool automatically retries a potentially completed write.

## SQL: SQLite, MySQL and PostgreSQL

SQLite:

```json
{"path":"/targets/example.db","allow_write":false}
```

The file must already exist at an absolute path, without a proxy. Mount target files separately from the configuration volume. ConnKit refuses its own configuration database, including symlink and hardlink aliases. Query connections open in read-only/query-only mode and use an SQLite authorizer to deny mutation, attachment and extension loading.

MySQL / PostgreSQL:

```json
{"host":"db.example.net","port":5432,"database":"app","username":"agent_reader","password":"replace-me","tls":true,"allow_write":false}
```

Omit `port` for the default (3306 or 5432). Optional `ca_pem`, `client_cert_pem`, and `client_key_pem` support a private CA and client authentication. With TLS enabled, server identity verification is mandatory. Both drivers route TCP connections through the selected proxy. PostgreSQL hostname resolution is left to the route; SOCKS5/CONNECT can resolve at the proxy. Each call creates and closes its own pool, so changes take effect immediately.

| Tool | Arguments beyond connection_id |
| --- | --- |
| `db_tables` | Optional `limit` |
| `db_schema` | `table`, optional `limit` |
| `db_query` | `query`, `params` array, optional `limit` |
| `db_execute` | `query`, `params` array; requires `allow_write` |

Queries run inside read-only transactions on MySQL and PostgreSQL; SQLite has separate driver enforcement. This does not make a privileged target account safe for arbitrary SQL or functions with external side effects. Provision read-only database accounts for query connections. Multiple statements are disabled by the MySQL driver and PostgreSQL prepared statement mode. JSON integer parameters are decoded exactly into int64; larger integers must be supplied as explicit strings. Decimal parameters are passed as decimal strings to avoid float64 rounding. Placeholders retain native syntax: `?` for SQLite/MySQL and `$1`, `$2` for PostgreSQL. No target schema migration occurs.

Example: `{"connection_id":1,"query":"SELECT id, name FROM users WHERE id = $1","params":[42],"limit":20}`.

## SSH and SFTP

```json
{"host":"server.example.net","port":22,"username":"agent","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n...","host_key":"ssh-ed25519 AAAA...","allow_exec":true}
```

A pinned `host_key` is required. `password` is an alternative to `private_key`; encrypted private keys use `private_key_passphrase`.

- `ssh_exec`: `command` string; requires `allow_exec`. Returns bounded stdout/stderr, exit code and truncation flag. Arbitrary shell commands carry the permissions of the SSH account.
- `sftp_read`: `path`; returns at most 512 KiB as base64 with a truncation flag.
- File upload uses the separate [S3-staged transfer tools](file-transfers.md).

`connection_test` performs SSH authentication without executing a command; its response explicitly says the operation was not tested.

## HTTPS

```json
{"base_url":"https://api.example.net/v1/","token":"replace-me","headers":{"Accept":"application/json"},"allow_write":false}
```

`https_request` accepts a relative `path` (including query string), `method`, and text `body`. Use `items?limit=20` under a `/v1/` base. Absolute URLs, different origins and paths escaping the configured base are rejected. Authentication is configured by the operator (`token`, `username`/`password`, or `headers`); callers cannot inject headers. Optional CA/client certificate fields use the SQL TLS format. Redirects return their status without being followed. Response headers are restricted to content type/length, ETag and last-modified; cookies and authorization headers are excluded.

GET, HEAD and OPTIONS are available by default. POST, PUT, PATCH and DELETE require `allow_write`. A server can still implement side effects on GET; choose endpoints and target credentials accordingly. HTTP status is returned even for errors; check both status and content.

## Redis

```json
{"host":"redis.example.net","port":6379,"database":"0","username":"agent","password":"replace-me","tls":true,"allow_exec":false}
```

- `redis_scan`: optional `cursor`, `pattern`, `limit`; returns keys and next cursor. Redis COUNT is a hint and may return more keys. Continue until the cursor is zero.
- `redis_read`: `command`, `args` strings. Supported commands: TYPE, EXISTS, TTL, PTTL, STRLEN, LLEN, SCARD, ZCARD, HLEN, bounded GETRANGE (nonnegative start/end), HGET.
- `redis_command`: arbitrary `command` and `args`; requires `allow_exec`. Use a constrained Redis ACL.

Standalone Redis is supported. Cluster/Sentinel discovery and streaming commands are not provided. Driver command retries are disabled. TLS is applied inside the route-aware dialer, with certificate and hostname verification.

## MongoDB

```json
{"uri":"mongodb://mongo.example.net:27017/?authSource=admin","database":"app","username":"agent","password":"replace-me","tls":true,"allow_write":false}
```

Use `mongodb://`; `mongodb+srv://` is rejected until DNS discovery routing is implemented. Credentials can be included in the encrypted URI. When using separate `username`/`password`, the configured `database` is used as the authentication source; use URI credentials for a separate authSource. Native topology node connections all use the route dialer. Invalid-certificate/hostname TLS options are rejected. Driver read and write retries are disabled.

Tools: `mongo_collections`, `mongo_find`, `mongo_count`, `mongo_aggregate`, `mongo_insert`, `mongo_update`, `mongo_delete`.

Find/count use `collection` and optional `filter` as an Extended JSON string. Find also accepts `limit`. Aggregate uses a `pipeline` Extended JSON array string and rejects `$out` and `$merge`, including nested pipelines. Output documents use canonical Extended JSON strings. Insert uses `document`; update uses `filter` plus an update-operator `document`; delete uses `filter`. Update/delete affect one matching document. All three write tools require `allow_write`.

## Kubernetes

```json
{"base_url":"https://kubernetes.example.net:6443/","token":"replace-me","ca_pem":"-----BEGIN CERTIFICATE-----\n...","allow_write":false}
```

Use a service-account token or client certificate configured directly. Kubeconfig executable authentication plugins are not executed.

- `k8s_get`: `path`, e.g. `/api/v1/namespaces/default/pods`. List requests use a 100-resource limit; follow the server's `metadata.continue` token in a subsequent path query.
- `k8s_logs`: exact pod `/log` path; caps tail lines and bytes, without following.
- `k8s_apply`: exact resource path and YAML/JSON `body`; uses server-side apply with field manager `connkit`, without forcing ownership conflicts; requires `allow_write`.
- `k8s_delete`: exact resource path; requires `allow_write`.

Only `/api/`, `/apis/` and `/version` paths are accepted. Proxy, exec, attach and portforward subresources are rejected. Watch/follow streams are disabled. Kubernetes RBAC controls accessible namespaces, resources and verbs. The adapter returns API status and body for the caller to inspect; HTTP 403 does not count as business success even though the transport completed.

## Management and audit

The Admin UI provides connection tests, editable API key grants/expiry/enabled state, anonymous listener CIDRs and a call list. Saved CIDRs take effect on the next request and intersect with process `CONNKIT_MCP_TRUSTED_CIDRS`; immediate TCP peer addresses are used. Empty CIDR lists add no restriction.

`connection_test` is also available through MCP. It performs database/Redis/MongoDB ping, SSH authentication, HTTPS HEAD or Kubernetes `/version`. Its response shows what was actually checked. Real queries, commands and application behavior require separate acceptance.

Every MCP tool call persists actor/key ID, connection ID (where supplied/resolvable), tool name, duration and status. Arguments, credentials, upstream error text and result bodies are excluded. Calls are recorded before execution; a crash can leave `running`. A canceled call is marked `unknown`; an error response can still follow a completed remote mutation. Inspect target state before retrying. Calls are listed in descending ID order, 100 at a time, with `before` pagination. Retention/automatic deletion is not implemented.

## Remaining work and verification boundary

RDP sessions/screenshots/input, Kubernetes exec/port-forward/watch, MongoDB SRV, Redis Cluster/Sentinel, structured protocol-specific settings forms, schema validation at save time, connection groups and per-tool key grants remain future work. RDP connection metadata can be saved but its test/operations return an unsupported-adapter error.

Automated local tests cover SQLite reads/writes, parameter binding, output limits, configuration-file isolation, HTTPS with real TLS fixtures, target restrictions, redirects, proxy failure without fallback, MCP tool registration/audit, live CIDR policy, key lifecycle, proxy chains and S3/SSH file delivery. Run `./scripts/test-native-fixtures.sh` to create disposable loopback-only MySQL and Redis containers, test native driver authentication/operations and permissions, then remove the fixtures. It requires Docker and never uses existing database services.

Tests use isolated fixtures, not the operator's real databases, Kubernetes cluster or cloud bucket. Validate target accounts, proxy routes, provider compatibility and application results before deployment.
