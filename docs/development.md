# Development and packaging

## Repository layout

- `admin/`: Iris management API, authentication, and configuration controllers.
- `admin-web/`: React, Vite, TypeScript, and Arco Design management frontend.
- `mcp/`: Official MCP Go SDK integration and separate authenticated/anonymous listeners.
- `cmd/admin/`, `cmd/mcp/`: Independent service entry points.
- `internal/store/`: Local SQLite models and GORM persistence shared by both services.
- `deploy/`: Nginx configuration and combined Admin container entrypoint.

## Current implementation

Admin provides encrypted connection/proxy configuration, key editing/enabling/revocation, connection tests, live anonymous CIDR policy, metadata-only call history, and cloud staging management. MCP provides SQL, SSH/SFTP, Redis, MongoDB, HTTPS and Kubernetes resource operations plus S3-staged file delivery. See [protocol settings and tools](protocols.md) and [file transfers](file-transfers.md) for exact capabilities and configuration.

RDP and Kubernetes streaming operations remain unimplemented. Protocol settings use JSON rather than dedicated forms; validation occurs when operations are invoked. Real target/cloud acceptance is required before deployment.

## Local development

Requirements: Go (see `go.mod`), a C compiler for the SQLite driver, Node.js 22.12+ (or a compatible newer LTS), and npm.

1. Copy `.env.example` to `.env`, generate an independent 32-byte master key with `openssl rand -base64 32`, and set an administrator password. Never commit `.env`.
2. Export those variables into the environment of each Go process. Both services require the same `CONNKIT_MASTER_KEY` and `CONNKIT_DB_PATH`.
3. Start Admin first to initialize its configuration schema:

   ```sh
   go run ./cmd/admin
   ```

4. In another terminal with the same configuration, start MCP:

   ```sh
   CONNKIT_MCP_ANONYMOUS_ADDR=127.0.0.1:8082 go run ./cmd/mcp
   ```

5. Start the frontend:

   ```sh
   cd admin-web
   npm ci
   npm run dev
   ```

The frontend is available at `http://127.0.0.1:5173` and proxies `/api` to the local Admin backend. The authenticated MCP endpoint is `http://127.0.0.1:8081/mcp`; the example above enables the anonymous endpoint at `http://127.0.0.1:8082/mcp`.

Admin sessions and MCP keys are separate bearer credentials. Create a connection, create a key granting access to that connection, and configure an MCP client that supports Streamable HTTP and the `Authorization: Bearer <key>` header. An empty connection grant exposes no connections. The anonymous endpoint only exposes connections with `allow_anonymous` enabled.

The current MCP transport is stateless. Each request revalidates the API key and connection grants. Use MCP `tools/list` for complete schemas; [protocol settings and tools](protocols.md) documents all registered operations. File delivery requires correctly configured SSH credentials, a pinned host key, and cloud storage.

## Process configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `CONNKIT_DB_PATH` | Shared local configuration database | `data/connkit.db` |
| `CONNKIT_MASTER_KEY` | Base64-encoded 32-byte encryption key | Required |
| `CONNKIT_ADMIN_USERNAME` | Administrator username | `admin` |
| `CONNKIT_ADMIN_PASSWORD` | Administrator password, 12–72 bytes | Required by Admin |
| `CONNKIT_ADMIN_ADDR` | Admin backend listener | `127.0.0.1:8080` |
| `CONNKIT_MCP_ADDR` | MCP API key listener | `:8081` |
| `CONNKIT_MCP_ANONYMOUS_ADDR` | Anonymous MCP listener | Disabled when unset |
| `CONNKIT_MCP_TRUSTED_CIDRS` | Optional comma-separated anonymous source CIDRs | Unrestricted at this layer when empty |
| `CONNKIT_MCP_ORIGINS` | Allowed exact browser origins | No browser origins allowed |

Clients that omit the Origin header can connect subject to the listener's normal access policy. CIDR rules inspect the immediate peer. The Admin Access policy page adds live CIDRs; when both environment and saved rules are present, both must allow the source. Proxy/NAT paths may change that address, so they must be considered when configuring these rules.

The Admin password is loaded at process startup. Changing it requires a restart and does not revoke existing Admin sessions, which expire after eight hours. Keep the master key stable; key rotation is not implemented. Back up the SQLite database using SQLite-aware methods and preserve the master key separately.

Both processes use the same local SQLite file and its WAL sidecar files on a shared local volume. Only Admin runs schema migration. This arrangement targets a single-host deployment; do not place the database on a shared network filesystem or deploy independent configuration database copies.

GORM and explicit Go models apply to ConnKit's own persistence. Target databases use their native drivers; target schemas must never be automatically migrated.

## Container images

GitHub Actions builds exactly two `linux/amd64` images:

- `ghcr.io/nathan77886/connkit-mcp`: MCP process, exposing ports 8081 and 8082.
- `ghcr.io/nathan77886/connkit-admin`: Nginx, Admin backend, and compiled Admin Web assets; exposing port 80. The backend listens on loopback inside the container.

The combined Admin entrypoint supervises both processes, forwards shutdown signals, and exits if either process stops. Its health check calls the backend through Nginx and checks configuration database connectivity.

Pull requests build without publishing. Pushes to `main`, `v*` tags, and manual workflow runs publish to GHCR after tests and checks pass. Tags include the branch or version plus a full commit SHA. Image availability depends on the first successful workflow run; image names in this document do not indicate that images have already been published.

After images have been published, configure `.env` and run:

```sh
docker compose up -d
```

Compose uses published images and binds all host ports to loopback by default. Change those bindings deliberately when exposing services to other hosts. The anonymous listener must remain accessible only to the intended trusted network.

## Checks

```sh
go test -race -shuffle=on ./...
go vet ./...
cd admin-web
npm ci
npm run build
```

GitHub Actions additionally runs golangci-lint and govulncheck before building the two images. Local binary compilation and tests do not publish container images.
