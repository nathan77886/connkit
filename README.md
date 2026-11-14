# ConnKit

**A unified connection service for AI agents, powered by MCP.**

[English](README.md) · [简体中文](README.zh-CN.md)

ConnKit brings system connections, credentials, and outbound proxies into one admin console, then exposes operations through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It is designed to let agents work with databases, servers, Kubernetes clusters, remote desktops, and HTTPS APIs through a common entry point.

> **Project status:** Early development. Admin, dual MCP listeners, SQL/SSH/Redis/MongoDB/HTTPS/Kubernetes resource tools, and S3-staged SSH file delivery are implemented. RDP and streaming Kubernetes operations remain planned; real target acceptance is required before deployment.

## Getting started

See [development and packaging](docs/development.md) for local setup, environment variables, MCP access, and container usage. The [implementation design](docs/architecture.md) (Simplified Chinese) describes the full intended scope.

Currently available: encrypted connection/proxy configuration, editable API keys and grants, anonymous CIDR policy, connection tests, metadata-only tool call records, protocol operations, and S3-staged file delivery. See [protocol settings and tools](docs/protocols.md) for exact capabilities, examples and limitations.

## Capabilities and roadmap

### Admin console

- Manage system connections, credentials, groups, and connection settings.
- Create, expire, disable, and revoke API keys with access to selected connections.
- Configure the connections available through the unauthenticated listener and optional IP/CIDR restrictions.
- Manage outbound proxies and upstream proxy chains.
- Test connectivity and authentication, and review tool call records.

### MCP service

- Streamable HTTP transport with a shared `/mcp` path on two separate listeners.
- An API key listener using `Authorization: Bearer <key>`.
- An unauthenticated listener for trusted networks, with optional IP/CIDR restrictions.
- Connection discovery and protocol-specific tools using registered connection IDs.
- Connection access checks, request timeouts, bounded results, and session cleanup.

### Connection types

- **SSH:** File delivery through S3-compatible storage, with target-side download and SHA-256 verification. Remote commands (explicit opt-in) and bounded SFTP reads are available.
- **Kubernetes:** Resource inspection, bounded logs, server-side apply and delete. Exec/streaming operations remain planned.
- **RDP (planned):** Remote desktop sessions, screenshots, and keyboard/mouse input.
- **MongoDB:** Collection discovery, document queries, aggregation, and authorized writes.
- **Redis:** Key scanning, data access, and authorized commands.
- **MySQL / PostgreSQL:** Schema inspection, parameterized SQL queries, and authorized writes through native database drivers.
- **SQLite:** Access to database files registered on the ConnKit server.
- **HTTPS:** Requests to configured API endpoints, with connection-level authentication, headers, and TLS settings.

### File uploads

Configure a private S3-compatible bucket, upload directly using a temporary PUT URL, and let an authorized SSH target download through a temporary GET URL. Storage credentials remain on the server; target files are verified and existing destinations are not overwritten. See [file transfers](docs/file-transfers.md) for setup, CORS, target requirements, and MCP tools.

### Outbound proxies

- Direct connections.
- HTTP CONNECT and HTTPS CONNECT proxies.
- SOCKS5 proxies.
- SSH tunnels.
- Proxy chains configured through upstream proxy references.

Each connection selects its own proxy configuration. Proxy failures are returned to the caller without falling back to a direct connection. SQLite file access does not use a network proxy.

## Architecture

ConnKit has three source modules and two backend processes:

- **Admin:** The Iris management API and administrator authentication.
- **Admin Web:** The React/Vite/Arco Design management console.
- **MCP:** Agent-facing tools backed by native drivers and protocol clients.

Tool calls pass through the listener's authentication policy, connection authorization, and protocol adapter before reaching the target directly or through its configured proxy. Both MCP listeners share the same tool implementation; their authentication policies remain separate.

The stack is Go, the official MCP Go SDK, React, Vite, Arco Design, and a shared SQLite or PostgreSQL configuration database. **GORM and Go models apply to ConnKit's own configuration data.** Target databases use their respective drivers and retain native query semantics. RDP uses a dedicated internal desktop protocol backend where required.

GitHub Actions is configured to build two images: `connkit-mcp` for MCP, and `connkit-admin` containing Nginx, the Admin backend, and compiled Admin Web assets. Both processes share the configured database; SQLite mode uses a shared local volume. Admin owns schema initialization. Images are published only after a successful workflow run.

See the [implementation design](docs/architecture.md) for details.

## Access and credentials

- The admin console always requires administrator authentication.
- API keys and target credentials are managed separately.
- API keys are stored as verification digests; target passwords and private keys are encrypted with a key held outside the configuration database.
- The unauthenticated listener is intended for trusted networks. Reverse proxies should forward authenticated access to the API key listener.
- A listener's authentication policy does not change based on a forwarded or loopback source address.
- Database roles, Redis ACLs, Kubernetes RBAC, and operating system accounts enforce target-side permissions.
- Call records exclude full credentials and result payloads by default.

## Documentation

- [Protocol settings and MCP tools](docs/protocols.md)
- [File transfers through S3-compatible storage](docs/file-transfers.md)
- [Development and packaging](docs/development.md)
- [English overview](README.md)
- [简体中文概览](README.zh-CN.md)
- [Implementation design / 实现设计](docs/architecture.md) — Simplified Chinese

## Contributing

Design feedback, protocol requirements, bug reports, and documentation improvements are welcome through [issues](https://github.com/nathan77886/connkit/issues) and pull requests. For implementation proposals, describe the intended behavior, affected connection types, proxy requirements, and how the change can be verified. Keep credentials and private environment details out of examples and reports.

## License

Licensed under the [MIT License](LICENSE).
