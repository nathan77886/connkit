# File transfers through S3-compatible storage

ConnKit uploads files to a private staging bucket and asks the target machine to download them. File bytes do not pass through MCP messages or the Admin backend, and uploads do not use direct SFTP writes.

## Transfer flow

1. Configure cloud storage in **Admin → Cloud storage**.
2. Select a registered SSH connection and an absolute destination path.
3. Calculate the file's size and SHA-256, then prepare an upload.
4. Upload the file directly to its temporary, object-specific PUT URL.
5. Request delivery. ConnKit verifies the cloud object's size and sends a temporary GET URL to the SSH target.
6. The target downloads into a private temporary file in the destination directory, verifies size and SHA-256, and commits the file without overwriting an existing destination.
7. Inspect the transfer status and explicitly remove the cloud copy when no longer needed.

The Admin page performs hashing, upload, and delivery in sequence. Browser hashing is incremental. MCP clients perform the same steps using the tools below.

## Storage configuration

ConnKit uses the official AWS SDK for Go v2 with an explicit endpoint and credentials. The settings support AWS S3 and services implementing compatible S3 operations, including MinIO and Cloudflare R2. Provider-specific compatibility must be verified against the intended deployment.

- **Endpoint:** An S3 API origin, without a bucket path, query string, or embedded credentials. It must be reachable by the caller uploading the file, ConnKit, and the target machine.
- **Region:** The provider's signing region; defaults to `us-east-1`. Use the region required by the provider, such as `auto` for R2.
- **Bucket:** An existing private bucket.
- **Access key / Secret key:** Explicit storage credentials, encrypted in the local configuration database. GET configuration responses return neither value.
- **Session token:** Optional temporary AWS credentials. Blank credential fields preserve existing values; use **Clear saved session token** to remove an old token.
- **Object prefix:** Defaults to `connkit`. Each upload receives a random object ID under this prefix.
- **Path-style addressing:** Enable for providers that require it.
- **Allow HTTP:** An explicit opt-in for trusted HTTP endpoints; otherwise HTTPS is required. Certificate verification remains enabled for HTTPS.
- **Storage proxy:** Optional proxy for ConnKit's S3 metadata and cleanup requests.
- **Maximum file size:** Defaults to 512 MiB; configurable from 1 to 5120 MiB. Files must be non-empty so the signed PUT can bind a positive Content-Length. This implementation uses single-object PUT, not multipart upload.

Credentials need permission to PUT, GET/HEAD, and DELETE objects under the configured prefix. ConnKit does not create buckets, grant public access, or modify bucket policies and CORS settings.

Saving storage configuration invalidates outstanding preparations. Create a new upload after changing the endpoint, bucket, credentials, proxy, or other storage settings.

## Browser CORS

Direct browser uploads require the bucket to allow PUT requests from the Admin site's exact origin. A typical AWS-style CORS configuration is:

```json
[
  {
    "AllowedOrigins": ["https://admin.example.com"],
    "AllowedMethods": ["PUT"],
    "AllowedHeaders": ["*"],
    "MaxAgeSeconds": 300
  }
]
```

Adapt this to the provider and actual Admin origin. CLI/agent uploads are not subject to browser CORS. Use the signed URL as returned; changing its hostname, path, query, or signed request headers can invalidate the signature.

## SSH target configuration

Register a connection with type `ssh` and settings such as:

```json
{
  "host": "target.example.com",
  "port": 22,
  "username": "operator",
  "private_key": "<SSH private key>",
  "host_key": "ssh-ed25519 <verified host public key>"
}
```

`password` is an alternative to `private_key`. Encrypted keys can use `private_key_passphrase`. `host_key` is a pinned authorized-key-format public key, obtained through a trusted channel. Host key verification cannot be disabled.

The first target-side implementation supports Linux/POSIX SSH targets with `sh`, `curl`, `mktemp`, `dirname`, `wc`, `tr`, `sha256sum`, `chmod`, `ln`, and `rm`. The destination directory must already exist, be writable by the SSH account, and support hard links. The resulting file mode is `0600`. Existing files and symbolic links are rejected; there is no automatic overwrite.

Windows/RDP and Kubernetes file delivery are not implemented by these tools.

### Proxy paths

These are separate network paths:

- **Caller → storage:** The browser or agent uses its own network to upload to the signed URL.
- **ConnKit → storage:** Uses the storage configuration's proxy, if selected.
- **ConnKit → SSH target:** Uses the target connection's proxy, if selected.
- **Target → storage:** The download runs on the target and uses that machine's network and curl environment.

Supported ConnKit routes are direct TCP, HTTP CONNECT, HTTPS CONNECT, SOCKS5, and SSH forwarding, including upstream proxy combinations. SSH proxies use the same host/user/authentication settings as SSH connections. HTTP/SOCKS5 proxies use `host`, `port`, and optional `username`/`password`. SOCKS5 forwards the destination hostname to the proxy. HTTPS proxies verify their TLS certificate. Failure does not fall back to direct dialing.

## MCP tools

### `files_prepare_upload`

Input:

```json
{
  "connection_id": 1,
  "name": "archive.tar.gz",
  "destination": "/srv/uploads/archive.tar.gz",
  "size": 12345,
  "sha256": "<64 hexadecimal characters>"
}
```

The result contains `file.id` and `upload` with `url`, `method`, required `headers`, and `expires_at`. PUT the exact bytes to that URL. Do not forward ConnKit's API key to storage. Browsers set Host and Content-Length themselves; CLI clients must preserve required headers and the declared body length.

### `files_deliver`

Input: `{"id":"<file.id>"}`. Delivery validates current connection access, file ownership, expiration, storage revision, and uploaded size. The target verifies SHA-256 before committing. A successfully delivered ID returns its recorded result without executing the target command again.

### `files_status`

Input: `{"id":"<file.id>"}`. Returns metadata and status without signed URLs or storage credentials.

### `files_remove`

Input: `{"id":"<file.id>"}`. Removes the staged cloud object, leaving the target file unchanged. Cleanup cannot run while delivery is in progress.

The authenticated listener binds files to their API key identity. Revoked/expired keys and removed connection grants lose access. The anonymous listener uses one shared anonymous identity, restricted to its permitted SSH connections. Admin transfers have a separate identity.

## Expiration and recovery

- PUT grants expire after 15 minutes; GET grants expire after 5 minutes. Temporary provider credentials can expire sooner.
- Transfer records are valid for 24 hours. Expiration does not automatically delete cloud objects.
- Configure a bucket lifecycle policy for the staging prefix to remove abandoned objects, for example after one day. ConnKit does not configure that policy automatically.
- Deleting an object does not revoke an already issued PUT URL: it can recreate the same object until the grant expires. Lifecycle cleanup remains necessary.
- Statuses include `prepared`, `delivering`, `delivered`, `unknown`, `removing`, and `removed`.
- Delivery uses a conditional database update to claim one attempt. It is bounded to five minutes, with a 240-second target download timeout.
- A failed or disconnected delivery becomes `unknown`. A process crash can leave `delivering`. Inspect the target before starting another upload; ConnKit does not automatically retry or overwrite the destination.
- A successful delivery can leave a cloud copy until explicit or lifecycle cleanup. Cleanup failure does not turn successful delivery into a failed target operation.

Signed URLs are temporary bearer credentials. ConnKit does not store them in transfer records or return download URLs through status tools. Avoid recording prepare-upload responses in public logs.

## Verification scope

Tests cover AWS SDK signing against a local S3-compatible HTTP fixture, an actual SSH protocol server executing target-side download commands, integrity failures, existing destinations, ownership and revocation, conditional delivery claims, cloud cleanup, proxy chaining, and SSH host key verification. They do not constitute live acceptance against AWS S3, R2, or MinIO deployments.
