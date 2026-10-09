# keyless (Rust)

A Rust implementation of Cloudflare's [Keyless SSL](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/)
protocol, wire-compatible with [cloudflare/gokeyless](https://github.com/cloudflare/gokeyless):

| crate | what |
|---|---|
| `keyless-protocol` | Wire format (header + TLV items + 1024-byte padding), opcodes, error codes, SKI derivation, tokio codec |
| `keyless-server` | mTLS key server (library + `keyless-server` binary), a drop-in for `gokeyless` for modern TLS |
| `keyless-client` | Multiplexing async client and **`KeylessSigningKey`, a `rustls::sign::SigningKey`** that signs on the key server |

## How it works

A TLS server needs its private key exactly once per handshake: to sign the
handshake (ECDHE, TLS 1.2/1.3) or to decrypt the pre-master secret (RSA key
exchange, TLS ≤ 1.2). Keyless SSL sends just that operation over a
mutually-authenticated TLS connection to a key server that holds the key.

```
browser ──TLS──▶ rustls ServerConfig ──(sign digest, SKI)──▶ keyless-server / gokeyless
                 cert only, KeylessSigningKey   ◀──signature──  holds private keys
```

All crates are `#![forbid(unsafe_code)]`; cryptography is the safe
`aws-lc-rs` API.

Wire format: `[major=1][minor=0][u16 body length][u32 request id]`, then TLV
items (`u8 tag, u16 len, value`). Requests carry an opcode
(`RSASignSHA256`, `RSAPSSSignSHA384`, `ECDSASignSHA256`, `Ed25519Sign`,
`Ping`, ...), the payload (a **digest**, not the transcript,
except for Ed25519), and the key's SHA-1 Subject Key Identifier. Messages are
padded to 1024 bytes. Many requests share one connection and are answered
out of order, matched by ID.

## Using the rustls integration

```rust
let tls = keyless_client::mtls_client_config([keyserver_ca], vec![client_cert], client_key)?;
let client = keyless_client::KeylessClient::new("keyserver.example.com:2407", Arc::new(tls))?;

// The TLS terminator holds the certificate chain only.
let certified = keyless_client::KeylessSigningKey::certified_key(client, chain)?;
let config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
```

`KeylessSigningKey` works with any `ResolvesServerCert` (for example `ResolvesServerCertUsingSni`
for several certificates) and with client-certificate auth (`ResolvesClientCert`).
`with_metadata` attaches SNI, IPs or a cert ID to requests for key servers that use them.

**Blocking caveat:** rustls's `Signer::sign` is synchronous (async signing is a
TODO upstream), so a handshake blocks its thread for one key-server round trip.
The client runs its connection on a small dedicated runtime and, on a
multi-threaded Tokio worker, waits via `block_in_place`, so this cannot
deadlock and other tasks keep running. On a current-thread runtime the whole
runtime stalls for the round trip. Prefer a multi-threaded runtime, and keep
the persistent connection warm.

## Running the server

```sh
keyless-server --listen 0.0.0.0:2407 \
  --auth-cert server.pem --auth-key server-key.pem \
  --cloudflare-ca-cert keyless_cacert.pem \
  --private-key-dirs /etc/keyless/keys      # *.key: PKCS#8, PKCS#1 or SEC1, PEM or DER
```

Library use: `Server::new(tls, keystore)` with your own `Keystore` (key
lookup by SKI/SNI/IP/...) and `PrivateKey` (HSM, KMS, ...) implementations;
`with_sealer`, `with_custom_op` and `with_is_limited` mirror gokeyless's hooks.

## Verification

- `cargo test --workspace` covers the following:
  - Wire-format unit tests, including exact bytes, padding edge cases and malformed input.
  - Every supported opcode against every key type (RSA-2048, P-256, P-384, P-521, Ed25519), with signatures verified independently. Also: rejection of legacy ops as `ErrBadOpcode`, gokeyless error codes, 500 concurrently multiplexed requests, reconnect after the server's idle timeout, and rejection of untrusted client certificates.
  - Real rustls TLS 1.3 and 1.2 handshakes with each key type held only by the key server, on multi-thread and current-thread Tokio and on plain synchronous rustls.
- `interop/run.sh` builds gokeyless from source (`reference/gokeyless`) and cross-tests:
  - Go `gokeyless-cli-tester` → Rust server: every supported test (ping, RSA SHA-256/384/512, ECDSA with the curve's hash) passes with Go-verified signatures. The 13 legacy combinations are uniformly rejected with `bad opcode`, and the script asserts exactly that.
  - Rust client + rustls → Go `gokeyless` server: all schemes verify, and TLS 1.2/1.3 handshakes complete.
  - Rust client + rustls → Rust server: same.

## Differences from gokeyless / not implemented

- **Only the operations modern TLS uses are supported.** These are RSA PKCS#1 v1.5 and PSS with SHA-256/384/512, ECDSA P-256/SHA-256, P-384/SHA-384 and P-521/SHA-224…512, and Ed25519. Everything else gets `ErrBadOpcode`:
  - `RSADecrypt` (RSA key exchange)
  - MD5SHA1, SHA-1 and SHA-224 signatures
  - ECDSA with a hash that doesn't match the curve, e.g. P-256 with SHA-384

  These are exactly what TLS 1.3 and rustls never negotiate. They are also what the safe aws-lc-rs API cannot express: it signs a supplied digest only for these combinations and has no unpadded RSA. Old TLS 1.0/1.1 clients, or gokeyless clients doing RSA key exchange, therefore won't work against this server. A custom `PrivateKey` (e.g. an HSM) may implement `decrypt_raw` or more hashes.
- `OpRPC` (Go `net/rpc` + `gob`) is not portable and returns `ErrBadOpcode`. Seal/Unseal/Custom go through the hooks above.
- Only in-memory keys ship. PKCS#11, Azure Key Vault and Google KMS would be `PrivateKey` implementations. The default keystore looks up by SKI only, like gokeyless's `DefaultKeystore`.
- No Prometheus metrics, Jaeger span propagation or Cloudflare API "initialize" flow. Logging uses `tracing`.
- The server accepts TLS 1.2 and 1.3 from clients. gokeyless pins TLS 1.2 with AES-256-GCM. Restrict this via the `rustls::ServerConfig` if needed.
- The server rejects a request whose opcode family does not match the key type, e.g. ECDSA on an RSA key, with `ErrCrypto` (gokeyless would sign anyway). It also checks the header major version.

Building on Windows: `.cargo/config.toml` sets `AWS_LC_SYS_PREBUILT_NASM=1` so aws-lc-sys does not need NASM.
