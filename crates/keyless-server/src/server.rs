use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use keyless_protocol::codec::{Frame, KeylessCodec};
use keyless_protocol::{ErrorCode, Op, Operation, Packet, VERSION_MAJOR};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::FramedRead;

use crate::key::PrivateKey;
use crate::keystore::Keystore;

/// Handler for [`Op::SEAL`] / [`Op::UNSEAL`].
pub trait Sealer: Send + Sync + 'static {
    fn seal(&self, op: &Operation) -> Result<Vec<u8>, ErrorCode>;
    fn unseal(&self, op: &Operation) -> Result<Vec<u8>, ErrorCode>;
}

/// Handler for [`Op::CUSTOM`].
pub type CustomOp = dyn Fn(&Operation) -> Result<Vec<u8>, ErrorCode> + Send + Sync;

/// Decides from the client's certificate chain whether a connection is
/// "limited" (may only ping).
pub type IsLimited = dyn Fn(&[CertificateDer<'_>]) -> bool + Send + Sync;

/// Connection tuning.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Idle connections are closed after this long without a request.
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
    pub handshake_timeout: Duration,
    /// Maximum number of requests in flight per connection.
    pub max_pending_per_connection: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            idle_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            max_pending_per_connection: 1024,
        }
    }
}

/// Builds a rustls config that requires client certificates issued by
/// `client_ca` (Cloudflare's keyless CA in production).
pub fn mtls_server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca: impl IntoIterator<Item = CertificateDer<'static>>,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut roots = RootCertStore::empty();
    for ca in client_ca {
        roots.add(ca)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
}

/// A Keyless key server.
pub struct Server<K> {
    keystore: K,
    acceptor: TlsAcceptor,
    config: ServerConfig,
    sealer: Option<Arc<dyn Sealer>>,
    custom: Option<Arc<CustomOp>>,
    is_limited: Option<Arc<IsLimited>>,
}

impl<K: Keystore> Server<K> {
    pub fn new(tls: Arc<rustls::ServerConfig>, keystore: K) -> Server<K> {
        Server {
            keystore,
            acceptor: TlsAcceptor::from(tls),
            config: ServerConfig::default(),
            sealer: None,
            custom: None,
            is_limited: None,
        }
    }

    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_sealer(mut self, sealer: impl Sealer) -> Self {
        self.sealer = Some(Arc::new(sealer));
        self
    }

    pub fn with_custom_op(
        mut self,
        f: impl Fn(&Operation) -> Result<Vec<u8>, ErrorCode> + Send + Sync + 'static,
    ) -> Self {
        self.custom = Some(Arc::new(f));
        self
    }

    pub fn with_is_limited(
        mut self,
        f: impl Fn(&[CertificateDer<'_>]) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.is_limited = Some(Arc::new(f));
        self
    }

    pub fn keystore(&self) -> &K {
        &self.keystore
    }

    /// Accepts connections until the listener fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        let mut backoff = Duration::from_millis(5);
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    backoff = Duration::from_millis(5);
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(self.clone().serve_connection(stream, peer));
                }
                // Transient errors such as EMFILE: back off rather than spin.
                Err(e) if is_transient(&e) => {
                    tracing::warn!(error = %e, ?backoff, "accept failed; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Serves one connection (TCP, Unix socket, ...) through the TLS handshake
    /// until it closes.
    pub async fn serve_connection<IO>(self: Arc<Self>, io: IO, peer: SocketAddr)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tls = match timeout(self.config.handshake_timeout, self.acceptor.accept(io)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                // Plain TCP health checks close before the handshake; keep that quiet.
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    tracing::debug!(%peer, "closed before TLS handshake");
                } else {
                    tracing::warn!(%peer, error = %e, "TLS handshake failed");
                }
                return;
            }
            Err(_) => {
                tracing::warn!(%peer, "TLS handshake timed out");
                return;
            }
        };
        let limited = match (&self.is_limited, tls.get_ref().1.peer_certificates()) {
            (Some(f), Some(certs)) => f(certs),
            _ => false,
        };
        tracing::debug!(%peer, limited, "connection established");

        let (rd, wr) = tokio::io::split(tls);
        let mut reader = FramedRead::new(rd, KeylessCodec);
        let mut writer = BufWriter::new(wr);
        let max_pending = self.config.max_pending_per_connection.max(1);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(max_pending);

        let write_timeout = self.config.write_timeout;
        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                // Coalesce whatever else is ready into a single flush.
                let write = async {
                    writer.write_all(&msg).await?;
                    while let Ok(msg) = rx.try_recv() {
                        writer.write_all(&msg).await?;
                    }
                    writer.flush().await
                };
                match timeout(write_timeout, write).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return tracing::warn!(%peer, error = %e, "write failed"),
                    Err(_) => return tracing::warn!(%peer, "write timed out"),
                }
            }
            let _ = writer.shutdown().await;
        });

        let pending = Arc::new(Semaphore::new(max_pending));
        loop {
            let Ok(permit) = pending.clone().acquire_owned().await else { break };
            let frame = match timeout(self.config.idle_timeout, reader.next()).await {
                Ok(Some(Ok(frame))) => frame,
                Ok(Some(Err(e))) => {
                    tracing::warn!(%peer, error = %e, "read failed");
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    tracing::debug!(%peer, "idle timeout");
                    break;
                }
            };
            let this = self.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let id = frame.header.id;
                let op = this.process(frame, limited).await;
                let msg = Packet::new(id, op).encode().unwrap_or_else(|e| {
                    tracing::error!(id, error = %e, "cannot encode response");
                    let err = Packet::new(id, Operation::error(ErrorCode::INTERNAL));
                    err.encode().expect("error responses always fit")
                });
                let _ = tx.send(msg).await;
                drop(permit);
            });
        }
        // Answer everything still in flight before closing.
        drop(tx);
        let _ = writer_task.await;
        tracing::debug!(%peer, "connection closed");
    }

    async fn process(&self, frame: Frame, limited: bool) -> Operation {
        if frame.header.major != VERSION_MAJOR {
            return Operation::error(ErrorCode::VERSION_MISMATCH);
        }
        let op = match frame.op {
            Ok(op) => op,
            Err(e) => {
                tracing::warn!(id = frame.header.id, error = %e, "malformed request");
                return Operation::error(ErrorCode::FORMAT);
            }
        };
        tracing::trace!(id = frame.header.id, opcode = %op.opcode, ski = ?op.ski, sni = %op.sni, "request");

        let result = if limited && op.opcode != Op::PING {
            Err(ErrorCode::BAD_OPCODE)
        } else {
            self.dispatch(op).await
        };
        match result {
            Ok(op) => op,
            Err(code) => {
                tracing::debug!(id = frame.header.id, %code, "request failed");
                Operation::error(code)
            }
        }
    }

    async fn dispatch(&self, op: Operation) -> Result<Operation, ErrorCode> {
        match op.opcode {
            Op::PING => Ok(Operation::new(Op::PONG, op.payload)),
            Op::SEAL | Op::UNSEAL => {
                let sealer = self.sealer.clone().ok_or(ErrorCode::INTERNAL)?;
                blocking(move || {
                    if op.opcode == Op::SEAL { sealer.seal(&op) } else { sealer.unseal(&op) }
                })
                .await
                .map(Operation::response)
            }
            Op::CUSTOM => {
                let custom = self.custom.clone().ok_or(ErrorCode::BAD_OPCODE)?;
                blocking(move || custom(&op)).await.map(Operation::response)
            }
            Op::RSA_DECRYPT => {
                let key = self.lookup(&op).await?;
                blocking(move || key.decrypt_raw(&op.payload).map_err(crypto_error))
                    .await
                    .map(Operation::response)
            }
            Op::RESPONSE | Op::PONG | Op::ERROR => Err(ErrorCode::UNEXPECTED_OPCODE),
            opcode => {
                // Op::RPC (Go net/rpc + gob) is intentionally unsupported.
                let params = opcode.sign_params().ok_or(ErrorCode::BAD_OPCODE)?;
                let key = self.lookup(&op).await?;
                blocking(move || key.sign(params, &op.payload).map_err(crypto_error))
                    .await
                    .map(Operation::response)
            }
        }
    }

    async fn lookup(&self, op: &Operation) -> Result<Arc<dyn PrivateKey>, ErrorCode> {
        match self.keystore.get(op).await {
            Ok(Some(key)) => Ok(key),
            Ok(None) => {
                tracing::info!(ski = ?op.ski, sni = %op.sni, "key not found");
                Err(ErrorCode::KEY_NOT_FOUND)
            }
            Err(e) => {
                tracing::error!(ski = ?op.ski, error = %e, "keystore error");
                Err(ErrorCode::INTERNAL)
            }
        }
    }
}

fn crypto_error(e: crate::KeyError) -> ErrorCode {
    tracing::warn!(error = %e, "key operation failed");
    match e {
        crate::KeyError::Unsupported => ErrorCode::BAD_OPCODE,
        _ => ErrorCode::CRYPTO,
    }
}

/// Runs a private key operation off the async workers; RSA signing takes
/// around a millisecond and HSM/KMS-backed keys may block on I/O.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ErrorCode> + Send + 'static,
) -> Result<T, ErrorCode> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
        tracing::error!(error = %e, "key operation panicked");
        Err(ErrorCode::INTERNAL)
    })
}

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    ) || matches!(e.raw_os_error(), Some(23 | 24)) // ENFILE / EMFILE
}
