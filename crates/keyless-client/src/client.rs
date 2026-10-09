use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures_util::StreamExt;
use keyless_protocol::codec::KeylessCodec;
use keyless_protocol::{DecodeError, ErrorCode, Op, Operation, Packet};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::runtime::{Handle, Runtime, RuntimeFlavor};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::codec::FramedRead;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connecting to key server: {0}")]
    Connect(#[source] io::Error),
    #[error("timed out connecting to key server")]
    ConnectTimeout,
    #[error("key server connection lost")]
    ConnectionLost,
    #[error("timed out waiting for key server response")]
    Timeout,
    #[error("key server returned error: {0}")]
    Remote(ErrorCode),
    #[error("unexpected response opcode {0}")]
    UnexpectedResponse(Op),
    #[error("key server returned an empty payload")]
    EmptyPayload,
    #[error("malformed response: {0}")]
    Decode(#[from] DecodeError),
    #[error("cannot encode request: {0}")]
    Encode(#[from] keyless_protocol::EncodeError),
    #[error("signature scheme {0:?} is not supported by this key")]
    UnsupportedScheme(rustls::SignatureScheme),
    #[error("invalid key server name {0:?}")]
    InvalidServerName(String),
    #[error("cannot start client runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("client task failed: {0}")]
    Task(String),
}

/// Client tuning.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub connect_timeout: Duration,
    /// Time allowed for a single request/response round trip.
    pub request_timeout: Duration,
    /// TLS server name to verify; defaults to the host part of the address.
    pub server_name: Option<ServerName<'static>>,
    /// Runtime that drives the connection. If `None`, the client starts a
    /// small dedicated runtime, which makes the blocking API (used by the
    /// rustls signer) safe to call from any thread. A supplied runtime must be
    /// multi-threaded if the blocking API is used from its own threads.
    pub runtime: Option<Handle>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            server_name: None,
            runtime: None,
        }
    }
}

/// Builds a rustls client config that trusts `server_ca` and authenticates
/// with a client certificate, as key servers require.
pub fn mtls_client_config(
    server_ca: impl IntoIterator<Item = CertificateDer<'static>>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let mut roots = RootCertStore::empty();
    for ca in server_ca {
        roots.add(ca)?;
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
}

/// A connection-multiplexing Keyless client. Cheap to clone.
///
/// Requests share one TLS connection and are matched to responses by ID, so
/// many handshakes can wait on the key server concurrently. A lost
/// connection is re-established transparently (each request is retried once).
#[derive(Clone)]
pub struct KeylessClient {
    inner: Arc<Inner>,
}

struct Inner {
    addr: String,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    config: ClientConfig,
    handle: Handle,
    runtime: StdMutex<Option<Runtime>>,
    conn: Mutex<Option<Arc<Conn>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Dropping a Runtime from async context panics; shut down detached.
        if let Some(rt) = self.runtime.get_mut().unwrap().take() {
            rt.shutdown_background();
        }
    }
}

impl std::fmt::Debug for KeylessClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessClient").field("addr", &self.inner.addr).finish_non_exhaustive()
    }
}

impl KeylessClient {
    /// Creates a client for the key server at `addr` (`host:port`). No
    /// connection is made until the first request.
    pub fn new(addr: impl Into<String>, tls: Arc<rustls::ClientConfig>) -> Result<Self, ClientError> {
        KeylessClient::with_config(addr, tls, ClientConfig::default())
    }

    pub fn with_config(
        addr: impl Into<String>,
        tls: Arc<rustls::ClientConfig>,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let addr = addr.into();
        let server_name = match &config.server_name {
            Some(name) => name.clone(),
            None => {
                let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
                let host = host.trim_start_matches('[').trim_end_matches(']');
                ServerName::try_from(host.to_owned())
                    .map_err(|_| ClientError::InvalidServerName(host.to_owned()))?
            }
        };
        let (handle, runtime) = match &config.runtime {
            Some(handle) => (handle.clone(), None),
            None => {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("keyless-client")
                    .enable_all()
                    .build()
                    .map_err(ClientError::Runtime)?;
                (rt.handle().clone(), Some(rt))
            }
        };
        Ok(KeylessClient {
            inner: Arc::new(Inner {
                addr,
                server_name,
                connector: TlsConnector::from(tls),
                config,
                handle,
                runtime: StdMutex::new(runtime),
                conn: Mutex::new(None),
            }),
        })
    }

    pub fn addr(&self) -> &str {
        &self.inner.addr
    }

    /// Sends `op` and returns the raw response operation (which may be an
    /// [`Op::ERROR`]).
    pub async fn do_operation(&self, op: Operation) -> Result<Operation, ClientError> {
        // Run on the client's runtime so connection I/O is always owned by it,
        // whatever runtime the caller is on.
        let inner = self.inner.clone();
        self.inner
            .handle
            .spawn(async move { inner.do_operation(op).await })
            .await
            .map_err(|e| ClientError::Task(e.to_string()))?
    }

    /// Sends `op` and returns the payload of a successful response.
    pub async fn execute(&self, op: Operation) -> Result<Vec<u8>, ClientError> {
        payload(self.do_operation(op).await?)
    }

    /// Blocking variant of [`execute`](Self::execute), for synchronous
    /// callers such as [`rustls::sign::Signer`].
    ///
    /// On a multi-threaded Tokio worker this uses `block_in_place`, so the
    /// caller's runtime keeps making progress on its other workers.
    pub fn execute_blocking(&self, op: Operation) -> Result<Vec<u8>, ClientError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let inner = self.inner.clone();
        self.inner.handle.spawn(async move {
            let _ = tx.send(inner.do_operation(op).await.and_then(payload));
        });
        let wait = || rx.recv().unwrap_or_else(|_| Err(ClientError::Task("client runtime shut down".into())));
        match Handle::try_current() {
            Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(wait),
            _ => wait(),
        }
    }

    /// Round-trips a ping through the key server.
    pub async fn ping(&self, data: &[u8]) -> Result<Vec<u8>, ClientError> {
        let resp = self.do_operation(Operation::new(Op::PING, data.to_vec())).await?;
        match resp.opcode {
            Op::PONG => Ok(resp.payload),
            Op::ERROR => Err(ClientError::Remote(resp.error_code().unwrap_or(ErrorCode::FORMAT))),
            other => Err(ClientError::UnexpectedResponse(other)),
        }
    }
}

fn payload(resp: Operation) -> Result<Vec<u8>, ClientError> {
    match resp.opcode {
        Op::RESPONSE if resp.payload.is_empty() => Err(ClientError::EmptyPayload),
        Op::RESPONSE => Ok(resp.payload),
        Op::ERROR => Err(ClientError::Remote(resp.error_code().unwrap_or(ErrorCode::FORMAT))),
        other => Err(ClientError::UnexpectedResponse(other)),
    }
}

impl Inner {
    async fn do_operation(&self, op: Operation) -> Result<Operation, ClientError> {
        // A pooled connection may have been closed by the server (idle
        // timeout) just as we used it; retry once on a fresh connection.
        let mut attempts = 2;
        loop {
            attempts -= 1;
            let conn = self.connection().await?;
            match conn.request(op.clone(), self.config.request_timeout).await {
                Err(ClientError::ConnectionLost) if attempts > 0 => {
                    tracing::debug!(addr = %self.addr, "connection lost; retrying");
                }
                result => return result,
            }
        }
    }

    async fn connection(&self) -> Result<Arc<Conn>, ClientError> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = slot.as_ref().filter(|c| !c.closed.load(Ordering::Acquire)) {
            return Ok(conn.clone());
        }
        let conn = timeout(self.config.connect_timeout, self.connect())
            .await
            .map_err(|_| ClientError::ConnectTimeout)??;
        *slot = Some(conn.clone());
        Ok(conn)
    }

    async fn connect(&self) -> Result<Arc<Conn>, ClientError> {
        let tcp = TcpStream::connect(&self.addr).await.map_err(ClientError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let tls = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(ClientError::Connect)?;
        tracing::debug!(addr = %self.addr, "connected to key server");
        Ok(Conn::spawn(tls))
    }
}

type Waiter = oneshot::Sender<Result<Operation, DecodeError>>;

/// One multiplexed TLS connection with reader and writer tasks.
struct Conn {
    /// Encoded packets for the writer task.
    tx: mpsc::Sender<Vec<u8>>,
    pending: StdMutex<HashMap<u32, Waiter>>,
    next_id: AtomicU32,
    closed: AtomicBool,
}

impl Conn {
    fn spawn(tls: tokio_rustls::client::TlsStream<TcpStream>) -> Arc<Conn> {
        let (rd, wr) = tokio::io::split(tls);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        let conn = Arc::new(Conn {
            tx,
            pending: StdMutex::new(HashMap::new()),
            next_id: AtomicU32::new(0),
            closed: AtomicBool::new(false),
        });

        let writer_conn = Arc::downgrade(&conn);
        tokio::spawn(async move {
            let mut writer = BufWriter::new(wr);
            while let Some(msg) = rx.recv().await {
                // Coalesce whatever else is queued into a single flush.
                let write = async {
                    writer.write_all(&msg).await?;
                    while let Ok(msg) = rx.try_recv() {
                        writer.write_all(&msg).await?;
                    }
                    writer.flush().await
                };
                if let Err(e) = write.await {
                    tracing::debug!(error = %e, "key server write failed");
                    break;
                }
            }
            if let Some(conn) = writer_conn.upgrade() {
                conn.shut_down();
            }
        });

        let reader_conn = conn.clone();
        tokio::spawn(async move {
            let mut reader = FramedRead::new(rd, KeylessCodec);
            while let Some(frame) = reader.next().await {
                match frame {
                    Ok(frame) => {
                        let waiter = reader_conn.pending.lock().unwrap().remove(&frame.header.id);
                        match waiter {
                            Some(waiter) => {
                                let _ = waiter.send(frame.op);
                            }
                            None => tracing::debug!(id = frame.header.id, "response for unknown request"),
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "key server read failed");
                        break;
                    }
                }
            }
            reader_conn.shut_down();
        });

        conn
    }

    /// Marks the connection dead and fails all waiting requests.
    fn shut_down(&self) {
        self.closed.store(true, Ordering::Release);
        self.pending.lock().unwrap().clear();
    }

    async fn request(&self, op: Operation, limit: Duration) -> Result<Operation, ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = Packet::new(id, op).encode()?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        if self.closed.load(Ordering::Acquire) || self.tx.send(msg).await.is_err() {
            self.pending.lock().unwrap().remove(&id);
            return Err(ClientError::ConnectionLost);
        }
        match timeout(limit, rx).await {
            Ok(Ok(result)) => Ok(result?),
            Ok(Err(_)) => Err(ClientError::ConnectionLost),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(ClientError::Timeout)
            }
        }
    }
}
