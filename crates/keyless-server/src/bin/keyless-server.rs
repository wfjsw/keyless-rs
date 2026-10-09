#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use keyless_server::{mtls_server_config, Server, ServerConfig, SkiKeystore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Keyless SSL key server (gokeyless compatible).
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "KEYLESS_LISTEN", default_value = "0.0.0.0:2407")]
    listen: SocketAddr,
    /// Certificate chain this server presents to keyless clients (PEM).
    #[arg(long, env = "KEYLESS_AUTH_CERT", default_value = "server.pem")]
    auth_cert: PathBuf,
    /// Private key for --auth-cert (PEM).
    #[arg(long, env = "KEYLESS_AUTH_KEY", default_value = "server-key.pem")]
    auth_key: PathBuf,
    /// CA that issues keyless client certificates (PEM).
    #[arg(long, env = "KEYLESS_CLOUDFLARE_CA_CERT", default_value = "keyless_cacert.pem")]
    cloudflare_ca_cert: PathBuf,
    /// Directories searched recursively for `*.key` private keys.
    #[arg(long = "private-key-dirs", env = "KEYLESS_PRIVATE_KEY_DIRS", value_delimiter = ',')]
    private_key_dirs: Vec<PathBuf>,
    /// Individual private key files.
    #[arg(long = "private-key-files", value_delimiter = ',')]
    private_key_files: Vec<PathBuf>,
    /// Seconds an idle connection is kept open.
    #[arg(long, default_value_t = 30)]
    idle_timeout: u64,
    /// Maximum concurrent requests per connection.
    #[arg(long, default_value_t = 1024)]
    max_pending: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keyless_server=info".into()),
        )
        .init();
    let args = Args::parse();

    let keystore = SkiKeystore::new();
    for dir in &args.private_key_dirs {
        keystore.add_dir(dir)?;
    }
    for file in &args.private_key_files {
        keystore.add_file(file)?;
    }
    if keystore.is_empty() {
        tracing::warn!("no private keys loaded");
    }

    let chain = CertificateDer::pem_file_iter(&args.auth_cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&args.auth_key)?;
    let ca = CertificateDer::pem_file_iter(&args.cloudflare_ca_cert)?.collect::<Result<Vec<_>, _>>()?;
    let tls = mtls_server_config(chain, key, ca)?;

    let server = Server::new(Arc::new(tls), keystore).with_config(ServerConfig {
        idle_timeout: Duration::from_secs(args.idle_timeout),
        max_pending_per_connection: args.max_pending,
        ..ServerConfig::default()
    });
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, keys = server.keystore().len(), "listening");
    Arc::new(server).serve(listener).await?;
    Ok(())
}
