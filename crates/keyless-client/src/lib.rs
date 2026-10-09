//! Client for Keyless SSL key servers (gokeyless or `keyless-server`), and a
//! [`rustls::sign::SigningKey`] implementation that performs the TLS
//! handshake signature on the remote key server.
//!
//! ```no_run
//! # fn demo(chain: Vec<rustls_pki_types::CertificateDer<'static>>, client_tls: rustls::ClientConfig)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use keyless_client::{KeylessClient, KeylessSigningKey};
//!
//! let client = KeylessClient::new("keyserver.example.com:2407", Arc::new(client_tls))?;
//! let certified = KeylessSigningKey::certified_key(client, chain)?;
//! let config = rustls::ServerConfig::builder()
//!     .with_no_client_auth()
//!     .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

mod client;
mod signer;

pub use client::{mtls_client_config, ClientConfig, ClientError, KeylessClient};
pub use signer::{KeylessSigningKey, RequestMetadata};

pub use keyless_protocol as protocol;
