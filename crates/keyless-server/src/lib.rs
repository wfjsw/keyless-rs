//! A Keyless SSL key server, wire-compatible with
//! [gokeyless](https://github.com/cloudflare/gokeyless).
//!
//! The server accepts mutually-authenticated TLS connections and performs
//! private key operations on behalf of TLS terminators that do not hold the
//! keys. Requests on a connection are processed concurrently and answered
//! out of order, matched by request ID.

#![forbid(unsafe_code)]

mod key;
mod keystore;
mod server;

pub use key::{KeyError, LocalKey, PrivateKey};
pub use keystore::{Keystore, KeystoreError, SkiKeystore};
pub use server::{mtls_server_config, CustomOp, IsLimited, Sealer, Server, ServerConfig};

pub use keyless_protocol as protocol;
