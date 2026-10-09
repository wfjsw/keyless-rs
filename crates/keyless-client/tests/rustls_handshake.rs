//! Full TLS handshakes where the terminating rustls server holds only the
//! certificate; the private key lives on the key server.

mod common;

use std::sync::Arc;

use common::{client, start_server, Keys, Pki};
use keyless_client::{KeylessClient, KeylessSigningKey};
use keyless_server::ServerConfig;
use rcgen::{ExtendedKeyUsagePurpose, KeyPair};
use rustls::sign::SingleCertAndKey;
use rustls::{RootCertStore, SupportedProtocolVersion};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The TLS terminator: knows the certificate, delegates signing.
fn frontend_config(pki: &Pki, keyless: &KeylessClient, key: &KeyPair) -> Arc<rustls::ServerConfig> {
    let cert = pki.cert_for("example.test", ExtendedKeyUsagePurpose::ServerAuth, key);
    let certified = KeylessSigningKey::certified_key(keyless.clone(), vec![cert]).unwrap();
    certified.keys_match().unwrap();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified))),
    )
}

/// An ordinary TLS client (a browser, say) that trusts the test CA.
fn browser_config(pki: &Pki, version: &'static SupportedProtocolVersion) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[version])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

const VERSIONS: [&SupportedProtocolVersion; 2] = [&rustls::version::TLS13, &rustls::version::TLS12];

async fn handshake_all(pki: &Pki, keys: &Keys, keyless: &KeylessClient) {
    for key in keys.all() {
        let acceptor = tokio_rustls::TlsAcceptor::from(frontend_config(pki, keyless, key));
        for version in VERSIONS {
            let connector = tokio_rustls::TlsConnector::from(browser_config(pki, version));
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);

            let server = tokio::spawn({
                let acceptor = acceptor.clone();
                async move {
                    let mut tls = acceptor.accept(server_io).await.expect("server handshake");
                    let mut buf = [0u8; 5];
                    tls.read_exact(&mut buf).await.unwrap();
                    tls.write_all(&buf).await.unwrap();
                    tls.flush().await.unwrap();
                }
            });
            let name = ServerName::try_from("example.test").unwrap();
            let mut tls = connector.connect(name, client_io).await.unwrap_or_else(|e| {
                panic!("handshake with {:?} key over {:?} failed: {e}", key.algorithm(), version.version)
            });
            assert_eq!(tls.get_ref().1.protocol_version(), Some(version.version));
            tls.write_all(b"hello").await.unwrap();
            let mut echo = [0u8; 5];
            tls.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"hello");
            server.await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn handshakes_on_multi_thread_runtime() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;
    handshake_all(&pki, &keys, &client(&pki, addr)).await;
}

#[test]
fn handshakes_on_current_thread_runtime() {
    // Signing blocks the only runtime thread for one round trip; the
    // client's dedicated runtime keeps that from deadlocking. The key server
    // gets its own runtime, as it would be on another machine: anything else
    // sharing the blocked current-thread runtime stalls during signing.
    let pki = Pki::new();
    let keys = Keys::new();
    let key_server_rt = tokio::runtime::Runtime::new().unwrap();
    let addr = key_server_rt.block_on(start_server(&pki, keys.keystore.clone(), ServerConfig::default()));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(handshake_all(&pki, &keys, &client(&pki, addr)));
}

#[test]
fn handshake_with_plain_synchronous_rustls() {
    let pki = Pki::new();
    let keys = Keys::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = rt.block_on(start_server(&pki, keys.keystore.clone(), ServerConfig::default()));
    let keyless = client(&pki, addr);

    for key in keys.all() {
        for version in VERSIONS {
            let mut server: rustls::Connection =
                rustls::ServerConnection::new(frontend_config(&pki, &keyless, key)).unwrap().into();
            let mut client: rustls::Connection = rustls::ClientConnection::new(
                browser_config(&pki, version),
                ServerName::try_from("example.test").unwrap(),
            )
            .unwrap()
            .into();

            while client.is_handshaking() || server.is_handshaking() {
                pump(&mut client, &mut server);
                pump(&mut server, &mut client);
            }
            assert_eq!(client.protocol_version(), Some(version.version));
        }
    }
}

fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    if !buf.is_empty() {
        let mut rd = buf.as_slice();
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
            to.process_new_packets().unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_fails_cleanly_when_key_server_lacks_the_key() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;
    let keyless = client(&pki, addr);

    let stranger = KeyPair::generate().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(frontend_config(&pki, &keyless, &stranger));
    let connector = tokio_rustls::TlsConnector::from(browser_config(&pki, &rustls::version::TLS13));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move { acceptor.accept(server_io).await.map(|_| ()) });
    let result = connector.connect(ServerName::try_from("example.test").unwrap(), client_io).await;
    assert!(result.is_err());
    let err = server.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("key not found"), "{err}");
}
