//! Exercises a key server (gokeyless or keyless-server) end to end:
//! pings it, signs with every scheme each certificate's key supports,
//! verifies the signatures locally, and completes real rustls TLS 1.2 and 1.3
//! handshakes whose signatures are produced remotely. The certificates in
//! <cert-dir> must be issued by <ca.pem>.
//!
//! cargo run --example keyless-check -- <keyserver host:port> <server-name> \
//!     <ca.pem> <client.pem> <client-key.pem> <cert-dir>

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;

use aws_lc_rs::signature::{self, VerificationAlgorithm};
use keyless_client::{mtls_client_config, ClientConfig, KeylessClient, KeylessSigningKey};
use keyless_protocol::{certificate_spki, spki_public_key};
use rustls::sign::SingleCertAndKey;
use rustls::SignatureScheme as S;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, server_name, ca, cert, key, cert_dir] = args.as_slice() else {
        return Err("usage: keyless-check <addr> <server-name> <ca.pem> <client.pem> <client-key.pem> <cert-dir>".into());
    };
    let ca = CertificateDer::from_pem_file(ca)?;
    let tls = mtls_client_config([ca.clone()], vec![CertificateDer::from_pem_file(cert)?], PrivateKeyDer::from_pem_file(key)?)?;
    let config = ClientConfig { server_name: Some(ServerName::try_from(server_name.clone())?), ..Default::default() };
    let client = KeylessClient::with_config(addr.clone(), Arc::new(tls), config)?;

    assert_eq!(client.ping(b"keyless-check").await?, b"keyless-check");
    println!("ping ok");

    let mut failures = 0;
    for entry in std::fs::read_dir(cert_dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "crt") {
            failures += check_cert(&client, &ca, &path).await?;
        }
    }
    if failures > 0 {
        return Err(format!("{failures} checks failed").into());
    }
    println!("all checks passed");
    Ok(())
}

async fn check_cert(client: &KeylessClient, ca: &CertificateDer<'static>, path: &Path) -> Result<usize, Error> {
    let cert = CertificateDer::from_pem_file(path)?;
    let key = KeylessSigningKey::from_certificate(client.clone(), &cert)?;
    let spki = certificate_spki(&cert)?;
    println!("{}: {:?} ski={}", path.display(), key.kind(), key.ski());

    let message = b"keyless-check transcript";
    let mut failures = 0;
    for (scheme, verify) in schemes() {
        let Some(signer) = rustls::sign::SigningKey::choose_scheme(&key, &[scheme]) else { continue };
        let result = tokio::task::spawn_blocking(move || signer.sign(message)).await?;
        let verified = result.as_ref().ok().map(|sig| {
            signature::UnparsedPublicKey::new(verify, spki_public_key(spki).unwrap()).verify(message, sig).is_ok()
        });
        println!("  sign {scheme:?}: {}", match (&result, verified) {
            (Ok(_), Some(true)) => "ok, verified".to_string(),
            (Ok(_), _) => { failures += 1; "SIGNATURE INVALID".to_string() }
            (Err(e), _) => { failures += 1; format!("ERROR {e}") }
        });
    }

    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![cert.clone()], Arc::new(key)));
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let result = tokio::task::spawn_blocking({
            let (certified, ca, cert) = (certified.clone(), ca.clone(), cert.clone());
            move || handshake(certified, ca, &cert, version)
        })
        .await?;
        match result {
            Ok(scheme) => println!("  rustls {:?} handshake: ok ({scheme:?})", version.version),
            Err(e) => {
                failures += 1;
                println!("  rustls {:?} handshake: FAILED {e}", version.version)
            }
        }
    }
    Ok(failures)
}

fn schemes() -> [(S, &'static dyn VerificationAlgorithm); 9] {
    [
        (S::RSA_PKCS1_SHA256, &signature::RSA_PKCS1_2048_8192_SHA256),
        (S::RSA_PKCS1_SHA384, &signature::RSA_PKCS1_2048_8192_SHA384),
        (S::RSA_PKCS1_SHA512, &signature::RSA_PKCS1_2048_8192_SHA512),
        (S::RSA_PSS_SHA256, &signature::RSA_PSS_2048_8192_SHA256),
        (S::RSA_PSS_SHA384, &signature::RSA_PSS_2048_8192_SHA384),
        (S::RSA_PSS_SHA512, &signature::RSA_PSS_2048_8192_SHA512),
        (S::ECDSA_NISTP256_SHA256, &signature::ECDSA_P256_SHA256_ASN1),
        (S::ECDSA_NISTP384_SHA384, &signature::ECDSA_P384_SHA384_ASN1),
        (S::ED25519, &signature::ED25519),
    ]
}

/// In-memory handshake between a rustls server using the remote key and a
/// rustls client that trusts `ca`. Returns the negotiated cipher suite.
fn handshake(
    certified: Arc<rustls::sign::CertifiedKey>,
    ca: CertificateDer<'static>,
    cert: &CertificateDer<'static>,
    version: &'static rustls::SupportedProtocolVersion,
) -> Result<rustls::CipherSuite, Error> {
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca)?;
    let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Connect using whatever DNS name the certificate carries.
    let name = ServerName::try_from(first_dns_name(cert).ok_or("certificate has no DNS name")?)?;
    let mut server: rustls::Connection = rustls::ServerConnection::new(Arc::new(server_config))?.into();
    let mut client: rustls::Connection = rustls::ClientConnection::new(Arc::new(client_config), name)?.into();
    while client.is_handshaking() || server.is_handshaking() {
        pump(&mut client, &mut server)?;
        pump(&mut server, &mut client)?;
    }
    Ok(client.negotiated_cipher_suite().map(|s| s.suite()).ok_or("no suite")?)
}

fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) -> Result<(), Error> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf)?;
    }
    let mut rd = buf.as_slice();
    while !rd.is_empty() {
        to.read_tls(&mut rd)?;
        to.process_new_packets()?;
    }
    Ok(())
}

/// Finds the first dNSName SAN by scanning for its DER encoding; good enough
/// for test certificates.
fn first_dns_name(cert: &[u8]) -> Option<String> {
    cert.windows(2).enumerate().find_map(|(i, w)| {
        let len = w[1] as usize;
        let name = cert.get(i + 2..i + 2 + len)?;
        (w[0] == 0x82 && len > 3 && name.iter().all(|c| c.is_ascii_alphanumeric() || b".-".contains(c)) && name.contains(&b'.'))
            .then(|| String::from_utf8(name.to_vec()).ok())?
    })
}
