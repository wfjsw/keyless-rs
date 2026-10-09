#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use keyless_client::{mtls_client_config, ClientConfig, KeylessClient};
use keyless_server::{mtls_server_config, LocalKey, Server, ServerConfig, SkiKeystore};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SignatureAlgorithm,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

/// A throwaway CA plus the mTLS identities of a key server and its client.
pub struct Pki {
    pub ca: CertifiedIssuer<'static, KeyPair>,
    pub server: (CertificateDer<'static>, PrivateKeyDer<'static>),
    pub client: (CertificateDer<'static>, PrivateKeyDer<'static>),
}

impl Pki {
    pub fn new() -> Pki {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "Keyless Test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let mut pki = Pki {
            server: (CertificateDer::from(vec![]), PrivateKeyDer::Pkcs8(vec![].into())),
            client: (CertificateDer::from(vec![]), PrivateKeyDer::Pkcs8(vec![].into())),
            ca,
        };
        pki.server = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        pki.client = pki.leaf("keyless-client", ExtendedKeyUsagePurpose::ClientAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        pki
    }

    pub fn ca_der(&self) -> CertificateDer<'static> {
        self.ca.der().clone()
    }

    /// Issues a certificate for `name` with a fresh key of type `alg`.
    pub fn leaf(
        &self,
        name: &str,
        eku: ExtendedKeyUsagePurpose,
        alg: &'static SignatureAlgorithm,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate_for(alg).unwrap();
        let cert = self.cert_for(name, eku, &key);
        (cert, PrivateKeyDer::Pkcs8(key.serialize_der().into()))
    }

    /// Issues a certificate for `name` over an existing key.
    pub fn cert_for(&self, name: &str, eku: ExtendedKeyUsagePurpose, key: &KeyPair) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = vec![eku];
        params.signed_by(key, &self.ca).unwrap().der().clone()
    }

    pub fn client_tls(&self) -> Arc<rustls::ClientConfig> {
        Arc::new(mtls_client_config([self.ca_der()], vec![self.client.0.clone()], self.client.1.clone_key()).unwrap())
    }
}

/// Keys of every supported type, with their keystore loaded.
pub struct Keys {
    pub rsa: KeyPair,
    pub p256: KeyPair,
    pub p384: KeyPair,
    pub p521: KeyPair,
    pub ed25519: KeyPair,
    pub keystore: Arc<SkiKeystore>,
}

impl Keys {
    pub fn new() -> Keys {
        let keys = Keys {
            rsa: KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap(),
            p256: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
            p384: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap(),
            p521: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap(),
            ed25519: KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
            keystore: Arc::new(SkiKeystore::new()),
        };
        for kp in keys.all() {
            let key = LocalKey::from_pem(kp.serialize_pem().as_bytes()).unwrap();
            keys.keystore.add(Arc::new(key)).unwrap();
        }
        keys
    }

    pub fn all(&self) -> [&KeyPair; 5] {
        [&self.rsa, &self.p256, &self.p384, &self.p521, &self.ed25519]
    }
}

/// Starts a key server on an ephemeral port.
pub async fn start_server(pki: &Pki, keystore: Arc<SkiKeystore>, config: ServerConfig) -> SocketAddr {
    let tls = mtls_server_config(vec![pki.server.0.clone()], pki.server.1.clone_key(), [pki.ca_der()]).unwrap();
    let server = Arc::new(Server::new(Arc::new(tls), keystore).with_config(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve(listener));
    addr
}

pub fn client(pki: &Pki, addr: SocketAddr) -> KeylessClient {
    let config = ClientConfig {
        server_name: Some(ServerName::try_from("localhost").unwrap()),
        ..ClientConfig::default()
    };
    KeylessClient::with_config(addr.to_string(), pki.client_tls(), config).unwrap()
}
