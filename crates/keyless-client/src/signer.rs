use std::net::IpAddr;
use std::sync::Arc;

use aws_lc_rs::digest;
use keyless_protocol::{certificate_spki, ski_from_spki, KeyKind, Op, Operation, Ski, SpkiError};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use rustls_pki_types::{CertificateDer, SubjectPublicKeyInfoDer};

use crate::client::{ClientError, KeylessClient};

/// Optional request fields some key servers use for key selection, logging
/// or policy (gokeyless ignores them with its default keystore).
#[derive(Clone, Debug, Default)]
pub struct RequestMetadata {
    pub sni: String,
    pub client_ip: Option<IpAddr>,
    pub server_ip: Option<IpAddr>,
    pub cert_id: String,
}

/// A [`SigningKey`] whose private half lives on a Keyless key server.
///
/// rustls calls [`Signer::sign`] synchronously in the middle of the
/// handshake, so signing blocks the calling thread for one key server round
/// trip (see [`KeylessClient::execute_blocking`]).
#[derive(Clone)]
pub struct KeylessSigningKey {
    inner: Arc<KeyInner>,
}

struct KeyInner {
    client: KeylessClient,
    ski: Ski,
    kind: KeyKind,
    spki: Vec<u8>,
    metadata: RequestMetadata,
}

impl std::fmt::Debug for KeylessSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessSigningKey")
            .field("ski", &self.inner.ski)
            .field("kind", &self.inner.kind)
            .field("keyserver", &self.inner.client.addr())
            .finish()
    }
}

impl KeylessSigningKey {
    /// A remote key identified by its DER SubjectPublicKeyInfo.
    pub fn from_spki(client: KeylessClient, spki: &[u8]) -> Result<Self, SpkiError> {
        Ok(KeylessSigningKey {
            inner: Arc::new(KeyInner {
                client,
                ski: ski_from_spki(spki)?,
                kind: KeyKind::from_spki(spki)?,
                spki: spki.to_vec(),
                metadata: RequestMetadata::default(),
            }),
        })
    }

    /// The remote key matching `cert`'s public key.
    pub fn from_certificate(client: KeylessClient, cert: &CertificateDer<'_>) -> Result<Self, SpkiError> {
        KeylessSigningKey::from_spki(client, certificate_spki(cert)?)
    }

    /// A [`CertifiedKey`] for `chain` (leaf first) whose key is remote.
    pub fn certified_key(
        client: KeylessClient,
        chain: Vec<CertificateDer<'static>>,
    ) -> Result<CertifiedKey, SpkiError> {
        let leaf = chain.first().ok_or(SpkiError::Malformed)?;
        let key = KeylessSigningKey::from_certificate(client, leaf)?;
        Ok(CertifiedKey::new(chain, Arc::new(key)))
    }

    /// Returns a copy that sends `metadata` with every request.
    pub fn with_metadata(&self, metadata: RequestMetadata) -> Self {
        let i = &self.inner;
        KeylessSigningKey {
            inner: Arc::new(KeyInner {
                client: i.client.clone(),
                ski: i.ski,
                kind: i.kind,
                spki: i.spki.clone(),
                metadata,
            }),
        }
    }

    pub fn ski(&self) -> Ski {
        self.inner.ski
    }

    pub fn kind(&self) -> KeyKind {
        self.inner.kind
    }

    /// Signs `message` with `scheme` without going through rustls.
    pub async fn sign_async(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        if !self.schemes().contains(&scheme) {
            return Err(ClientError::UnsupportedScheme(scheme));
        }
        let op = self.inner.operation(scheme, message).ok_or(ClientError::UnsupportedScheme(scheme))?;
        self.inner.client.execute(op).await
    }

    fn schemes(&self) -> &'static [SignatureScheme] {
        match self.inner.kind {
            // Same preference order as rustls's own RSA key.
            KeyKind::Rsa => &[
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ],
            KeyKind::EcdsaP256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            KeyKind::EcdsaP384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            KeyKind::EcdsaP521 => &[SignatureScheme::ECDSA_NISTP521_SHA512],
            KeyKind::Ed25519 => &[SignatureScheme::ED25519],
        }
    }
}

impl KeyInner {
    /// Maps a TLS signature scheme to a Keyless request. The key server
    /// receives the digest, never the handshake transcript (except Ed25519,
    /// which signs the message itself).
    fn operation(&self, scheme: SignatureScheme, message: &[u8]) -> Option<Operation> {
        use SignatureScheme as S;
        let (opcode, alg) = match scheme {
            S::RSA_PKCS1_SHA256 => (Op::RSA_SIGN_SHA256, &digest::SHA256),
            S::RSA_PKCS1_SHA384 => (Op::RSA_SIGN_SHA384, &digest::SHA384),
            S::RSA_PKCS1_SHA512 => (Op::RSA_SIGN_SHA512, &digest::SHA512),
            S::RSA_PSS_SHA256 => (Op::RSA_PSS_SIGN_SHA256, &digest::SHA256),
            S::RSA_PSS_SHA384 => (Op::RSA_PSS_SIGN_SHA384, &digest::SHA384),
            S::RSA_PSS_SHA512 => (Op::RSA_PSS_SIGN_SHA512, &digest::SHA512),
            S::ECDSA_NISTP256_SHA256 => (Op::ECDSA_SIGN_SHA256, &digest::SHA256),
            S::ECDSA_NISTP384_SHA384 => (Op::ECDSA_SIGN_SHA384, &digest::SHA384),
            S::ECDSA_NISTP521_SHA512 => (Op::ECDSA_SIGN_SHA512, &digest::SHA512),
            S::ED25519 => return Some(self.request(Op::ED25519_SIGN, message.to_vec())),
            _ => return None,
        };
        Some(self.request(opcode, digest::digest(alg, message).as_ref().to_vec()))
    }

    fn request(&self, opcode: Op, payload: Vec<u8>) -> Operation {
        let m = &self.metadata;
        Operation {
            opcode,
            payload,
            ski: Some(self.ski),
            sni: m.sni.clone(),
            client_ip: m.client_ip,
            server_ip: m.server_ip,
            cert_id: m.cert_id.clone(),
            ..Default::default()
        }
    }
}

impl SigningKey for KeylessSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self.schemes().iter().find(|s| offered.contains(s))?;
        Some(Box::new(KeylessSigner { key: self.inner.clone(), scheme: *scheme }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.inner.spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.inner.kind {
            KeyKind::Rsa => SignatureAlgorithm::RSA,
            KeyKind::EcdsaP256 | KeyKind::EcdsaP384 | KeyKind::EcdsaP521 => SignatureAlgorithm::ECDSA,
            KeyKind::Ed25519 => SignatureAlgorithm::ED25519,
        }
    }
}

struct KeylessSigner {
    key: Arc<KeyInner>,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for KeylessSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessSigner").field("ski", &self.key.ski).field("scheme", &self.scheme).finish()
    }
}

impl Signer for KeylessSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let op = self
            .key
            .operation(self.scheme, message)
            .ok_or_else(|| rustls::Error::General(format!("keyless: unsupported scheme {:?}", self.scheme)))?;
        self.key.client.execute_blocking(op).map_err(|e| {
            tracing::warn!(ski = %self.key.ski, scheme = ?self.scheme, error = %e, "remote signing failed");
            rustls::Error::General(format!("keyless: {e}"))
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
