//! Private key operations.
//!
//! [`LocalKey`] uses only the safe aws-lc-rs API. That API signs a
//! caller-supplied digest (`sign_digest`), but only for the algorithm
//! combinations TLS 1.2/1.3 actually negotiate, so compared to gokeyless the
//! following are deliberately unsupported (answered with `ErrBadOpcode`):
//! MD5+SHA1, SHA-1 and SHA-224 signatures, ECDSA with a hash that does not
//! match the curve (except P-521, which supports SHA-224 through SHA-512), and raw RSA
//! decryption (RSA key exchange).

use aws_lc_rs::digest::{self, Digest};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, RsaEncoding};
use keyless_protocol::{HashAlg, KeyKind, SignAlg, SignParams, SpkiError};
use rustls_pki_types::PrivateKeyDer;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("operation {0:?} does not match key type {1:?}")]
    Mismatch(SignAlg, KeyKind),
    #[error("payload length {got} does not match digest length {want}")]
    BadDigestLength { got: usize, want: usize },
    /// The key type supports the operation family but not this variant
    /// (e.g. a legacy hash). Reported to clients as `ErrBadOpcode`.
    #[error("operation not supported by this key")]
    Unsupported,
    #[error("unsupported or malformed private key")]
    Parse,
    #[error(transparent)]
    Spki(#[from] SpkiError),
    #[error("signing failed")]
    Crypto,
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// A private key that can serve Keyless operations. Implement this for keys
/// held in an HSM, a cloud KMS, etc.; [`LocalKey`] covers in-memory keys.
///
/// Methods are synchronous and are invoked on a blocking thread pool.
pub trait PrivateKey: Send + Sync + 'static {
    /// DER SubjectPublicKeyInfo of the public half.
    fn spki(&self) -> &[u8];

    /// Signs `input`, which is a digest computed with `params.hash` (or the
    /// full message for Ed25519). ECDSA signatures must be ASN.1 DER.
    fn sign(&self, params: SignParams, input: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// Raw RSA decryption without padding removal, for RSA key exchange.
    /// Unsupported by default; implementations must not reveal padding
    /// validity (Bleichenbacher).
    fn decrypt_raw(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        Err(KeyError::Unsupported)
    }
}

/// An in-memory private key (RSA, ECDSA P-256/384/521 or Ed25519).
pub struct LocalKey {
    inner: Inner,
    kind: KeyKind,
    spki: Vec<u8>,
}

enum Inner {
    Rsa(RsaKeyPair),
    /// aws-lc-rs binds an ECDSA key pair to one digest, so keep one per
    /// digest the curve supports.
    Ecdsa(Vec<(&'static digest::Algorithm, EcdsaKeyPair)>),
    Ed25519(Ed25519KeyPair),
}

impl std::fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKey").field("kind", &self.kind).finish_non_exhaustive()
    }
}

/// Signing algorithms per curve, primary (curve-matched) one first.
const CURVES: [&[(&EcdsaSigningAlgorithm, &digest::Algorithm)]; 3] = [
    &[(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &digest::SHA256)],
    &[(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &digest::SHA384)],
    &[
        (&signature::ECDSA_P521_SHA512_ASN1_SIGNING, &digest::SHA512),
        (&signature::ECDSA_P521_SHA384_ASN1_SIGNING, &digest::SHA384),
        (&signature::ECDSA_P521_SHA256_ASN1_SIGNING, &digest::SHA256),
        (&signature::ECDSA_P521_SHA224_ASN1_SIGNING, &digest::SHA224),
    ],
];

impl LocalKey {
    /// Parses a PEM file containing a PKCS#8, PKCS#1 (RSA) or SEC1 (EC) key.
    pub fn from_pem(pem: &[u8]) -> Result<LocalKey, KeyError> {
        use rustls_pki_types::pem::PemObject;
        let der = PrivateKeyDer::from_pem_slice(pem).map_err(|_| KeyError::Parse)?;
        LocalKey::from_der(&der)
    }

    /// Parses PEM, falling back to auto-detected DER.
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<LocalKey, KeyError> {
        LocalKey::from_pem(bytes).or_else(|_| {
            let der = PrivateKeyDer::try_from(bytes).map_err(|_| KeyError::Parse)?;
            LocalKey::from_der(&der)
        })
    }

    pub fn from_der(der: &PrivateKeyDer<'_>) -> Result<LocalKey, KeyError> {
        let bytes = der.secret_der();
        let inner = match der {
            PrivateKeyDer::Pkcs1(_) => Inner::Rsa(RsaKeyPair::from_der(bytes).map_err(|_| KeyError::Parse)?),
            PrivateKeyDer::Sec1(_) => parse_ecdsa(bytes)?,
            PrivateKeyDer::Pkcs8(_) => RsaKeyPair::from_pkcs8(bytes)
                .map(Inner::Rsa)
                .or_else(|_| parse_ecdsa(bytes))
                .or_else(|_| Ed25519KeyPair::from_pkcs8_maybe_unchecked(bytes).map(Inner::Ed25519))
                .map_err(|_| KeyError::Parse)?,
            _ => return Err(KeyError::Parse),
        };
        let spki = match &inner {
            Inner::Rsa(kp) => kp.public_key().as_der().map(|d| d.as_ref().to_vec()),
            Inner::Ecdsa(kps) => kps[0].1.public_key().as_der().map(|d| d.as_ref().to_vec()),
            Inner::Ed25519(kp) => kp.public_key().as_der().map(|d| d.as_ref().to_vec()),
        }
        .map_err(|_| KeyError::Parse)?;
        let kind = KeyKind::from_spki(&spki)?;
        Ok(LocalKey { inner, kind, spki })
    }

    pub fn kind(&self) -> KeyKind {
        self.kind
    }
}

/// Parses a SEC1 or PKCS#8 EC key, trying each supported curve.
fn parse_ecdsa(der: &[u8]) -> Result<Inner, KeyError> {
    for algs in CURVES {
        if EcdsaKeyPair::from_private_key_der(algs[0].0, der).is_err() {
            continue;
        }
        let pairs = algs
            .iter()
            .map(|(alg, hash)| Ok((*hash, EcdsaKeyPair::from_private_key_der(alg, der).map_err(|_| KeyError::Parse)?)))
            .collect::<Result<_, KeyError>>()?;
        return Ok(Inner::Ecdsa(pairs));
    }
    Err(KeyError::Parse)
}

fn digest_alg(hash: HashAlg) -> Option<&'static digest::Algorithm> {
    match hash {
        HashAlg::Sha224 => Some(&digest::SHA224),
        HashAlg::Sha256 => Some(&digest::SHA256),
        HashAlg::Sha384 => Some(&digest::SHA384),
        HashAlg::Sha512 => Some(&digest::SHA512),
        HashAlg::None | HashAlg::Md5Sha1 | HashAlg::Sha1 => None,
    }
}

impl PrivateKey for LocalKey {
    fn spki(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, params: SignParams, input: &[u8]) -> Result<Vec<u8>, KeyError> {
        if let Some(want) = params.hash.output_len() {
            if input.len() != want {
                return Err(KeyError::BadDigestLength { got: input.len(), want });
            }
        }
        let imported = || -> Result<Digest, KeyError> {
            let alg = digest_alg(params.hash).ok_or(KeyError::Unsupported)?;
            Digest::import_less_safe(input, alg).map_err(|_| KeyError::Crypto)
        };

        match (&self.inner, params.alg) {
            (Inner::Ed25519(kp), SignAlg::Ed25519) => Ok(kp.sign(input).as_ref().to_vec()),
            (Inner::Ecdsa(pairs), SignAlg::Ecdsa) => {
                let digest = imported()?;
                let (_, kp) = pairs
                    .iter()
                    .find(|(alg, _)| *alg == digest.algorithm())
                    .ok_or(KeyError::Unsupported)?;
                Ok(kp.sign_digest(&digest).map_err(|_| KeyError::Crypto)?.as_ref().to_vec())
            }
            (Inner::Rsa(kp), SignAlg::RsaPkcs1 | SignAlg::RsaPss) => {
                let encoding: &'static dyn RsaEncoding = match (params.alg, params.hash) {
                    (SignAlg::RsaPkcs1, HashAlg::Sha256) => &signature::RSA_PKCS1_SHA256,
                    (SignAlg::RsaPkcs1, HashAlg::Sha384) => &signature::RSA_PKCS1_SHA384,
                    (SignAlg::RsaPkcs1, HashAlg::Sha512) => &signature::RSA_PKCS1_SHA512,
                    (SignAlg::RsaPss, HashAlg::Sha256) => &signature::RSA_PSS_SHA256,
                    (SignAlg::RsaPss, HashAlg::Sha384) => &signature::RSA_PSS_SHA384,
                    (SignAlg::RsaPss, HashAlg::Sha512) => &signature::RSA_PSS_SHA512,
                    _ => return Err(KeyError::Unsupported),
                };
                let mut sig = vec![0; kp.public_modulus_len()];
                kp.sign_digest(encoding, &imported()?, &mut sig).map_err(|_| KeyError::Crypto)?;
                Ok(sig)
            }
            (_, alg) => Err(KeyError::Mismatch(alg, self.kind)),
        }
    }
}
