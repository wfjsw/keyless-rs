//! Minimal DER walking: just enough to find a certificate's
//! SubjectPublicKeyInfo and derive the key type and SKI from it.

use aws_lc_rs::digest;

use crate::Ski;

const SEQUENCE: u8 = 0x30;
const BIT_STRING: u8 = 0x03;
const OID: u8 = 0x06;
const CONTEXT_0: u8 = 0xA0;

const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpkiError {
    #[error("malformed DER")]
    Malformed,
    #[error("unsupported public key algorithm")]
    UnsupportedAlgorithm,
}

/// Public key type, as far as Keyless SSL is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Rsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

impl KeyKind {
    /// Identifies the key type of a DER SubjectPublicKeyInfo.
    pub fn from_spki(spki: &[u8]) -> Result<KeyKind, SpkiError> {
        let spki = Spki::parse(spki)?;
        match spki.alg_oid {
            OID_RSA_ENCRYPTION => Ok(KeyKind::Rsa),
            OID_ED25519 => Ok(KeyKind::Ed25519),
            OID_EC_PUBLIC_KEY => {
                let curve = Tlv::read(spki.params)?;
                if curve.tag != OID {
                    return Err(SpkiError::UnsupportedAlgorithm);
                }
                match curve.contents {
                    OID_P256 => Ok(KeyKind::EcdsaP256),
                    OID_P384 => Ok(KeyKind::EcdsaP384),
                    OID_P521 => Ok(KeyKind::EcdsaP521),
                    _ => Err(SpkiError::UnsupportedAlgorithm),
                }
            }
            _ => Err(SpkiError::UnsupportedAlgorithm),
        }
    }
}

/// Computes the gokeyless Subject Key Identifier of a DER SubjectPublicKeyInfo:
/// SHA-1 over the contents of the `subjectPublicKey` BIT STRING (excluding
/// the unused-bits octet), i.e. RFC 5280 section 4.2.1.2 method (1).
pub fn ski_from_spki(spki: &[u8]) -> Result<Ski, SpkiError> {
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, spki_public_key(spki)?);
    let mut ski = [0; 20];
    ski.copy_from_slice(hash.as_ref());
    Ok(Ski(ski))
}

/// Returns the contents of an SPKI's `subjectPublicKey` BIT STRING: the
/// PKCS#1 `RSAPublicKey`, the EC point, or the raw Ed25519 key. This is the
/// form signature verifiers such as `aws_lc_rs::signature` expect.
pub fn spki_public_key(spki: &[u8]) -> Result<&[u8], SpkiError> {
    Ok(Spki::parse(spki)?.key)
}

/// Returns the DER SubjectPublicKeyInfo element of an X.509 certificate.
pub fn certificate_spki(cert: &[u8]) -> Result<&[u8], SpkiError> {
    let tbs = expect(cert, SEQUENCE)?.0;
    let mut rest = expect(tbs, SEQUENCE)?.0;
    if rest.first() == Some(&CONTEXT_0) {
        rest = Tlv::read(rest)?.rest; // version
    }
    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        rest = Tlv::read(rest)?.rest;
    }
    let spki = Tlv::read(rest)?;
    if spki.tag != SEQUENCE {
        return Err(SpkiError::Malformed);
    }
    Ok(spki.element)
}

/// The parts of a SubjectPublicKeyInfo we care about.
struct Spki<'a> {
    alg_oid: &'a [u8],
    /// Remaining AlgorithmIdentifier contents (the curve OID for EC keys).
    params: &'a [u8],
    /// `subjectPublicKey` BIT STRING contents, minus the unused-bits octet.
    key: &'a [u8],
}

impl<'a> Spki<'a> {
    fn parse(spki: &'a [u8]) -> Result<Spki<'a>, SpkiError> {
        let (body, trailing) = expect(spki, SEQUENCE)?;
        if !trailing.is_empty() {
            return Err(SpkiError::Malformed);
        }
        let (alg_id, rest) = expect(body, SEQUENCE)?;
        let (alg_oid, params) = expect(alg_id, OID)?;
        let (bits, _) = expect(rest, BIT_STRING)?;
        match bits.split_first() {
            Some((0, key)) => Ok(Spki { alg_oid, params, key }),
            _ => Err(SpkiError::Malformed),
        }
    }
}

/// Reads a TLV with tag `want`, returning (contents, rest of input).
fn expect(input: &[u8], want: u8) -> Result<(&[u8], &[u8]), SpkiError> {
    let tlv = Tlv::read(input)?;
    if tlv.tag != want {
        return Err(SpkiError::Malformed);
    }
    Ok((tlv.contents, tlv.rest))
}

struct Tlv<'a> {
    tag: u8,
    contents: &'a [u8],
    /// The whole encoded element, header included.
    element: &'a [u8],
    /// Input following the element.
    rest: &'a [u8],
}

impl<'a> Tlv<'a> {
    fn read(input: &'a [u8]) -> Result<Tlv<'a>, SpkiError> {
        let [tag, first, rest @ ..] = input else {
            return Err(SpkiError::Malformed);
        };
        if tag & 0x1F == 0x1F {
            return Err(SpkiError::Malformed); // high tag numbers never occur here
        }
        let (len, rest) = match *first {
            n @ 0..=0x7F => (n as usize, rest),
            0x81..=0x84 => {
                let n = (first & 0x7F) as usize;
                let (len_bytes, rest) = rest.split_at_checked(n).ok_or(SpkiError::Malformed)?;
                let len = len_bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
                (len, rest)
            }
            _ => return Err(SpkiError::Malformed),
        };
        let (contents, rest) = rest.split_at_checked(len).ok_or(SpkiError::Malformed)?;
        let element = &input[..input.len() - rest.len()];
        Ok(Tlv { tag: *tag, contents, element, rest })
    }
}
