//! Wire format of the Keyless SSL protocol, byte-compatible with
//! [gokeyless](https://github.com/cloudflare/gokeyless).
//!
//! A message is an 8-byte [`Header`] followed by a body of TLV items
//! (1-byte tag, 2-byte big-endian length, value). Every message is padded with
//! a [`Tag::PADDING`] item to at least [`PADDED_LENGTH`] bytes so that the
//! request and response sizes do not leak which operation was performed.

#![forbid(unsafe_code)]

mod der;
mod message;

#[cfg(feature = "codec")]
pub mod codec;

pub use der::{certificate_spki, ski_from_spki, spki_public_key, KeyKind, SpkiError};
pub use message::{DecodeError, EncodeError, Header, Operation, Packet};

use std::fmt;

/// Protocol major version emitted by this implementation.
pub const VERSION_MAJOR: u8 = 1;
/// Protocol minor version emitted by this implementation.
pub const VERSION_MINOR: u8 = 0;
/// Size of the fixed message header.
pub const HEADER_LENGTH: usize = 8;
/// Minimum size of a whole message (header + body) after padding.
pub const PADDED_LENGTH: usize = 1024;

/// Tag identifying a TLV item in a message body.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub u8);

impl Tag {
    /// SHA-256 digest of an RSA modulus (legacy key lookup).
    pub const CERTIFICATE_DIGEST: Tag = Tag(0x01);
    /// SNI of the proxied TLS connection.
    pub const SERVER_NAME: Tag = Tag(0x02);
    /// IPv4/IPv6 address of the TLS client.
    pub const CLIENT_IP: Tag = Tag(0x03);
    /// SHA-1 Subject Key Identifier of the key to use.
    pub const SUBJECT_KEY_IDENTIFIER: Tag = Tag(0x04);
    /// IPv4/IPv6 address of the proxied TLS server.
    pub const SERVER_IP: Tag = Tag(0x05);
    /// Opaque certificate identifier.
    pub const CERT_ID: Tag = Tag(0x06);
    /// Requested operation, or the response status.
    pub const OPCODE: Tag = Tag(0x11);
    /// Payload to sign/decrypt, or the result.
    pub const PAYLOAD: Tag = Tag(0x12);
    /// Function name for [`Op::CUSTOM`].
    pub const CUSTOM_FUNC_NAME: Tag = Tag(0x13);
    /// Supplemental payload.
    pub const EXTRA: Tag = Tag(0x14);
    /// Binary encoded Jaeger span context.
    pub const JAEGER_SPAN: Tag = Tag(0x15);
    /// JSON request metadata.
    pub const REQ_CONTEXT: Tag = Tag(0x16);
    /// Compliance region of the operation.
    pub const COMPLIANCE_REGION: Tag = Tag(0x17);
    /// Meaningless padding.
    pub const PADDING: Tag = Tag(0x20);
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({:#04x})", self.0)
    }
}

/// Operation requested by a client, or status of a response.
///
/// Kept as an open newtype so unknown opcodes survive a decode/encode cycle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Op(pub u8);

impl Op {
    pub const RSA_DECRYPT: Op = Op(0x01);
    pub const RSA_SIGN_MD5SHA1: Op = Op(0x02);
    pub const RSA_SIGN_SHA1: Op = Op(0x03);
    pub const RSA_SIGN_SHA224: Op = Op(0x04);
    pub const RSA_SIGN_SHA256: Op = Op(0x05);
    pub const RSA_SIGN_SHA384: Op = Op(0x06);
    pub const RSA_SIGN_SHA512: Op = Op(0x07);

    pub const RSA_PSS_SIGN_SHA256: Op = Op(0x35);
    pub const RSA_PSS_SIGN_SHA384: Op = Op(0x36);
    pub const RSA_PSS_SIGN_SHA512: Op = Op(0x37);

    pub const ECDSA_SIGN_MD5SHA1: Op = Op(0x12);
    pub const ECDSA_SIGN_SHA1: Op = Op(0x13);
    pub const ECDSA_SIGN_SHA224: Op = Op(0x14);
    pub const ECDSA_SIGN_SHA256: Op = Op(0x15);
    pub const ECDSA_SIGN_SHA384: Op = Op(0x16);
    pub const ECDSA_SIGN_SHA512: Op = Op(0x17);

    /// Ed25519 signature over the full (unhashed) payload.
    pub const ED25519_SIGN: Op = Op(0x18);

    pub const SEAL: Op = Op(0x21);
    pub const UNSEAL: Op = Op(0x22);
    /// Go `net/rpc` + `gob` call; not portable outside Go.
    pub const RPC: Op = Op(0x23);
    pub const CUSTOM: Op = Op(0x24);

    pub const RESPONSE: Op = Op(0xF0);
    pub const PING: Op = Op(0xF1);
    pub const PONG: Op = Op(0xF2);
    pub const ERROR: Op = Op(0xFF);

    /// Describes how a signing opcode should be executed, or `None` if the
    /// opcode is not a signing operation.
    pub fn sign_params(self) -> Option<SignParams> {
        use HashAlg::*;
        use SignAlg::*;
        let (alg, hash) = match self {
            Op::RSA_SIGN_MD5SHA1 => (RsaPkcs1, Md5Sha1),
            Op::RSA_SIGN_SHA1 => (RsaPkcs1, Sha1),
            Op::RSA_SIGN_SHA224 => (RsaPkcs1, Sha224),
            Op::RSA_SIGN_SHA256 => (RsaPkcs1, Sha256),
            Op::RSA_SIGN_SHA384 => (RsaPkcs1, Sha384),
            Op::RSA_SIGN_SHA512 => (RsaPkcs1, Sha512),
            Op::RSA_PSS_SIGN_SHA256 => (RsaPss, Sha256),
            Op::RSA_PSS_SIGN_SHA384 => (RsaPss, Sha384),
            Op::RSA_PSS_SIGN_SHA512 => (RsaPss, Sha512),
            Op::ECDSA_SIGN_MD5SHA1 => (Ecdsa, Md5Sha1),
            Op::ECDSA_SIGN_SHA1 => (Ecdsa, Sha1),
            Op::ECDSA_SIGN_SHA224 => (Ecdsa, Sha224),
            Op::ECDSA_SIGN_SHA256 => (Ecdsa, Sha256),
            Op::ECDSA_SIGN_SHA384 => (Ecdsa, Sha384),
            Op::ECDSA_SIGN_SHA512 => (Ecdsa, Sha512),
            Op::ED25519_SIGN => (Ed25519, None),
            _ => return Option::None,
        };
        Some(SignParams { alg, hash })
    }

    fn name(self) -> Option<&'static str> {
        Some(match self {
            Op::RSA_DECRYPT => "RSADecrypt",
            Op::RSA_SIGN_MD5SHA1 => "RSASignMD5SHA1",
            Op::RSA_SIGN_SHA1 => "RSASignSHA1",
            Op::RSA_SIGN_SHA224 => "RSASignSHA224",
            Op::RSA_SIGN_SHA256 => "RSASignSHA256",
            Op::RSA_SIGN_SHA384 => "RSASignSHA384",
            Op::RSA_SIGN_SHA512 => "RSASignSHA512",
            Op::RSA_PSS_SIGN_SHA256 => "RSAPSSSignSHA256",
            Op::RSA_PSS_SIGN_SHA384 => "RSAPSSSignSHA384",
            Op::RSA_PSS_SIGN_SHA512 => "RSAPSSSignSHA512",
            Op::ECDSA_SIGN_MD5SHA1 => "ECDSASignMD5SHA1",
            Op::ECDSA_SIGN_SHA1 => "ECDSASignSHA1",
            Op::ECDSA_SIGN_SHA224 => "ECDSASignSHA224",
            Op::ECDSA_SIGN_SHA256 => "ECDSASignSHA256",
            Op::ECDSA_SIGN_SHA384 => "ECDSASignSHA384",
            Op::ECDSA_SIGN_SHA512 => "ECDSASignSHA512",
            Op::ED25519_SIGN => "Ed25519Sign",
            Op::SEAL => "Seal",
            Op::UNSEAL => "Unseal",
            Op::RPC => "RPC",
            Op::CUSTOM => "Custom",
            Op::RESPONSE => "Response",
            Op::PING => "Ping",
            Op::PONG => "Pong",
            Op::ERROR => "Error",
            _ => return None,
        })
    }
}

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "Op({:#04x})", self.0),
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Signature algorithm family of a signing opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignAlg {
    RsaPkcs1,
    /// RSASSA-PSS with salt length equal to the hash length (as in TLS 1.3).
    RsaPss,
    /// ECDSA; signatures are ASN.1 DER `SEQUENCE { r, s }`.
    Ecdsa,
    Ed25519,
}

/// Hash that was applied to the payload of a signing request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// Payload is the raw message (Ed25519).
    None,
    /// Concatenation of MD5 and SHA-1 digests (TLS 1.0/1.1).
    Md5Sha1,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Expected payload length, if fixed.
    pub fn output_len(self) -> Option<usize> {
        match self {
            HashAlg::None => None,
            HashAlg::Md5Sha1 => Some(36),
            HashAlg::Sha1 => Some(20),
            HashAlg::Sha224 => Some(28),
            HashAlg::Sha256 => Some(32),
            HashAlg::Sha384 => Some(48),
            HashAlg::Sha512 => Some(64),
        }
    }
}

/// How a signing opcode must be executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignParams {
    pub alg: SignAlg,
    pub hash: HashAlg,
}

/// One-byte error code carried in the payload of an [`Op::ERROR`] response.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u8);

impl ErrorCode {
    pub const NONE: ErrorCode = ErrorCode(0);
    pub const CRYPTO: ErrorCode = ErrorCode(1);
    pub const KEY_NOT_FOUND: ErrorCode = ErrorCode(2);
    pub const READ: ErrorCode = ErrorCode(3);
    pub const VERSION_MISMATCH: ErrorCode = ErrorCode(4);
    pub const BAD_OPCODE: ErrorCode = ErrorCode(5);
    pub const UNEXPECTED_OPCODE: ErrorCode = ErrorCode(6);
    pub const FORMAT: ErrorCode = ErrorCode(7);
    pub const INTERNAL: ErrorCode = ErrorCode(8);
    pub const CERT_NOT_FOUND: ErrorCode = ErrorCode(9);
    pub const EXPIRED: ErrorCode = ErrorCode(10);
    pub const REMOTE_CONFIGURATION: ErrorCode = ErrorCode(11);

    pub fn description(self) -> &'static str {
        match self {
            ErrorCode::NONE => "no error",
            ErrorCode::CRYPTO => "cryptography error",
            ErrorCode::KEY_NOT_FOUND => "key not found due to no matching SKI/SNI/ServerIP",
            ErrorCode::READ => "read failure",
            ErrorCode::VERSION_MISMATCH => "version mismatch",
            ErrorCode::BAD_OPCODE => "bad opcode",
            ErrorCode::UNEXPECTED_OPCODE => "unexpected opcode",
            ErrorCode::FORMAT => "malformed message",
            ErrorCode::INTERNAL => "internal error",
            ErrorCode::CERT_NOT_FOUND => "certificate not found",
            ErrorCode::EXPIRED => "sealing key expired",
            ErrorCode::REMOTE_CONFIGURATION => "remote configuration error",
            _ => "unknown error",
        }
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorCode({}: {})", self.0, self.description())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "keyless: {}", self.description())
    }
}

impl std::error::Error for ErrorCode {}

/// SHA-1 Subject Key Identifier, the primary key-lookup index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ski(pub [u8; 20]);

impl Ski {
    /// gokeyless treats the all-zero SKI as "absent".
    pub fn is_valid(&self) -> bool {
        self.0 != [0; 20]
    }
}

impl fmt::Display for Ski {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Ski {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ski({self})")
    }
}
