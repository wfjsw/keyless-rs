use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{ErrorCode, Op, Ski, Tag, HEADER_LENGTH, PADDED_LENGTH, VERSION_MAJOR, VERSION_MINOR};

/// Fixed 8-byte message header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub major: u8,
    pub minor: u8,
    /// Length of the body that follows the header.
    pub length: u16,
    /// Request ID; responses echo the ID of the request they answer.
    pub id: u32,
}

impl Header {
    pub fn decode(b: &[u8; HEADER_LENGTH]) -> Header {
        Header {
            major: b[0],
            minor: b[1],
            length: u16::from_be_bytes([b[2], b[3]]),
            id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LENGTH] {
        let mut b = [0; HEADER_LENGTH];
        b[0] = self.major;
        b[1] = self.minor;
        b[2..4].copy_from_slice(&self.length.to_be_bytes());
        b[4..8].copy_from_slice(&self.id.to_be_bytes());
        b
    }
}

/// The body of a message: one operation (request) or its result (response).
///
/// Empty/absent fields are omitted on the wire, mirroring gokeyless.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Operation {
    pub opcode: Op,
    pub payload: Vec<u8>,
    pub extra: Vec<u8>,
    pub ski: Option<Ski>,
    /// SHA-256 of the uppercase hex RSA modulus (legacy lookup index).
    pub digest: Option<[u8; 32]>,
    pub client_ip: Option<IpAddr>,
    pub server_ip: Option<IpAddr>,
    pub sni: String,
    pub cert_id: String,
    pub custom_func_name: String,
    pub jaeger_span: Option<Vec<u8>>,
    pub req_context: Option<Vec<u8>>,
    /// 0 means "no region".
    pub compliance_region: u8,
}

/// A complete message: request ID plus operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Packet {
    pub id: u32,
    pub op: Operation,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("message body of {0} bytes exceeds the 65535 byte limit")]
    TooLarge(usize),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("item {tag:#04x} extends {overrun} bytes past the end of the body")]
    Truncated { tag: u8, overrun: usize },
    #[error("invalid opcode item length {0}")]
    BadOpcodeLength(usize),
    #[error("invalid compliance region item length {0}")]
    BadComplianceRegionLength(usize),
    #[error("invalid IP address length {0}")]
    BadIpLength(usize),
    #[error("tag {0:#04x} seen multiple times")]
    DuplicateTag(u8),
    #[error("message is shorter than its header")]
    ShortHeader,
    #[error("header length {header} does not match body length {actual}")]
    LengthMismatch { header: usize, actual: usize },
}

impl Operation {
    pub fn new(opcode: Op, payload: impl Into<Vec<u8>>) -> Operation {
        Operation { opcode, payload: payload.into(), ..Default::default() }
    }

    /// An [`Op::RESPONSE`] carrying `payload`.
    pub fn response(payload: impl Into<Vec<u8>>) -> Operation {
        Operation::new(Op::RESPONSE, payload)
    }

    /// An [`Op::ERROR`] carrying `code`.
    pub fn error(code: ErrorCode) -> Operation {
        Operation::new(Op::ERROR, vec![code.0])
    }

    /// The error code if this is an [`Op::ERROR`] response.
    pub fn error_code(&self) -> Option<ErrorCode> {
        if self.opcode != Op::ERROR {
            return None;
        }
        // gokeyless always sends exactly one byte; treat anything else as malformed.
        Some(match self.payload.as_slice() {
            [code] => ErrorCode(*code),
            _ => ErrorCode::FORMAT,
        })
    }

    /// Appends the TLV encoding of this operation, including padding, to `out`.
    ///
    /// Items are emitted in the same order as gokeyless.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        put(out, Tag::OPCODE, &[self.opcode.0]);
        if !self.payload.is_empty() {
            put(out, Tag::PAYLOAD, &self.payload);
        }
        if !self.extra.is_empty() {
            put(out, Tag::EXTRA, &self.extra);
        }
        if let Some(ski) = self.ski.filter(Ski::is_valid) {
            put(out, Tag::SUBJECT_KEY_IDENTIFIER, &ski.0);
        }
        if let Some(digest) = self.digest.filter(|d| *d != [0; 32]) {
            put(out, Tag::CERTIFICATE_DIGEST, &digest);
        }
        if let Some(ip) = self.client_ip {
            put_ip(out, Tag::CLIENT_IP, ip);
        }
        if let Some(ip) = self.server_ip {
            put_ip(out, Tag::SERVER_IP, ip);
        }
        for (tag, s) in [
            (Tag::SERVER_NAME, &self.sni),
            (Tag::CERT_ID, &self.cert_id),
            (Tag::CUSTOM_FUNC_NAME, &self.custom_func_name),
        ] {
            if !s.is_empty() {
                put(out, tag, s.as_bytes());
            }
        }
        if let Some(span) = &self.jaeger_span {
            put(out, Tag::JAEGER_SPAN, span);
        }
        if let Some(ctx) = &self.req_context {
            put(out, Tag::REQ_CONTEXT, ctx);
        }
        if self.compliance_region != 0 {
            put(out, Tag::COMPLIANCE_REGION, &[self.compliance_region]);
        }

        let len = out.len() - start;
        if len + HEADER_LENGTH < PADDED_LENGTH {
            // If we are within 1-2 bytes of the target, the 3-byte item header
            // overshoots it; gokeyless then emits an empty padding item.
            let pad = PADDED_LENGTH.saturating_sub(len + HEADER_LENGTH + 3);
            out.extend_from_slice(&[Tag::PADDING.0]);
            out.extend_from_slice(&(pad as u16).to_be_bytes());
            out.resize(out.len() + pad, 0);
        }

        let len = out.len() - start;
        if len > u16::MAX as usize {
            out.truncate(start);
            return Err(EncodeError::TooLarge(len));
        }
        Ok(())
    }

    /// Decodes a message body. Unknown tags are ignored for forward
    /// compatibility; known tags may appear at most once.
    pub fn decode(body: &[u8]) -> Result<Operation, DecodeError> {
        let mut op = Operation::default();
        let mut seen = [false; 256];
        let mut i = 0;
        // Like gokeyless, 1-2 trailing bytes that cannot form an item header are ignored.
        while i + 3 <= body.len() {
            let tag = Tag(body[i]);
            let len = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
            let end = i + 3 + len;
            if end > body.len() {
                return Err(DecodeError::Truncated { tag: tag.0, overrun: end - body.len() });
            }
            let data = &body[i + 3..end];
            i = end;

            match tag {
                Tag::OPCODE => match data {
                    [b] => op.opcode = Op(*b),
                    _ => return Err(DecodeError::BadOpcodeLength(data.len())),
                },
                Tag::PAYLOAD => op.payload = data.to_vec(),
                Tag::EXTRA => op.extra = data.to_vec(),
                Tag::SUBJECT_KEY_IDENTIFIER => {
                    // Wrong-length SKIs are silently ignored, as in gokeyless.
                    if let Ok(ski) = <[u8; 20]>::try_from(data) {
                        op.ski = Some(Ski(ski)).filter(Ski::is_valid);
                    }
                }
                Tag::CERTIFICATE_DIGEST => {
                    if let Ok(digest) = <[u8; 32]>::try_from(data) {
                        op.digest = Some(digest).filter(|d| *d != [0; 32]);
                    }
                }
                Tag::CLIENT_IP => op.client_ip = Some(decode_ip(data)?),
                Tag::SERVER_IP => op.server_ip = Some(decode_ip(data)?),
                Tag::SERVER_NAME => op.sni = String::from_utf8_lossy(data).into_owned(),
                Tag::CERT_ID => op.cert_id = String::from_utf8_lossy(data).into_owned(),
                Tag::CUSTOM_FUNC_NAME => {
                    op.custom_func_name = String::from_utf8_lossy(data).into_owned()
                }
                Tag::JAEGER_SPAN => op.jaeger_span = Some(data.to_vec()),
                Tag::REQ_CONTEXT => op.req_context = Some(data.to_vec()),
                Tag::COMPLIANCE_REGION => match data {
                    [b] => op.compliance_region = *b,
                    _ => return Err(DecodeError::BadComplianceRegionLength(data.len())),
                },
                Tag::PADDING => {}
                _ => continue,
            }

            if std::mem::replace(&mut seen[tag.0 as usize], true) {
                return Err(DecodeError::DuplicateTag(tag.0));
            }
        }
        Ok(op)
    }
}

impl Packet {
    pub fn new(id: u32, op: Operation) -> Packet {
        Packet { id, op }
    }

    /// Encodes header and body.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(PADDED_LENGTH);
        out.resize(HEADER_LENGTH, 0);
        self.op.encode_into(&mut out)?;
        let header = Header {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            length: (out.len() - HEADER_LENGTH) as u16,
            id: self.id,
        };
        out[..HEADER_LENGTH].copy_from_slice(&header.encode());
        Ok(out)
    }

    /// Decodes a complete message (header followed by exactly `length` body bytes).
    pub fn decode(msg: &[u8]) -> Result<Packet, DecodeError> {
        let (header, body) = msg.split_first_chunk::<HEADER_LENGTH>().ok_or(DecodeError::ShortHeader)?;
        let header = Header::decode(header);
        if header.length as usize != body.len() {
            return Err(DecodeError::LengthMismatch {
                header: header.length as usize,
                actual: body.len(),
            });
        }
        Ok(Packet { id: header.id, op: Operation::decode(body)? })
    }
}

fn put(out: &mut Vec<u8>, tag: Tag, data: &[u8]) {
    out.push(tag.0);
    // Oversized items are caught by the total-length check in encode_into.
    out.extend_from_slice(&(data.len().min(u16::MAX as usize) as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn put_ip(out: &mut Vec<u8>, tag: Tag, ip: IpAddr) {
    // Go's net.IP.To4() also collapses IPv4-mapped IPv6 addresses to 4 bytes.
    match ip {
        IpAddr::V4(v4) => put(out, tag, &v4.octets()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => put(out, tag, &v4.octets()),
            None => put(out, tag, &v6.octets()),
        },
    }
}

fn decode_ip(data: &[u8]) -> Result<IpAddr, DecodeError> {
    if let Ok(b) = <[u8; 4]>::try_from(data) {
        Ok(IpAddr::V4(Ipv4Addr::from(b)))
    } else if let Ok(b) = <[u8; 16]>::try_from(data) {
        Ok(IpAddr::V6(Ipv6Addr::from(b)))
    } else {
        Err(DecodeError::BadIpLength(data.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_op() -> Operation {
        Operation {
            opcode: Op::ECDSA_SIGN_SHA256,
            payload: vec![7; 1000],
            extra: vec![8; 100],
            ski: Some(Ski([1; 20])),
            digest: Some([2; 32]),
            client_ip: Some("1.1.1.1".parse().unwrap()),
            server_ip: Some("2001:db8::1".parse().unwrap()),
            sni: "example.com".into(),
            cert_id: "cert".into(),
            custom_func_name: "CustomFuncName".into(),
            jaeger_span: Some(b"615f730ad5fe896f:615f730ad5fe896f:1".to_vec()),
            req_context: Some(vec![9; 100]),
            compliance_region: 1,
        }
    }

    #[test]
    fn roundtrip_large() {
        let pkt = Packet::new(42, full_op());
        let bytes = pkt.encode().unwrap();
        assert!(bytes.len() > PADDED_LENGTH);
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);

        // Dropping the compliance region removes exactly one 4-byte item (Go test parity).
        let mut op = full_op();
        op.compliance_region = 0;
        let smaller = Packet::new(42, op.clone()).encode().unwrap();
        assert_eq!(bytes.len(), smaller.len() + 4);
        assert_eq!(Packet::decode(&smaller).unwrap().op, op);
    }

    #[test]
    fn small_messages_are_padded_to_1024() {
        for payload_len in [0, 1, 32, 500, 1000, 1005, 1006, 1007, 1008, 1013] {
            let pkt = Packet::new(1, Operation::new(Op::PING, vec![0xAB; payload_len]));
            let bytes = pkt.encode().unwrap();
            let unpadded = HEADER_LENGTH + 4 + if payload_len > 0 { 3 + payload_len } else { 0 };
            if unpadded < PADDED_LENGTH {
                assert!(bytes.len() >= PADDED_LENGTH && bytes.len() <= PADDED_LENGTH + 2, "{payload_len}: {}", bytes.len());
            } else {
                assert_eq!(bytes.len(), unpadded);
            }
            assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
        }
    }

    #[test]
    fn exact_wire_bytes_for_ping() {
        let bytes = Packet::new(0x01020304, Operation::new(Op::PING, b"hi".to_vec())).encode().unwrap();
        assert_eq!(&bytes[..8], &[1, 0, 0x03, 0xF8, 1, 2, 3, 4]);
        assert_eq!(&bytes[8..17], &[0x11, 0, 1, 0xF1, 0x12, 0, 2, b'h', b'i']);
        assert_eq!(&bytes[17..20], &[0x20, 0x03, 0xEC]);
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn ipv4_mapped_collapses() {
        let mut op = Operation::new(Op::PING, vec![]);
        op.client_ip = Some("::ffff:10.0.0.1".parse().unwrap());
        let mut out = vec![];
        op.encode_into(&mut out).unwrap();
        assert_eq!(Operation::decode(&out).unwrap().client_ip, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(Operation::decode(&[0x11, 0, 2, 1, 2]), Err(DecodeError::BadOpcodeLength(2)));
        assert_eq!(Operation::decode(&[0x12, 0, 5, 1]), Err(DecodeError::Truncated { tag: 0x12, overrun: 4 }));
        assert_eq!(
            Operation::decode(&[0x11, 0, 1, 1, 0x11, 0, 1, 2]),
            Err(DecodeError::DuplicateTag(0x11))
        );
        assert_eq!(Operation::decode(&[0x03, 0, 3, 1, 2, 3]), Err(DecodeError::BadIpLength(3)));
        // Unknown tags (even repeated) and trailing junk are tolerated.
        let op = Operation::decode(&[0x99, 0, 1, 0, 0x99, 0, 0, 0x11, 0, 1, 0xF1, 0xAA]).unwrap();
        assert_eq!(op.opcode, Op::PING);
    }

    #[test]
    fn too_large() {
        let pkt = Packet::new(1, Operation::new(Op::PING, vec![0; 70_000]));
        assert!(matches!(pkt.encode(), Err(EncodeError::TooLarge(_))));
    }
}
