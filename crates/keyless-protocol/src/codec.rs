//! [`tokio_util::codec`] framing for Keyless messages.

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{DecodeError, EncodeError, Header, Operation, Packet, HEADER_LENGTH};

/// A received message. The body is decoded separately from the framing so a
/// malformed body can be answered with an error response instead of tearing
/// down the connection.
#[derive(Debug)]
pub struct Frame {
    pub header: Header,
    pub op: Result<Operation, DecodeError>,
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
}

/// Frames Keyless messages on a byte stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeylessCodec;

impl Decoder for KeylessCodec {
    type Item = Frame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, CodecError> {
        let Some(header) = src.first_chunk::<HEADER_LENGTH>() else {
            src.reserve(HEADER_LENGTH);
            return Ok(None);
        };
        let header = Header::decode(header);
        let total = HEADER_LENGTH + header.length as usize;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }
        src.advance(HEADER_LENGTH);
        let body = src.split_to(header.length as usize);
        Ok(Some(Frame { header, op: Operation::decode(&body) }))
    }
}

impl Encoder<Packet> for KeylessCodec {
    type Error = CodecError;

    fn encode(&mut self, pkt: Packet, dst: &mut BytesMut) -> Result<(), CodecError> {
        dst.extend_from_slice(&pkt.encode()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Op;

    #[test]
    fn decodes_split_and_coalesced_frames() {
        let a = Packet::new(1, Operation::new(Op::PING, b"a".to_vec())).encode().unwrap();
        let b = Packet::new(2, Operation::error(crate::ErrorCode::CRYPTO)).encode().unwrap();
        let mut all = a.clone();
        all.extend_from_slice(&b);

        let mut codec = KeylessCodec;
        let mut buf = BytesMut::new();
        let mut got = vec![];
        for chunk in all.chunks(100) {
            buf.extend_from_slice(chunk);
            while let Some(frame) = codec.decode(&mut buf).unwrap() {
                got.push((frame.header.id, frame.op.unwrap()));
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1.payload, b"a");
        assert_eq!(got[1].1.error_code(), Some(crate::ErrorCode::CRYPTO));
        assert!(buf.is_empty());
    }
}
