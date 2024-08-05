use std::iter::repeat;

use super::{
    errors::WireGuardError, COOKIE_REPLY, COOKIE_REPLY_SZ, DATA, DATA_OVERHEAD_SZ, HANDSHAKE_INIT,
    HANDSHAKE_INIT_SZ, HANDSHAKE_RESP, HANDSHAKE_RESP_SZ,
};

#[derive(Clone)]
pub struct Packet {
    /// max header len
    head: usize,
    buf: Box<[u8]>,

    off: usize,
    end: usize,
}

impl Packet {
    pub fn new(overhead: usize, mtu: usize) -> Self {
        let mut buf = Vec::with_capacity(mtu + overhead);
        buf.extend(repeat(0).take(mtu + overhead));

        Packet {
            head: overhead,
            off: overhead,
            end: buf.len(),
            buf: buf.into_boxed_slice(),
        }
    }

    pub fn write_data(&mut self, data: &[u8]) {
        self.end = self.head + data.len();
        self.buf[self.head..self.end].copy_from_slice(data);
    }

    /// Reset packet to store max size packet
    pub fn reset(&mut self) -> &mut Self {
        self.off = self.head;
        self.end = self.buf.len();
        self
    }

    // Change the size of header
    pub fn set_head(&mut self, len: usize) -> &mut Self {
        self.off = self.head - len;
        self
    }

    pub fn set_data(&mut self, len: usize) -> &mut Self {
        self.end = self.head + len;
        self
    }

    /// Return header and data
    pub fn full(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..self.end]
    }

    /// Return just the header
    pub fn head(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..self.head]
    }

    /// Return just the data
    pub fn data(&mut self) -> &mut [u8] {
        &mut self.buf[self.head..self.end]
    }
}

impl Packet {
    pub fn tag(mut self) -> Result<TaggedPacket, Packet> {
        let packet_type = u32::from_le_bytes(self.data()[0..4].try_into().unwrap());

        let tagged = match (packet_type, self.data().len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => TaggedPacket::Init {
                // sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                // unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                // .expect("length already checked above"),
                // encrypted_static: &src[40..88],
                // encrypted_timestamp: &src[88..116],
                packet: self,
            },
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => TaggedPacket::Reply {
                // sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                // receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                // unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                //     .expect("length already checked above"),
                // encrypted_nothing: &src[44..60],
                packet: self,
            },
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => TaggedPacket::Cookie {
                // receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                // nonce: &src[8..32],
                // encrypted_cookie: &src[32..64],
                packet: self,
            },
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => TaggedPacket::Data {
                // receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                // counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                // encrypted_encapsulated_packet: &src[16..],
                packet: self,
            },
            _ => return Err(self),
        };
        Ok(tagged)
    }
}

pub enum TaggedPacket {
    Init { packet: Packet },
    Reply { packet: Packet },
    Cookie { packet: Packet },
    Data { packet: Packet },
}

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    pub sender_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_static: &'a [u8],
    pub encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    pub nonce: &'a [u8],
    pub encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    pub counter: u64,
    pub encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum ParsedPacket<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

#[inline(always)]
pub fn parse_incoming_packet(src: &[u8]) -> Result<ParsedPacket, WireGuardError> {
    if src.len() < 4 {
        return Err(WireGuardError::InvalidPacket);
    }

    // Checks the type, as well as the reserved zero fields
    let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

    Ok(match (packet_type, src.len()) {
        (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => ParsedPacket::HandshakeInit(HandshakeInit {
            sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                .expect("length already checked above"),
            encrypted_static: &src[40..88],
            encrypted_timestamp: &src[88..116],
        }),
        (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => ParsedPacket::HandshakeResponse(HandshakeResponse {
            sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
            unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                .expect("length already checked above"),
            encrypted_nothing: &src[44..60],
        }),
        (COOKIE_REPLY, COOKIE_REPLY_SZ) => ParsedPacket::PacketCookieReply(PacketCookieReply {
            receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            nonce: &src[8..32],
            encrypted_cookie: &src[32..64],
        }),
        (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => ParsedPacket::PacketData(PacketData {
            receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
            encrypted_encapsulated_packet: &src[16..],
        }),
        _ => return Err(WireGuardError::InvalidPacket),
    })
}
