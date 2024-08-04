use std::iter::repeat;

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

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum TaggedPacket<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}
