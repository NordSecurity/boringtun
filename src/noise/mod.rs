// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod dev;
pub mod errors;
pub mod handshake;
pub mod rate_limiter;
pub mod safe_duration;
pub mod session;
pub mod tun;

#[cfg(test)]
mod integration_tests;
mod timers;

use std::iter::repeat;
use std::net::{Ipv4Addr, Ipv6Addr};

use errors::WireGuardError;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

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
