use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

use parking_lot::{Mutex, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{sleepyinstant::Instant, x25519};

use super::{
    handshake::{Cookies, Handshake, InitRecvState, InitSentState, NoiseParams, TimeStamper},
    session::Session,
    Packet,
};

const NUM_SES: usize = 8;

pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";
const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;

pub trait QueueIn {
    fn push(self, packet: Packet);
}

pub trait QueueOut {
    fn pop(self) -> Option<Packet>;
}

// pub trait QueueOut: Sync {

// }

pub enum SessionState {
    None,
    InitSent(InitSentState),
    InitRecv(InitRecvState),
    Session(Session),
}

pub struct Node {
    pub public_key: PublicKey,
    secret_key: StaticSecret,

    stamper: TimeStamper,

    connections: HashMap<PublicKey, ConnId>,
    // Per connection data
    noise_params: Vec<NoiseParams>,
    cookies: Vec<Mutex<Cookies>>,
    active_session: Vec<AtomicU32>,

    // Per session data
    states: Vec<RwLock<SessionState>>,

    // Per idx data
    idx_to_state: RwLock<HashMap<u32, usize>>,
}

impl Node {
    pub fn new(ss: StaticSecret, psk: Option<StaticSecret>) -> Self {
        Self {
            public_key: PublicKey::from(&ss),
            secret_key: ss,

            stamper: TimeStamper::new(),

            connections: HashMap::new(),
            noise_params: Vec::new(),
            cookies: Vec::new(),
            active_session: Vec::new(),

            states: Vec::new(),

            idx_to_state: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_conn(&mut self, config: Conn) -> ConnId {
        todo!()
    }

    pub fn transport_one_plaintext(
        &self,
        conn: ConnId,
        tun_out: impl QueueOut,
        net_in: impl QueueIn,
        pool: impl QueueOut,
    ) {
        // need to ensure session
        let ses_id = self.active_session[conn.0].load(Ordering::Relaxed);
        let state_id = conn.0 * NUM_SES + ses_id as usize;

        {
            let state = self.states[state_id].read();
            match state.deref() {
                SessionState::None => (),
                SessionState::Session(ses) => {
                    if let Some(mut packet) = tun_out.pop() {
                        ses.encrypt(&mut packet);
                        net_in.push(packet);
                    }
                    // Encrypted packet enqueued
                    return;
                }
                _ => {
                    return;
                }
            }
        }

        // No active init
        let mut state = self.states[state_id].write();
        let new_state = match state.deref_mut() {
            &mut SessionState::None => {
                let Some(mut packet) = pool.pop() else {
                    return;
                };

                let mut cookies = self.cookies[conn.0].lock();
                let index = self.next_idx();
                self.noise_params[conn.0].format_handshake_initiation(
                    index,
                    &self.stamper,
                    &mut cookies,
                    &mut packet,
                )
            }
            _ => {
                return;
            }
        };

        *state = SessionState::InitSent(new_state);
    }

    fn next_idx(&self) -> u32 {
        // This needs to find a next free index
        todo!()
    }

    // pub fn transport_one_encrypted(
    //     &self,
    //     net_out: &impl QueueOut,
    //     net_in: &impl QueueIn,
    //     tun_in: &impl QueueIn,
    // ) {
    //     match Tunn::parse_incoming_packet(&packet.0) {
    //         Ok(packet) => match packet {
    //             super::TaggedPacket::HandshakeInit(init) => {}
    //             super::TaggedPacket::HandshakeResponse(_) => todo!(),
    //             super::TaggedPacket::PacketCookieReply(_) => todo!(),
    //             super::TaggedPacket::PacketData(_) => todo!(),
    //         },
    //         Err(_) => return,
    //     }
    // }
}

pub struct ConnId(usize);

pub struct Conn {
    pub public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
}

impl Default for Conn {
    fn default() -> Self {
        Self {
            public_key: PublicKey::from([0u8; 32]),
            preshared_key: None,
        }
    }
}

pub fn default<T: Default>() -> T {
    T::default()
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;

    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::StaticSecret;

    impl QueueIn for &mut Vec<Packet> {
        fn push(self, packet: Packet) {
            self.push(packet);
        }
    }

    impl QueueOut for &mut Vec<Packet> {
        fn pop(self) -> Option<Packet> {
            self.pop()
        }
    }

    pub fn test_communication() {
        let msg = b"hello mister";

        let mut node_a = Node::new(StaticSecret::random_from_rng(OsRng), None);
        let mut node_b = Node::new(StaticSecret::random_from_rng(OsRng), None);

        let conn_ab = node_a.add_conn(Conn {
            public_key: node_b.public_key,
            ..default()
        });
        let conn_ba = node_b.add_conn(Conn {
            public_key: node_a.public_key,
            ..default()
        });

        let mut pool = Vec::new();
        pool.extend(repeat(Packet::new(80, 1420)).take(32));

        let mut net = Vec::new();

        let mut msg_a = Vec::new();
        // let mut msg_b = Vec::new();

        let mut packet = pool.pop().unwrap();
        packet.write_data(msg);

        msg_a.push(packet);

        node_a.transport_one_plaintext(conn_ab, &mut msg_a, &mut net, &mut pool);
        assert_eq!(net.len(), 1, "hanshake sent");

        // node_b.queue_encrypted(packet, &mut out_b, &mut net);

        // {
        //     let mut net = net_b.0.lock();
        //     for packet in net.drain(..) {
        //         node_a.queue_encrypted(packet, &out_b, &net_a);
        //     }
        // }

        // let parsed = Tunn::parse_incoming_packet(packet);

        // let (conn, ses) = match parsed {
        //     Ok(kind) => match kind {
        //         crate::noise::Packet::HandshakeInit(init) => {}
        //         other => panic!("Unexpected packet: {other:?}"),
        //     },
        //     err => panic!("Unexpected error: {err:?}"),
        // };

        // node_a.
    }
}
