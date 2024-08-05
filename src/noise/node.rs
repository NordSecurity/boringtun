use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

use parking_lot::{Mutex, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    handshake::{Cookies, InitRecvState, InitSentState, NoiseParams, TimeStamper},
    packet::{parse_incoming_packet, Packet},
    session::Session,
    N_SESSIONS,
};

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

    links: HashMap<PublicKey, LinkId>,
    // Per link data
    noise_params: Vec<NoiseParams>,
    cookies: Vec<Mutex<Cookies>>,
    active_session: Vec<AtomicU32>,

    // Per session data
    states: Vec<RwLock<SessionState>>,

    // Per idx data
    idx_to_state: RwLock<(u32, HashMap<u32, usize>)>,
}

impl Node {
    pub fn new(ss: StaticSecret, psk: Option<StaticSecret>) -> Self {
        Self {
            public_key: PublicKey::from(&ss),
            secret_key: ss,

            stamper: TimeStamper::new(),

            links: HashMap::new(),
            noise_params: Vec::new(),
            cookies: Vec::new(),
            active_session: Vec::new(),

            states: Vec::new(),

            idx_to_state: RwLock::new((0, HashMap::new())),
        }
    }

    pub fn add_link(&mut self, config: Link) -> LinkId {
        let slot = self.links.len();

        let id = LinkId(slot);
        if slot == self.links.len() {
            self.noise_params.push(NoiseParams::new(
                self.secret_key.clone(),
                self.public_key,
                config.public_key,
                config.preshared_key,
            ));
            self.cookies.push(Mutex::new(Cookies::default()));
            self.active_session.push(AtomicU32::new(0));

            for _ in 0..N_SESSIONS {
                self.states.push(RwLock::new(SessionState::None));
            }
        } else {
            todo!("slots")
        }
        self.links.insert(config.public_key, id);
        id
    }

    pub fn encode_one(
        &self,
        link: LinkId,
        pool: impl QueueOut,
        tun_out: impl QueueOut,
        net_in: impl QueueIn,
    ) {
        // need to ensure session
        let ses_id = self.active_session[link.0].load(Ordering::Relaxed);
        let state_id = link.0 * N_SESSIONS + ses_id as usize;

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

                let index = self.activate(state_id);

                let state = {
                    let mut cookies = self.cookies[link.0].lock();
                    self.noise_params[link.0].format_handshake_initiation(
                        index,
                        &self.stamper,
                        &mut cookies,
                        &mut packet,
                    )
                };
                // TODO(pna): probably smarter to move after write lock is freed
                net_in.push(packet);
                state
            }
            _ => {
                return;
            }
        };

        *state = SessionState::InitSent(new_state);
    }

    pub fn decode_one(
        &self,
        link: LinkId,
        pool: impl QueueIn,
        net_out: impl QueueOut,
        net_in: impl QueueIn,
        tun_in: impl QueueIn,
    ) {
        // match Tunn::parse_incoming_packet(&packet.0) {
        //     Ok(packet) => match packet {
        //         super::TaggedPacket::HandshakeInit(init) => {}
        //         super::TaggedPacket::HandshakeResponse(_) => todo!(),
        //         super::TaggedPacket::PacketCookieReply(_) => todo!(),
        //         super::TaggedPacket::PacketData(_) => todo!(),
        //     },
        //     Err(_) => return,
        // }
        let Some(mut packet) = net_out.pop() else {
            return;
        };

        match packet.tag() {
            Ok(tagged) => match tagged {
                super::packet::TaggedPacket::Init { packet } => {
                    // let ses = self.active_session[link.0].load(Ordering::Release);
                    // let state_id = link.0 * N_SESSIONS + ses;
                    // self.states[state_id].read
                }
                super::packet::TaggedPacket::Reply { packet } => todo!(),
                super::packet::TaggedPacket::Cookie { packet } => todo!(),
                super::packet::TaggedPacket::Data { packet } => todo!(),
            },
            Err(packet) => {
                // Return packet to pool
                pool.push(packet);
            }
        }

        // TODO: rate limiter should be used here
        // let Ok(tagged) = parse_incoming_packet(packet.full()) else {
        //     return;
        // };

        // enum Act { Init }
        // let action = match tagged {
        //     super::packet::TaggedPacket::HandshakeInit(init) => {
        //         Act::Init
        //     },
        //     super::packet::TaggedPacket::HandshakeResponse(resp) => todo!(),
        //     super::packet::TaggedPacket::PacketCookieReply(_) => todo!(),
        //     super::packet::TaggedPacket::PacketData(data) => todo!(),
        // }
        // match action {
        //     Act::Init => {
        //         self.
        //     },
        // }
    }

    fn activate(&self, state_id: usize) -> u32 {
        // TODO: use a pseudo random generator
        let mut next_and_map = self.idx_to_state.write();
        // TODO: need some max iter count
        while next_and_map.1.contains_key(&next_and_map.0) {
            next_and_map.0 += 1;
        }
        let idx = next_and_map.0;
        next_and_map.1.insert(idx, state_id);
        next_and_map.0 += 1;
        idx
    }
}

#[derive(Copy, Clone)]
pub struct LinkId(usize);

pub struct Link {
    pub public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
}

impl Default for Link {
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

    #[test]
    pub fn test_communication() {
        let msg = b"hello mister";

        let mut node_a = Node::new(StaticSecret::random_from_rng(OsRng), None);
        let mut node_b = Node::new(StaticSecret::random_from_rng(OsRng), None);

        let conn_ab = node_a.add_link(Link {
            public_key: node_b.public_key,
            ..default()
        });
        let conn_ba = node_b.add_link(Link {
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

        node_a.encode_one(conn_ab, &mut pool, &mut msg_a, &mut net);
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
