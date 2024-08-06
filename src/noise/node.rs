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
    // link -> active session
    active: Vec<AtomicU32>,
    // Maybe smarter to use a lock free set
    busy: Vec<Mutex<u32>>,

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
            active: Vec::new(),
            busy: Vec::new(),

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
            self.active.push(AtomicU32::new(0));
            self.busy.push(Mutex::new(0));

            for _ in 0..N_SESSIONS {
                self.states.push(RwLock::new(SessionState::None));
            }
        } else {
            todo!("slots")
        }
        self.links.insert(config.public_key, id);
        id
    }

    /// Force new handshake
    pub fn queue_handshake(&self, link: LinkId, pool: impl QueueOut, net_output: impl QueueIn) {
        let Some(index) = self.alloc_state(link) else {
            return;
        };

        let state_id = link.0 * N_SESSIONS + index as usize;
        let packet = {
            let mut state = self.states[state_id].write();
            let (new_state, packet) = match state.deref_mut() {
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
                    (state, packet)
                }
                _ => {
                    // Busy
                    return;
                }
            };
            *state = SessionState::InitSent(new_state);

            packet
        };

        net_output.push(packet);
    }

    pub fn encode_one(
        &self,
        link: LinkId,
        pool: impl QueueOut,
        msg_input: impl QueueOut,
        net_output: impl QueueIn,
    ) {
        // need to ensure session
        let ses_id = self.active[link.0].load(Ordering::Relaxed);
        let state_id = link.0 * N_SESSIONS + ses_id as usize;

        {
            let state = self.states[state_id].read();
            match state.deref() {
                SessionState::None => {}
                SessionState::Session(ses) => {
                    if let Some(mut packet) = msg_input.pop() {
                        ses.encrypt(&mut packet);
                        net_output.push(packet);
                    }
                    // Encrypted packet enqueued
                    return;
                }
                // if we are in progress, wait till ready
                _ => return,
            }
        }

        self.queue_handshake(link, pool, net_output)
    }

    pub fn decode_one(
        &self,
        link: LinkId,
        pool: impl QueueIn,
        net_out: impl QueueOut,
        net_in: impl QueueIn,
        tun_in: impl QueueIn,
    ) {
        let Some(mut packet) = net_out.pop() else {
            return;
        };

        match packet.tag() {
            Ok(tagged) => match tagged {
                super::packet::AnyPacket::Init { mut packet } => {
                    let Some(index) = self.alloc_state(link) else {
                        return;
                    };
                    let state_id = link.0 * N_SESSIONS + index;

                    self.noise_params[link.0].handle_handshake_init(&mut packet);

                    // let ses = self.active_session[link.0].load(Ordering::Release);
                    // let state_id = link.0 * N_SESSIONS + ses;
                    // self.states[state_id].read
                }
                super::packet::AnyPacket::Reply { packet } => todo!(),
                super::packet::AnyPacket::Cookie { packet } => todo!(),
                super::packet::AnyPacket::Data { packet } => todo!(),
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

    /// Try to aquire a free state for link
    fn alloc_state(&self, link: LinkId) -> Option<usize> {
        let mut busy = self.busy[link.0].lock();
        let mut index = 0..N_SESSIONS;
        // Sweep and find a free bit
        let idx = loop {
            let Some(idx) = index.next() else {
                // No free slot
                return None;
            };
            let spot = 1 << idx;
            if spot & *busy == 0 {
                break idx;
            }
        };
        *busy |= 1 << idx;
        Some(idx)
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

    use crate::noise::packet::AnyPacket;

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
    pub fn test_handshaking() {
        let mut node_a = Node::new(StaticSecret::random_from_rng(OsRng), None);
        let b_public = PublicKey::from(&StaticSecret::random_from_rng(OsRng));

        let link_ab = node_a.add_link(Link {
            public_key: b_public,
            ..default()
        });

        let mut pool = Vec::new();
        pool.extend(repeat(Packet::new(80, 1420)).take(32));
        let mut net = Vec::new();

        // Queue all possible handshakes per link
        for _ in 0..N_SESSIONS {
            node_a.queue_handshake(link_ab, &mut pool, &mut net);
            let msg = net
                .pop()
                .expect("one packet sent")
                .tag()
                .expect("a valid message");
            assert!(matches!(msg, AnyPacket::Init { .. }),)
        }
        node_a.queue_handshake(link_ab, &mut pool, &mut net);
        assert_eq!(net.len(), 0, "outgoing handshake limit reached");
    }

    #[test]
    pub fn test_communication() {
        let msg = b"hello mister";

        let mut node_a = Node::new(StaticSecret::random_from_rng(OsRng), None);
        let mut node_b = Node::new(StaticSecret::random_from_rng(OsRng), None);

        let link_ab = node_a.add_link(Link {
            public_key: node_b.public_key,
            ..default()
        });
        let link_ba = node_b.add_link(Link {
            public_key: node_a.public_key,
            ..default()
        });

        let mut pool = Vec::new();
        pool.extend(repeat(Packet::new(80, 1420)).take(32));

        // messages in a network
        let mut net_a = Vec::new();
        // messages in b network
        let mut net_b = Vec::new();

        // a plaintext input
        let mut msg_a_input = Vec::new();
        // b plaintext output
        let mut msg_a_output = Vec::new();

        // b plaintext input
        // let mut msg_b_input = Vec::new();
        // b plaintext output
        let mut msg_b_output = Vec::new();

        let mut packet = pool.pop().unwrap();
        packet.write_data(msg);

        msg_a_input.push(packet);

        // queue packets to b's network
        node_a.encode_one(link_ab, &mut pool, &mut msg_a_input, &mut net_b);
        assert_eq!(net_a.len(), 1, "hanshake init sent");

        // react to init from a
        node_b.decode_one(
            link_ba,
            &mut pool,
            &mut net_b,
            &mut net_a,
            &mut msg_b_output,
        );
        assert_eq!(net_a.len(), 1, "hanshake reply sent");

        // react to reply from b
        node_a.decode_one(
            link_ab,
            &mut pool,
            &mut net_a,
            &mut net_b,
            &mut msg_a_output,
        );
        assert_eq!(net_a.len(), 0, "reply consumed");

        // send actual message
        node_a.encode_one(link_ab, &mut pool, &mut msg_a_input, &mut net_b);
        assert_eq!(net_b.len(), 1, "data encoded");

        // react to init from a
        node_b.decode_one(
            link_ba,
            &mut pool,
            &mut net_b,
            &mut net_a,
            &mut msg_b_output,
        );
        assert_eq!(msg_b_output.len(), 1, "msg decoded");
        assert_eq!(msg_b_output.pop().expect("keepalive").data_mut(), msg,);
    }
}
