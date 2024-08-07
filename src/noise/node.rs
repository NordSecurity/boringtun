use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

use parking_lot::{Mutex, RwLock};
use tracing::{debug, info_span, trace, trace_span, warn, Span};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    handshake::{Cookies, InitRecvState, InitSentState, NoiseParams, Tai64N, TimeStamper},
    packet::{parse_incoming_packet, Packet},
    session::Session,
    N_SESSIONS,
};

pub trait Enqueue<T: Sized + Send + 'static = Packet> {
    fn push(self, packet: T);
}

pub trait Dequeue<T: Sized + Send + 'static = Packet> {
    fn pop(self) -> Option<Packet>;
}

pub enum SessionState {
    None,
    InitSent(InitSentState),
    Active(Session),
}

pub struct Node {
    pub public_key: PublicKey,
    secret_key: StaticSecret,

    stamper: TimeStamper,

    links: HashMap<PublicKey, LinkId>,
    // Per link data
    noise_params: Vec<NoiseParams>,
    cookies: Vec<Mutex<Cookies>>,
    last_handshake: Vec<Mutex<Tai64N>>,
    // link -> active session
    active: Vec<AtomicU32>,
    // Maybe smarter to use a lock free set
    busy: Vec<Mutex<u32>>,

    // Per session data
    states: Vec<RwLock<SessionState>>,

    // Per idx data
    idx_to_state: RwLock<(u32, HashMap<u32, usize>)>,

    span: Span,
}

impl Node {
    pub fn new(ss: StaticSecret) -> Self {
        let public_key = PublicKey::from(&ss);
        let mut pk = base64::encode(public_key);
        let _ = pk.split_off(4);
        let span = info_span!("node", pk = pk);

        Self {
            secret_key: ss,
            public_key,

            stamper: TimeStamper::new(),

            links: HashMap::new(),
            noise_params: Vec::new(),
            cookies: Vec::new(),
            last_handshake: Vec::new(),
            active: Vec::new(),
            busy: Vec::new(),

            states: Vec::new(),

            idx_to_state: RwLock::new((0, HashMap::new())),

            span,
        }
    }

    pub fn add_link(&mut self, config: Link) -> LinkId {
        let _s = self.span.enter();

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
            self.last_handshake.push(Mutex::new(Tai64N::zero()));

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
    pub fn queue_handshake(&self, link: LinkId, pool: impl Dequeue, net_output: impl Enqueue) {
        let _s = self.span.enter();

        trace!(link = ?link, "queueing handshake");

        let Some(state_pos) = self.alloc_state(link) else {
            return;
        };

        let state_id = link.0 * N_SESSIONS + state_pos as usize;
        let (packet, index) = {
            let mut state = self.states[state_id].write();
            let (new_state, packet, index) = match state.deref_mut() {
                &mut SessionState::None => {
                    let Some(mut packet) = pool.pop() else {
                        return;
                    };

                    let index = self.prepare_index(state_id);

                    let init_state = {
                        let mut cookies = self.cookies[link.0].lock();
                        self.noise_params[link.0].format_handshake_initiation(
                            index,
                            &self.stamper,
                            &mut cookies,
                            &mut packet,
                        )
                    };
                    (init_state, packet, index)
                }
                _ => {
                    // Busy
                    return;
                }
            };
            *state = SessionState::InitSent(new_state);

            (packet, index)
        };

        net_output.push(packet);
        trace!(?link, state_id, index, "handshake sent");
    }

    pub fn encode_one(
        &self,
        link: LinkId,
        pool: impl Dequeue,
        msg_input: impl Dequeue,
        net_output: impl Enqueue,
    ) {
        let _s = self.span.enter();

        // need to ensure session
        let ses_id = self.active[link.0].load(Ordering::Relaxed);
        let state_id = link.0 * N_SESSIONS + ses_id as usize;
        {
            let state = self.states[state_id].read();
            match state.deref() {
                SessionState::None => {}
                SessionState::Active(ses) => {
                    if let Some(mut packet) = msg_input.pop() {
                        ses.encrypt(&mut packet);
                        net_output.push(packet);
                        trace!(
                            ?link,
                            state_id,
                            index = ses.receiving_index,
                            "encrypting packet sent"
                        );
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
        pool: impl Enqueue,
        net_input: impl Dequeue,
        net_output: impl Enqueue,
        tun_output: impl Enqueue,
    ) {
        let _s = self.span.enter();

        let Some(packet) = net_input.pop() else {
            debug!(?link, "no data");
            return;
        };

        match packet.tag() {
            Ok(tagged) => match tagged {
                super::packet::AnyPacket::Init(packet) => {
                    trace!(?link, "init recieved");

                    let recv_state = {
                        let mut last_handshake = self.last_handshake[link.0].lock();
                        match self.noise_params[link.0]
                            .receive_handshake_initiation(&mut last_handshake, &packet)
                        {
                            Ok(state) => state,
                            Err(err) => {
                                trace!(?link, ?err, "init decode failed");
                                pool.push(packet.into_packet());
                                return;
                            }
                        }
                    };

                    let mut packet = packet.into_packet();
                    let Some(index) = self.alloc_state(link) else {
                        pool.push(packet);
                        return;
                    };
                    let state_id = link.0 * N_SESSIONS + index;
                    let index = {
                        let mut state = self.states[state_id].write();
                        let mut cookies = self.cookies[link.0].lock();
                        let local_index = self.prepare_index(state_id);
                        *state = SessionState::Active(
                            self.noise_params[link.0].format_handshake_response(
                                recv_state,
                                local_index,
                                &mut cookies,
                                &mut packet,
                            ),
                        );
                        local_index
                    };
                    self.activate(link, index);
                    net_output.push(packet);
                    trace!(?link, state_id, index, "reply sent")
                }
                super::packet::AnyPacket::Reply(packet) => {
                    trace!(?link, "reply recieved");

                    let index = packet.receiver_idx();
                    let Some((state_id, for_link)) = self.map_index(index) else {
                        trace!(?link, index, "unknown index recieved");
                        pool.push(packet.into_packet());
                        return;
                    };
                    if for_link != link {
                        // Got a reply for an unexpected link
                        warn!(?link, found=?for_link, "recieved packet for wrong link");
                        pool.push(packet.into_packet());
                        return;
                    }

                    {
                        let mut state = self.states[state_id].write();
                        let ses = match state.deref() {
                            SessionState::InitSent(init) => {
                                match self.noise_params[link.0]
                                    .receive_handshake_response(init, &packet)
                                {
                                    Ok(ses) => ses,
                                    Err(err) => {
                                        trace!(?link, ?err, state_id, "failed to decode response");
                                        pool.push(packet.into_packet());
                                        return;
                                    }
                                }
                            }
                            _ => {
                                // Reply for invalid sate
                                trace!(?link, state_id, "recieved response for incorrect sate");
                                pool.push(packet.into_packet());
                                return;
                            }
                        };
                        // TODO: should consider index should be changed
                        *state = SessionState::Active(ses);
                    }

                    self.activate(link, index);
                    pool.push(packet.into_packet());
                }
                super::packet::AnyPacket::Cookie(mut _packet) => todo!(),
                super::packet::AnyPacket::Data(mut packet) => {
                    trace!(?link, "data packet recieved");

                    let index = packet.receiver_idx();
                    let Some((state_id, for_link)) = self.map_index(index) else {
                        trace!(?link, index, "unknown index recieved");
                        pool.push(packet.into_packet());
                        return;
                    };
                    if for_link != link {
                        // Got a reply for an unexpected link
                        warn!(?link, found=?for_link, "recieved packet for wrong link");
                        pool.push(packet.into_packet());
                        return;
                    }

                    // TODO(pna): this will need to be generational
                    match self.states[state_id].read().deref() {
                        SessionState::Active(ses) => {
                            if let Err(err) = ses.decrypt(&mut packet) {
                                trace!(?link, state_id, index, ?err, "failed to decrypt packet");
                                pool.push(packet.into_packet())
                            } else {
                                tun_output.push(packet.into_packet());
                                trace!(?link, state_id, index, "decrypted packet pushed");
                            }
                        }
                        _ => {
                            trace!(?link, state_id, "received data packet for inactive state");
                            pool.push(packet.into_packet());
                        }
                    }
                }
            },
            Err(packet) => {
                // Return packet to pool
                trace!(?link, "unknown packet recieved");
                pool.push(packet);
            }
        }
    }

    fn map_index(&self, idx: u32) -> Option<(usize, LinkId)> {
        let _s = self.span.enter();

        let state_id = *{ self.idx_to_state.read().1.get(&idx)? };
        let link = LinkId(state_id / N_SESSIONS); // we allocate N_SESSIONS per link

        trace!(?link, state_id, index = idx, "maped index to state");

        Some((state_id, link))
    }

    /// Try to aquire a free state for link
    fn alloc_state(&self, link: LinkId) -> Option<usize> {
        let _s = self.span.enter();

        let mut busy = self.busy[link.0].lock();
        let mut index = 0..N_SESSIONS;
        // Sweep and find a free bit
        let idx = loop {
            let Some(idx) = index.next() else {
                // No free slot
                trace!(?link, "all states busy");
                return None;
            };
            let spot = 1 << idx;
            if spot & *busy == 0 {
                break idx;
            }
        };
        *busy |= 1 << idx;

        trace!(?link, index = idx, "allocated a new state");

        Some(idx)
    }

    fn prepare_index(&self, state_id: usize) -> u32 {
        let _s = self.span.enter();

        // TODO: use a pseudo random generator
        let mut next_and_map = self.idx_to_state.write();
        // TODO: need some max iter count
        while next_and_map.1.contains_key(&next_and_map.0) {
            next_and_map.0 += 1;
        }
        let index = next_and_map.0;
        next_and_map.1.insert(index, state_id);
        next_and_map.0 += 1;

        trace!(state_id, index, "prepared index for recieve");

        index
    }

    fn activate(&self, link: LinkId, index: u32) {
        let _s = self.span.enter();

        self.active[link.0].store(index, Ordering::Relaxed);
        trace!(?link, index, "activated new state");
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
    use tracing::{subscriber, Level};
    use tracing_subscriber::{fmt, util::SubscriberInitExt};
    use x25519_dalek::StaticSecret;

    impl Enqueue for &mut Vec<Packet> {
        fn push(self, packet: Packet) {
            self.push(packet);
        }
    }

    impl Dequeue for &mut Vec<Packet> {
        fn pop(self) -> Option<Packet> {
            self.pop()
        }
    }

    #[test]
    pub fn test_handshaking() {
        let mut node_a = Node::new(StaticSecret::random_from_rng(OsRng));
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
        let _ = fmt()
            .with_max_level(Level::TRACE)
            .with_test_writer()
            .try_init();

        let msg = b"hello mister";

        let mut node_a = Node::new(StaticSecret::random_from_rng(OsRng));
        let mut node_b = Node::new(StaticSecret::random_from_rng(OsRng));

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
        assert_eq!(net_b.len(), 1, "hanshake init sent");

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
        assert_eq!(msg_b_output.pop().expect("data").data_mut(), msg,);
    }
}
