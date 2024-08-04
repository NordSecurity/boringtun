use std::{
    collections::HashMap,
    sync::atomic::{AtomicU32, Ordering},
};

use parking_lot::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{handshake::Handshake, session::Session, Packet, Tunn};

pub trait QueueIn: Sync {
    fn push(&self, packet: Packet);
}

pub trait QueueOut: Sync {
    fn pop(&self) -> Option<Packet>;
}

// pub trait QueueOut: Sync {

// }

//
pub struct Node {
    pub public_key: PublicKey,
    secret_key: StaticSecret,

    connections: HashMap<PublicKey, ConnId>,

    idx_to_handshake: HashMap<u32, ConnId>,
    handshakes: Vec<RwLock<Handshake>>,

    active_session: Vec<AtomicU32>,
    idx_to_session: HashMap<u32, usize>,
    sessions: Vec<RwLock<Option<Session>>>,
}

impl Node {
    pub fn new(ss: StaticSecret, psk: Option<StaticSecret>) -> Self {
        Self {
            public_key: PublicKey::from(&ss),
            secret_key: ss,

            connections: HashMap::new(),

            idx_to_handshake: HashMap::new(),
            handshakes: Vec::new(),

            idx_to_session: HashMap::new(),
            sessions: Vec::new(),
        }
    }

    pub fn add_conn(&mut self, config: Conn) -> ConnId {
        todo!()
    }

    pub fn transport_one_plaintext(
        &self,
        conn: ConnId,
        tun_out: &impl QueueOut,
        net_in: &impl QueueIn,
    ) {
        // need to ensure session
        let ses_id = self.active_session[conn.0].load(Ordering::Relaxed);
        {
            let ses = self.sessions[conn.0 + ses_id as usize].read();
            if let Some(ses) = ses.as_ref() {
                if let Some(mut packet) = tun_out.pop() {
                    ses.encrypt(&mut packet);
                    net_in.push(packet)
                }
            }
        }
        if let Some(ses) =  {
            ses_id.
        }
    }

    pub fn transport_one_encrypted(
        &self,
        net_out: &impl QueueOut,
        net_in: &impl QueueIn,
        tun_in: &impl QueueIn,
    ) {
        match Tunn::parse_incoming_packet(&packet.0) {
            Ok(packet) => match packet {
                super::TaggedPacket::HandshakeInit(init) => {}
                super::TaggedPacket::HandshakeResponse(_) => todo!(),
                super::TaggedPacket::PacketCookieReply(_) => todo!(),
                super::TaggedPacket::PacketData(_) => todo!(),
            },
            Err(_) => return,
        }
    }
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

    use crate::noise::Tunn;

    use super::*;

    use parking_lot::Mutex;
    use rand_core::OsRng;
    use x25519_dalek::StaticSecret;

    #[derive(Default)]
    struct BadQueue(Mutex<Vec<Packet>>);

    impl QueueIn for BadQueue {
        fn push(&self, packet: Packet) {
            self.0.lock().push(packet);
        }
    }

    impl QueueOut for BadQueue {
        fn pop(&self) -> Option<Packet> {
            self.0.lock().pop()
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

        let msg_a = BadQueue::default();
        let net_a = BadQueue::default();
        node_a.queue_plaintext(conn_ab, packet, & net_a);

        let out_b = BadQueue::default();
        let net_b = BadQueue::default();

        {
            let mut net = net_a.0.lock();
            for packet in net.drain(..) {
                node_b.queue_encrypted(packet, &out_b, &net_b);
            }
        }

        {
            let mut net = net_b.0.lock();
            for packet in net.drain(..) {
                node_a.queue_encrypted(packet, &out_b, &net_a);
            }
        }

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
