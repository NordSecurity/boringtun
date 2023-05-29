// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "tun_linux.rs"]
pub mod tun;

#[cfg(unix)]
#[path = "udp_unix.rs"]
pub mod udp;

use std::collections::HashMap;
use std::convert::From;
use std::io::{self, BufReader, BufWriter};
use std::net::{IpAddr, SocketAddr};
#[cfg(not(target_os = "windows"))]
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::crypto::x25519::*;
use crate::noise::errors::*;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::*;
use allowed_ips::*;
use peer::*;
use poll::*;
use tun::*;
use udp::*;

use dev_lock::{Lock, LockReadGuard};
use slog::{error, info, o, trace, Logger};
use thiserror::Error;

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug, Error)]
pub enum Error {
    #[error("Socket creation error: {0}")]
    Socket(String),
    #[error("Socket bind error: {0}")]
    Bind(String),
    #[error("FCntl error: {0}")]
    FCntl(String),
    #[error("Event queue error: {0}")]
    EventQueue(String),
    #[error("IOCtl error: {0}")]
    IOCtl(String),
    #[error("Connect error: {0}")]
    Connect(String),
    #[error("Set sockopt error: {0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[error("Get sockopt error: {0}")]
    GetSockOpt(String),
    #[error("Get socket error: {0}")]
    GetSockName(String),
    #[error("UDP read error: {0}")]
    UDPRead(i32),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("Timer error: {0}")]
    Timer(String),
    #[error("Failed read from interface: {0}")]
    IfaceRead(i32),
    #[error("Failed to drop privileges: {0}")]
    DropPrivileges(String),
    #[error("Api socket error")]
    ApiSocket(#[from] std::io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler<T, S> =
    Box<dyn Fn(&mut LockReadGuard<Device<T, S>>, &mut ThreadData<T>) -> Action + Send + Sync>;

pub trait MakeExternalBoringtun: Send + Sync {
    fn make_external(&self, socket: RawFd);
}

// The trait satisfied by tunnel device implementations.
pub trait Tun: 'static + AsRawFd + Sized + Send + Sync {
    fn new(name: &str) -> Result<Self, Error>;
    #[cfg(not(target_os = "windows"))]
    fn new_from_fd(fd: RawFd) -> Result<Self, Error>;
    fn from_tun_fd(fd: RawFd) -> Result<TunSocket, Error>;
    fn set_non_blocking(self) -> Result<Self, Error>;

    fn name(&self) -> Result<String, Error>;
    fn mtu(&self) -> Result<usize, Error>;

    fn write4(&self, src: &[u8]) -> usize;
    fn write6(&self, src: &[u8]) -> usize;
    fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error>;
}

// The trait satisfied by UDP socket implementations.
pub trait Sock: 'static + AsRawFd + Sized + Send + Sync {
    fn new(protect: Arc<dyn MakeExternalBoringtun>) -> Result<Self, Error>;
    fn new6(protect: Arc<dyn MakeExternalBoringtun>) -> Result<Self, Error>;

    fn bind(self, port: u16) -> Result<Self, Error>;
    fn connect(self, dst: &SocketAddr) -> Result<Self, Error>;

    fn set_non_blocking(self) -> Result<Self, Error>;
    fn set_reuse(self) -> Result<Self, Error>;
    fn set_fwmark(&self, mark: u32) -> Result<(), Error>;

    fn port(&self) -> Result<u16, Error>;
    fn sendto(&self, buf: &[u8], dst: SocketAddr) -> usize;
    fn recvfrom<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error>;
    fn write(&self, buf: &[u8]) -> usize;
    fn read<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Error>;

    fn shutdown(&self);
}

pub struct DeviceHandle<T: Tun = TunSocket, S: Sock = UDPSocket> {
    pub device: Arc<Lock<Device<T, S>>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    pub logger: Logger,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    pub open_uapi_socket: bool,
    pub protect: Arc<dyn MakeExternalBoringtun>,
    pub firewall_process_inbound_callback:
        Option<Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>>,
    pub firewall_process_outbound_callback:
        Option<Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>>,
}

pub struct Device<T: Tun, S: Sock> {
    key_pair: Option<(Arc<X25519SecretKey>, Arc<X25519PublicKey>)>,
    queue: Arc<EventPoll<Handler<T, S>>>,

    listen_port: u16,
    fwmark: Option<u32>,
    update_seq: u32,

    iface: Arc<T>,
    udp4: Option<Arc<S>>,
    udp6: Option<Arc<S>>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<Arc<X25519PublicKey>, Arc<Peer<S>>>,
    peers_by_ip: AllowedIps<Arc<Peer<S>>>,
    peers_by_idx: HashMap<u32, Arc<Peer<S>>>,
    next_index: u32,

    pub config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,
}

struct ThreadData<T: Tun> {
    iface: Arc<T>,
    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
    update_seq: u32,
}

impl<T: Tun, S: Sock> DeviceHandle<T, S> {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle<T, S>, Error> {
        Self::new_with_tun(T::new(name)?, config)
    }

    pub fn new_with_tun(tun: T, config: DeviceConfig) -> Result<DeviceHandle<T, S>, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::<T, S>::new_with_tun(tun, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn send_uapi_cmd(&self, cmd: &str) -> String {
        let mut reader = BufReader::new(cmd.as_bytes());
        let mut writer = BufWriter::new(Vec::<u8>::new());
        api::api_exec(&mut self.device.read(), &mut reader, &mut writer);
        std::str::from_utf8(writer.buffer()).unwrap().to_owned()
    }

    pub fn trigger_exit(&self) {
        self.device.read().trigger_exit();
    }

    pub fn drop_connected_sockets(&self) {
        self.device.read().drop_connected_sockets();
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(&path);
        }
    }

    pub fn set_iface(&mut self, new_iface: T) -> Result<(), Error> {
        // Even though device struct is not being written to, we still take a write lock on device to stop the event loop
        self
            .device
            .read()
            .try_writeable(
                |device| device.trigger_yield(),
                |device| {
                    (device.update_seq, _) = device.update_seq.overflowing_add(1);
                    device.iface = Arc::new(new_iface.set_non_blocking()?);
                    device.register_iface_handler(device.iface.clone())?;
                    device.cancel_yield();

                    Ok(())
                }
            ).ok_or(Error::IOCtl("Failed to get device lock when setting tunnel".to_string()))?
    }

    fn event_loop(thread_id: usize, device: &Lock<Device<T, S>>) {
        let mut thread_local = DeviceHandle::new_thread_local(thread_id, &device.read());
        loop {
            let mut device_lock = device.read();
            if device_lock.update_seq != thread_local.update_seq {
                DeviceHandle::clean_thread_local(&thread_local, thread_id, &mut device_lock);
                thread_local = DeviceHandle::new_thread_local(thread_id, &device_lock)
            }
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        handler.cancel();
                    }
                    WaitResult::Error(e) => error!(device_lock.config.logger, "Poll error {:}", e),
                }
            }
        }
    }

    fn clean_thread_local(old: &ThreadData<T>, thread_id: usize, device_lock: &mut LockReadGuard<Device<T, S>>) {
        if thread_id == 0 || !device_lock.config.use_multi_queue {    
            device_lock
                .try_writeable(
                    |device| device.trigger_yield(),
                    |device| {
                        unsafe {
                            device.queue.clear_event_by_fd(old.iface.as_raw_fd());
                        }
                        device.cancel_yield();
                    }
            ).ok_or(Error::IOCtl("Failed to get device lock when setting tunnel".to_string())).unwrap(); // TODO unwrap
        }
    }

    fn new_thread_local(thread_id: usize, device_lock: &LockReadGuard<Device<T, S>>) -> ThreadData<T> {
        #[cfg(target_os = "linux")]
        let t_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: if thread_id == 0 || !device_lock.config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device_lock.iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    T::new(&device_lock.iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device_lock
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
            update_seq: device_lock.update_seq,
        };

        #[cfg(not(target_os = "linux"))]
        let t_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: Arc::clone(&iface_local.iface),
            update_seq: iface_local.update_seq,
        };

        t_local
    }
}

impl<T: Tun, S: Sock> Drop for DeviceHandle<T, S> {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl<T: Tun, S: Sock> Device<T, S> {
    fn next_index(&mut self) -> u32 {
        let next_index = self.next_index;
        self.next_index += 1;
        assert!(next_index < (1 << 24), "Too many peers created");
        next_index
    }

    fn remove_peer(&mut self, pub_key: &X25519PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            peer.shutdown_endpoint(); // close open udp socket and free the closure
            self.peers_by_idx.remove(&peer.index()); // peers_by_idx
            self.peers_by_ip
                .remove(&|p: &Arc<Peer<S>>| Arc::ptr_eq(&peer, p)); // peers_by_ip

            info!(peer.tunnel.logger, "Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: X25519PublicKey,
        update_only: bool,
        remove: bool,
        replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<AllowedIP>,
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        let pub_key = Arc::new(pub_key);

        if remove {
            self.remove_peer(&pub_key);

            return Ok(());
        }

        if let Some(peer) = self.peers.get(&pub_key) {
            let peer = Arc::clone(peer);

            if let Some(endpoint) = endpoint {
                peer.set_endpoint(endpoint);
            }

            if replace_ips {
                self.peers_by_ip
                    .remove(&|p: &Arc<Peer<S>>| Arc::ptr_eq(&peer, p));
                peer.set_allowed_ips(&allowed_ips);
            } else {
                peer.add_allowed_ips(&allowed_ips);
            }

            if let Some(keepalive) = keepalive {
                peer.set_persistent_keepalive(keepalive);
            }

            if let Some(preshared_key) = preshared_key {
                peer.set_preshared_key(preshared_key);
            }

            for AllowedIP { addr, cidr } in allowed_ips {
                self.peers_by_ip.insert(addr, cidr as _, Arc::clone(&peer));
            }
        } else {
            if update_only {
                return Ok(());
            }

            return self
                .new_peer(pub_key, endpoint, allowed_ips, keepalive, preshared_key)
                .and(Ok(()));
        }

        Ok(())
    }

    fn new_peer(
        &mut self,
        pub_key: Arc<X25519PublicKey>,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<AllowedIP>,
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<Arc<Peer<S>>, Error> {
        let next_index = self.next_index();
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");
        let mut tunn = Tunn::new(
            Arc::clone(&device_key_pair.0),
            Arc::clone(&pub_key),
            preshared_key,
            keepalive,
            next_index,
            None,
        )
        .unwrap();

        {
            let pub_key = base64::encode(pub_key.as_bytes());
            let peer_name = format!("{}…{}", &pub_key[0..4], &pub_key[pub_key.len() - 4..]);
            let peer_logger = self.config.logger.new(o!("peer" => peer_name));
            tunn.set_logger(peer_logger);
        }

        let peer = Arc::new(Peer::new(
            tunn,
            next_index,
            endpoint,
            &allowed_ips,
            preshared_key,
            self.config.protect.clone(),
        ));

        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip.insert(addr, cidr as _, Arc::clone(&peer));
        }

        info!(peer.tunnel.logger, "Peer added");

        Ok(peer)
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device<T, S>, Error> {
        Self::new_with_tun(T::new(name)?, config)
    }

    pub fn new_with_tun(tun: T, config: DeviceConfig) -> Result<Device<T, S>, Error> {
        let poll = EventPoll::<Handler<T, S>>::new()?;

        // Create a tunnel device
        let iface = Arc::new(tun.set_non_blocking()?);
        let mtu = iface.mtu()?;

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            update_seq: 0,
        };

        if device.config.open_uapi_socket {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                device.cleanup_paths.push(name_file);
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = Arc::new(
            S::new(self.config.protect.clone())?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?,
        );

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.port()?;
        }

        let udp_sock6 = Arc::new(
            S::new6(self.config.protect.clone())?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?,
        );

        self.register_udp_handler(Arc::clone(&udp_sock4))?;
        self.register_udp_handler(Arc::clone(&udp_sock6))?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, private_key: X25519SecretKey) {
        let mut bad_peers = vec![];

        let private_key = Arc::new(private_key);
        let public_key = Arc::new(private_key.public_key());
        let key_pair = Some((private_key.clone(), public_key.clone()));

        if self.key_pair == key_pair {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            // Taking a pointer should be Ok as long as all other threads are stopped
            let mut_ptr = Arc::into_raw(Arc::clone(peer)) as *mut Peer<S>;

            if unsafe {
                mut_ptr.as_mut().unwrap().tunnel.set_static_private(
                    Arc::clone(&private_key),
                    Arc::clone(&public_key),
                    Some(Arc::clone(&rate_limiter)),
                )
            }
            .is_err()
            {
                // In case we encounter an error, we will remove that peer
                // An error will be a result of bad public key/secret key combination
                bad_peers.push(peer);
            }
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);

        // Remove all the bad peers
        for _ in bad_peers {
            unimplemented!();
        }
    }

    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_fwmark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_fwmark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.endpoint().conn {
                sock.set_fwmark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let peer_map = &d.peers;

                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let endpoint_addr = match peer.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match peer.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            peer.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => error!(d.config.logger, "Timer error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => udp4.sendto(packet, endpoint_addr),
                                SocketAddr::V6(_) => udp6.sendto(packet, endpoint_addr),
                            };
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn drop_connected_sockets(&self) {
        for peer in self.peers.values() {
            let endpoint = peer.endpoint();
            if endpoint.conn.is_some() {
                drop(endpoint);
                peer.shutdown_endpoint();
            }
        }
    }

    pub fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: Arc<S>) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");

                let rate_limiter = d.rate_limiter.as_ref().unwrap();

                // Loop while we have packets on the anonymous connection
                while let Ok((addr, packet)) = udp.recvfrom(&mut t.src_buf[..]) {
                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    let parsed_packet =
                        match rate_limiter.verify_packet(Some(addr.ip()), packet, &mut t.dst_buf) {
                            Ok(packet) => packet,
                            Err(TunnResult::WriteToNetwork(cookie)) => {
                                udp.sendto(cookie, addr);
                                continue;
                            }
                            Err(_) => continue,
                        };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(&private_key, &public_key, &p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers
                                        .get(&X25519PublicKey::from(&hh.peer_static_public[..]))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match peer
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            udp.sendto(packet, addr);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if let Some(callback) = &d.config.firewall_process_inbound_callback {
                                if !callback(&peer.tunnel.peer_static_public, packet) {
                                    continue;
                                }
                            }
                            if peer.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                                trace!(
                                    d.config.logger,
                                    "Pkt -> TunnIface4 ({:?}), len: {}, src_addr: {}",
                                    t.iface.name(),
                                    packet.len(),
                                    addr
                                );
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if let Some(callback) = &d.config.firewall_process_inbound_callback {
                                if !callback(&peer.tunnel.peer_static_public, packet) {
                                    continue;
                                }
                            }
                            if peer.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                                trace!(
                                    d.config.logger,
                                    "Pkt -> TunnIface6 ({:?}), len: {}, src_addr: {}",
                                    t.iface.name(),
                                    packet.len(),
                                    addr
                                );
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            peer.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            udp.sendto(packet, addr);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let ip_addr = addr.ip();
                    peer.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = peer.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(
                                Arc::clone(peer),
                                sock,
                                ip_addr,
                                d.config.logger.clone(),
                            )
                            .unwrap();
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(
        &self,
        peer: Arc<Peer<S>>,
        udp: Arc<S>,
        peer_addr: IpAddr,
        logger: Logger,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let iface = &t.iface;
                let mut iter = MAX_ITR;

                while let Ok(src) = udp.read(&mut t.src_buf[..]) {
                    let mut flush = false;
                    match peer
                        .tunnel
                        .decapsulate(Some(peer_addr), src, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            error!(d.config.logger, "Decapsulate error {:?}", e);
                            eprintln!("Decapsulate error {:?}", e);
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            udp.write(packet);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if let Some(callback) = &d.config.firewall_process_inbound_callback {
                                if !callback(&peer.tunnel.peer_static_public, packet) {
                                    continue;
                                }
                            }
                            if peer.is_allowed_ip(addr) {
                                iface.write4(packet);
                                trace!(
                                    logger,
                                    "Pkt -> TunnIface4 ({:?}), len: {}, src_addr: {}",
                                    iface.name(),
                                    packet.len(),
                                    addr
                                );
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if let Some(callback) = &d.config.firewall_process_inbound_callback {
                                if !callback(&peer.tunnel.peer_static_public, packet) {
                                    continue;
                                }
                            }
                            if peer.is_allowed_ip(addr) {
                                iface.write6(packet);
                                trace!(
                                    logger,
                                    "Pkt -> TunnIface6 ({:?}), len: {}, src_addr: {}",
                                    iface.name(),
                                    packet.len(),
                                    addr
                                );
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            peer.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            udp.write(packet);
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<T>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let udp4 = d.udp4.as_ref().expect("Not connected");
                let udp6 = d.udp6.as_ref().expect("Not connected");

                let peers = &d.peers_by_ip;
                for _ in 0..MAX_ITR {
                    let src = match iface.read(&mut t.src_buf[..mtu]) {
                        Ok(src) => src,
                        Err(Error::IfaceRead(errno)) => {
                            let ek = io::Error::from_raw_os_error(errno).kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            error!(
                                d.config.logger,
                                "Fatal read error on tun interface: errno {:?}", errno
                            );
                            eprintln!("Fatal read error on tun interface: errno {:?}", errno);
                            return Action::Exit;
                        }
                        Err(e) => {
                            error!(
                                d.config.logger,
                                "Unexpected error on tun interface: {:?}", e
                            );
                            eprintln!("Unexpected error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let dst_addr = match Tunn::dst_address(src) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let peer = match peers.find(dst_addr) {
                        Some(peer) => peer,
                        None => continue,
                    };

                    if let Some(callback) = &d.config.firewall_process_outbound_callback {
                        if !callback(&peer.tunnel.peer_static_public, src) {
                            continue;
                        }
                    }

                    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => error!(d.config.logger, "Encapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            let endpoint = peer.endpoint();
                            if let Some(ref conn) = endpoint.conn {
                                let addr = endpoint.addr;
                                // Prefer to send using the connected socket
                                if conn.write(packet) == 0 && packet.len() > 0 {
                                    drop(endpoint);
                                    peer.shutdown_endpoint();
                                } else {
                                    trace!(
                                        d.config.logger,
                                        "Pkt -> ConnSock ({:?}), len: {}, dst_addr: {}",
                                        addr,
                                        packet.len(),
                                        dst_addr
                                    );
                                }
                            } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                udp4.sendto(packet, addr);
                                trace!(
                                    d.config.logger,
                                    "Pkt -> Udp4Sock ({:?}), len: {}, dst_addr: {}",
                                    addr,
                                    packet.len(),
                                    dst_addr
                                );
                            } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                udp6.sendto(packet, addr);
                                trace!(
                                    d.config.logger,
                                    "Pkt -> Udp6Sock ({:?}), len: {}, dst_addr: {}",
                                    addr,
                                    packet.len(),
                                    dst_addr
                                );
                            } else {
                                error!(d.config.logger, "No endpoint");
                            }
                        }
                        _ => panic!("Unexpected result from encapsulate"),
                    };
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
}
