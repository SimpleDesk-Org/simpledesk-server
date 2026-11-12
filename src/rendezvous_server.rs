use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        future::ready,
        sink::SinkExt,
        stream::{SplitSink, Stream, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

pub(crate) const REG_TIMEOUT: i64 = 30_000;
// SimpleDesk: devices may register over TCP/WebSocket. The connection stays open, the
// server sends an empty heartbeat and the device echoes it, which keeps it online.
const TCP_HEARTBEAT_MS: u128 = 20_000;
// A registered connection without any message for this long is dropped.
const TCP_PEER_IDLE_MS: u128 = 60_000;
// Other TCP/WebSocket connections are dropped after this, as before.
const TCP_IDLE_MS: u128 = 30_000;
const TCP_CHECK_INTERVAL: Duration = Duration::from_secs(5);
// Told to the device in seconds; it reconnects after 1.5 times this without a message.
const TCP_KEEP_ALIVE_SECS: i32 = 30;
// Open connections of devices registered over TCP/WebSocket, by their peer address.
pub(crate) type TcpPeers = Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Bytes>>>>;
// SimpleDesk: state of one TCP/WebSocket connection.
struct TcpConn {
    // Messages for the device registered on this connection.
    tx: mpsc::UnboundedSender<Bytes>,
    // Id of the device registered on this connection, if any.
    registered: Option<String>,
}
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
enum Sink {
    TcpStream(TcpStreamSink),
    Ws(WsSink),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
const MAX_RELAY_UUID_LEN: usize = 128;

// The peer sends this uuid to whatever relay_server names, so keep control bytes out of it.
fn validate_relay_uuid(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_RELAY_UUID_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid relay UUID");
    }
    Ok(())
}

// A peer acknowledging a RequestRelay leaves both fields empty.
fn validate_relay_response(uuid: &str, relay_server: &str) -> Result<(), &'static str> {
    if uuid.is_empty() && relay_server.is_empty() {
        return Ok(());
    }
    validate_relay_uuid(uuid)
}

// An online query for about 5000 ids is the largest message a client sends here.
const DEFAULT_MAX_MESSAGE_KB: usize = 64;
// A knob that can be turned to unbounded is not a bound.
const MAX_MESSAGE_KB_CAP: usize = 64 << 10;
// tungstenite's default, so raising MAX_MESSAGE_KB does not widen a frame past it.
const WS_DEFAULT_MAX_FRAME_SIZE: usize = 16 << 20;
// Every connection pays its read buffer up front, and tungstenite's default is 128 KiB.
const WS_BUFFER_SIZE: usize = 8 << 10;
static MAX_MESSAGE: Lazy<usize> =
    Lazy::new(|| max_message_kb(&get_arg("MAX_MESSAGE_KB")) << 10);

fn max_message_kb(arg: &str) -> usize {
    match arg.parse::<usize>() {
        Ok(kb) if kb > 0 => kb.min(MAX_MESSAGE_KB_CAP),
        _ => DEFAULT_MAX_MESSAGE_KB,
    }
}

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 { return; }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        if lock.len() >= max { lock.pop_front(); }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
    // SimpleDesk: LOGIN_REQUIRED=Y, only signed-in users may connect to a device.
    login_required: bool,
}

/// What a user who is not signed in sees when connecting (SimpleDesk, LOGIN_REQUIRED=Y).
const LOGIN_REQUIRED_MESSAGE: &str =
    "Bitte melde dich in SimpleDesk an (Konto → Anmelden), dann kannst du dich verbinden.";

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    tcp_peers: TcpPeers,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        // SimpleDesk: with WS_ONLY only the WebSocket port listens on bind_addr.
        let ws_only = ws_only();
        let internal_addr = internal_bind_address(bind_addr, ws_only);
        log::info!("WS_ONLY={}", if ws_only { "Y" } else { "N" });
        let mut socket = create_udp_listener(internal_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            tcp_peers: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
                login_required: get_arg("LOGIN_REQUIRED").to_uppercase() == "Y",
            }),
        };
        log::info!(
            "LOGIN_REQUIRED={}",
            if rs.inner.login_required { "Y" } else { "N" }
        );
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        // SimpleDesk: web panel on the API port (port - 2), reachable like the WebSocket port.
        tokio::spawn(crate::panel::start(
            bind_addr,
            (port - 2) as u16,
            rs.pm.clone(),
            rs.tcp_peers.clone(),
        ));
        let mut listener = create_tcp_listener(internal_addr, port).await?;
        let mut listener2 = create_tcp_listener(internal_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(bind_addr, ws_port).await?;
        let mut listener_console = listen_console(internal_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        log::info!("MAX_MESSAGE_KB={}", *MAX_MESSAGE >> 10);
        let test_addr = get_arg("TEST_HBBS");
        // SimpleDesk: without the other ports every connection has to go over the relay.
        if ws_only || get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(internal_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(internal_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(internal_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(internal_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => {
                            // SimpleDesk: a device registered over TCP/WebSocket gets it there.
                            if !self.send_to_tcp_peer(&msg, addr).await {
                                allow_err!(socket.send(msg.as_ref(), addr).await);
                            }
                        }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if let Some(res) = self.register_pk_result(rk, addr).await {
                        return send_rk_res(socket, addr, res).await;
                    }
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        conn: &mut TcpConn,
    ) -> bool {
        if bytes.is_empty() {
            // SimpleDesk: a registered device echoes the empty heartbeat.
            if let Some(id) = conn.registered.clone() {
                self.touch_tcp_peer(&id, try_into_v4(addr)).await;
                return true;
            }
            return false;
        }
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    if let Err(err) = validate_relay_uuid(&rf.uuid) {
                        log::warn!(
                            "Drop RequestRelay from {addr}: {err} (length {})",
                            rf.uuid.len()
                        );
                        return false;
                    }
                    // SimpleDesk: a relay only for signed-in users, see handle_punch_hole_request.
                    if !self.signed_in(&rf.token).await {
                        log::info!("Relay to {} from {} refused: not signed in", rf.id, addr);
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_relay_response(RelayResponse {
                            refuse_reason: LOGIN_REQUIRED_MESSAGE.to_owned(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, msg_out).await;
                        return false;
                    }
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    if let Err(err) = validate_relay_response(&rr.uuid, &rr.relay_server) {
                        log::warn!(
                            "Drop RelayResponse from {addr}: {err} (length {})",
                            rr.uuid.len()
                        );
                        return false;
                    }
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    // SimpleDesk: accepted over TCP/WebSocket too, the connection stays open.
                    return self.handle_tcp_register_pk(rk, sink, addr, conn).await;
                }
                _ => {}
            }
        }
        false
    }

    /// Checks a RegisterPk and stores the key of the device. Shared by UDP and
    /// TCP/WebSocket (SimpleDesk). None means the request is ignored without an answer.
    async fn register_pk_result(
        &mut self,
        rk: RegisterPk,
        addr: SocketAddr,
    ) -> Option<register_pk_response::Result> {
        if rk.uuid.is_empty() || rk.pk.is_empty() {
            return None;
        }
        let id = rk.id;
        let ip = addr.ip().to_string();
        if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
            return Some(UUID_MISMATCH);
        } else if !self.check_ip_blocker(&ip, &id).await {
            return Some(TOO_FREQUENT);
        }
        let peer = self.pm.get_or(&id).await;
        let (changed, ip_changed) = {
            let peer = peer.read().await;
            if peer.uuid.is_empty() {
                (true, false)
            } else {
                if peer.uuid == rk.uuid {
                    if peer.info.ip != ip && peer.pk != rk.pk {
                        log::warn!(
                            "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                            id,
                            ip,
                            rk.pk,
                            peer.info.ip,
                            peer.pk,
                        );
                        drop(peer);
                        return Some(UUID_MISMATCH);
                    }
                } else {
                    log::warn!(
                        "Peer {} uuid mismatch: {:?} vs {:?}",
                        id,
                        rk.uuid,
                        peer.uuid
                    );
                    drop(peer);
                    return Some(UUID_MISMATCH);
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                    ip_changed,
                )
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if req_pk.0 > 2 {
            return Some(TOO_FREQUENT);
        }
        req_pk.0 += 1;
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.clone(), 1);
                } else if let Some(v) = ips.get_mut(&ip) {
                    *v += 1;
                } else {
                    ips.insert(ip.clone(), 1);
                }
            } else {
                lock.insert(
                    id.clone(),
                    (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                );
            }
        }
        if changed {
            self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
        }
        Some(register_pk_response::Result::OK)
    }

    /// SimpleDesk: a device registers over TCP/WebSocket. On success the connection is
    /// remembered, so messages for the device are sent over it instead of UDP.
    async fn handle_tcp_register_pk(
        &mut self,
        rk: RegisterPk,
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        conn: &mut TcpConn,
    ) -> bool {
        let addr = try_into_v4(addr);
        if !rk.old_id.is_empty() {
            // SimpleDesk: the device asks for a new ID (rustdesk --set-id).
            let res = self.change_id_result(&rk, addr).await;
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_register_pk_response(RegisterPkResponse {
                result: res.into(),
                ..Default::default()
            });
            Self::send_to_sink(sink, msg_out).await;
            return false;
        }
        let id = rk.id.clone();
        let Some(res) = self.register_pk_result(rk, addr).await else {
            return false;
        };
        let ok = res == register_pk_response::Result::OK;
        if ok {
            if let Some(peer) = self.pm.get_in_memory(&id).await {
                let mut peer = peer.write().await;
                peer.socket_addr = addr;
                peer.last_reg_time = Instant::now();
            }
            if let Some(old) = conn.registered.replace(id) {
                log::info!("Connection {} registered again, was {}", addr, old);
            }
            self.tcp_peers.lock().await.insert(addr, conn.tx.clone());
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_pk_response(RegisterPkResponse {
            result: res.into(),
            keep_alive: if ok { TCP_KEEP_ALIVE_SECS } else { 0 },
            ..Default::default()
        });
        Self::send_to_sink(sink, msg_out).await;
        true
    }

    /// SimpleDesk: checks and applies an ID change. The client sends old_id, the new id
    /// and its uuid; only the device that owns old_id may rename it.
    async fn change_id_result(
        &mut self,
        rk: &RegisterPk,
        addr: SocketAddr,
    ) -> register_pk_response::Result {
        use register_pk_response::Result::{ID_EXISTS, INVALID_ID_FORMAT, OK};
        if rk.uuid.is_empty() || !hbb_common::is_valid_custom_id(&rk.id) {
            return INVALID_ID_FORMAT;
        }
        if !self.check_ip_blocker(&addr.ip().to_string(), &rk.id).await {
            return TOO_FREQUENT;
        }
        if rk.id == rk.old_id {
            return OK;
        }
        if let Some(peer) = self.pm.get(&rk.id).await {
            let uuid = peer.read().await.uuid.clone();
            if !uuid.is_empty() {
                // Already this device's ID, or taken by another device.
                return if uuid == rk.uuid { OK } else { ID_EXISTS };
            }
        }
        let Some(peer) = self.pm.get(&rk.old_id).await else {
            // The old ID is unknown here, so there is nothing to rename.
            return OK;
        };
        let old_uuid = peer.read().await.uuid.clone();
        if old_uuid.is_empty() {
            // Never registered with a key, so there is nothing to rename either.
            return OK;
        }
        if old_uuid != rk.uuid {
            log::warn!("Change id of {} refused: uuid mismatch", rk.old_id);
            return UUID_MISMATCH;
        }
        self.pm.change_id(peer, &rk.old_id, &rk.id).await
    }

    /// SimpleDesk: sends a message to a device registered over TCP/WebSocket.
    /// Returns false if no such device has this address, then UDP is used as before.
    async fn send_to_tcp_peer(&self, msg: &RendezvousMessage, addr: SocketAddr) -> bool {
        let Some(tx) = self.tcp_peers.lock().await.get(&addr).cloned() else {
            return false;
        };
        match msg.write_to_bytes() {
            Ok(bytes) => {
                tx.send(Bytes::from(bytes)).ok();
            }
            Err(err) => log::error!("write_to_bytes failed: {}", err),
        }
        true
    }

    /// SimpleDesk: whether a connection request may go on. Always, unless LOGIN_REQUIRED=Y;
    /// then only with the access token of a signed-in user.
    async fn signed_in(&self, token: &str) -> bool {
        !self.inner.login_required || crate::api::token_user(&self.pm.db, token).await.is_some()
    }

    /// SimpleDesk: the device echoed the heartbeat, so it is still online.
    async fn touch_tcp_peer(&self, id: &str, addr: SocketAddr) {
        if let Some(peer) = self.pm.get_in_memory(id).await {
            let mut peer = peer.write().await;
            if peer.socket_addr == addr {
                peer.last_reg_time = Instant::now();
            }
        }
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        // SimpleDesk: the client sends its access token with the request.
        if !self.signed_in(&ph.token).await {
            log::info!("Connection to {} from {} refused: not signed in", ph.id, addr);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                other_failure: LOGIN_REQUIRED_MESSAGE.to_owned(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            record_punch_req(
                try_into_v4(addr).ip().to_string(),
                try_into_v4(peer_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(Bytes::from(bytes))).await);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(addr) = to_addr {
            self.tx.send(Data::Msg(msg.into(), addr))?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// Handles loopback console requests and external NAT or online-status queries.
    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        if let Err(err) = timeout(1000, stream.write_all(res.as_bytes()))
                            .await
                            .unwrap_or_else(|elapsed| Err(elapsed.into()))
                        {
                            log::warn!("Failed to send the console reply: {err}");
                        }
                    }
                }
            });
            return;
        }
        let mut stream = FramedStream::from(stream, addr);
        stream.codec_mut().set_max_packet_length(*MAX_MESSAGE);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    /// Processes rendezvous messages on an accepted TCP or WebSocket connection.
    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let callback = |req: &Request, response: Response| {
                let headers = req.headers();
                // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
                // client IP is preserved when the WebSocket port runs behind a
                // reverse proxy (WSS). They are NOT validated: anyone who can reach
                // this port directly can spoof an arbitrary IP, bypassing IP-based
                // rate limiting / blocking and corrupting logged IPs. Do not expose
                // the WebSocket port directly to untrusted networks; only the
                // reverse proxy, which overwrites these headers, should be able to
                // connect to it.
                // https://github.com/rustdesk/rustdesk-server/issues/634
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok());
                if let Some(ip) = real_ip {
                    if let Ok(ip) = ip.parse() {
                        addr = SocketAddr::new(ip, addr.port());
                    }
                }
                Ok(response)
            };
            let ws_config = tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(*MAX_MESSAGE))
                .max_frame_size(Some((*MAX_MESSAGE).min(WS_DEFAULT_MAX_FRAME_SIZE)))
                .read_buffer_size(WS_BUFFER_SIZE)
                .write_buffer_size(WS_BUFFER_SIZE);
            let ws_stream = timeout(
                30_000,
                tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config)),
            )
            .await??;
            let (a, b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            let reader = b
                .take_while(|msg| ready(msg.is_ok()))
                .map(|msg| match msg {
                    Ok(tungstenite::Message::Binary(bytes)) => Some(bytes),
                    _ => None,
                });
            self.tcp_conn_loop(reader, &mut sink, addr, key, ws).await;
        } else {
            let mut framed = Framed::new(stream, BytesCodec::new());
            framed.codec_mut().set_max_packet_length(*MAX_MESSAGE);
            let (a, b) = framed.split();
            sink = Some(Sink::TcpStream(a));
            let reader = b
                .take_while(|bytes| ready(bytes.is_ok()))
                .map(|bytes| bytes.ok().map(BytesMut::freeze));
            self.tcp_conn_loop(reader, &mut sink, addr, key, ws).await;
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    /// Reads the messages of one TCP/WebSocket connection. `reader` yields Some(bytes) for
    /// a message and None for a frame without one, and ends when the connection does.
    /// SimpleDesk: for a device registered on the connection it also sends the heartbeat
    /// and the messages meant for the device, and forgets the connection at the end.
    async fn tcp_conn_loop<S>(
        &mut self,
        reader: S,
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) where
        S: Stream<Item = Option<Bytes>> + Send,
    {
        let mut reader = Box::pin(reader);
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
        let mut conn = TcpConn {
            tx,
            registered: None,
        };
        let mut check = interval(TCP_CHECK_INTERVAL);
        let mut last_recv = Instant::now();
        let mut last_heartbeat = Instant::now();
        loop {
            tokio::select! {
                msg = reader.next() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    last_recv = Instant::now();
                    if let Some(bytes) = msg {
                        if !self.handle_tcp(&bytes, sink, addr, key, ws, &mut conn).await {
                            break;
                        }
                    }
                }
                Some(bytes) = rx.recv() => {
                    Self::send_bytes_to_sink(sink, bytes).await;
                }
                _ = check.tick() => {
                    let idle = if conn.registered.is_some() {
                        TCP_PEER_IDLE_MS
                    } else {
                        TCP_IDLE_MS
                    };
                    if last_recv.elapsed().as_millis() > idle {
                        break;
                    }
                    if conn.registered.is_some()
                        && last_heartbeat.elapsed().as_millis() >= TCP_HEARTBEAT_MS
                    {
                        last_heartbeat = Instant::now();
                        Self::send_bytes_to_sink(sink, Bytes::new()).await;
                    }
                }
            }
        }
        if let Some(id) = conn.registered.take() {
            let addr = try_into_v4(addr);
            {
                let mut tcp_peers = self.tcp_peers.lock().await;
                if tcp_peers.get(&addr).is_some_and(|tx| tx.same_channel(&conn.tx)) {
                    tcp_peers.remove(&addr);
                }
            }
            // Without its connection the device cannot be reached, so it is offline now and
            // not only after REG_TIMEOUT. Unless it registered again on another connection.
            if let Some(peer) = self.pm.get_in_memory(&id).await {
                let mut peer = peer.write().await;
                if peer.socket_addr == addr {
                    peer.last_reg_time = get_expired_time();
                }
            }
        }
    }

    #[inline]
    async fn send_bytes_to_sink(sink: &mut Option<Sink>, bytes: Bytes) {
        if let Some(sink) = sink.as_mut() {
            match sink {
                Sink::TcpStream(s) => {
                    allow_err!(s.send(bytes).await);
                }
                Sink::Ws(ws) => {
                    allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                }
            }
        }
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_message_kb_falls_back_to_default_and_is_capped() {
        assert_eq!(max_message_kb(""), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("0"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("abc"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("256"), 256);
        assert_eq!(max_message_kb(&usize::MAX.to_string()), MAX_MESSAGE_KB_CAP);
    }

    #[test]
    fn default_message_bound_holds_an_online_query_for_5000_ids() {
        let mut msg = RendezvousMessage::new();
        msg.set_online_request(OnlineRequest {
            id: "1234567890".to_owned(),
            peers: (0..5000).map(|i| format!("{i:010}")).collect(),
            ..Default::default()
        });
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len <= DEFAULT_MAX_MESSAGE_KB << 10, "{len}");
    }

    #[test]
    fn relay_uuid_validation() {
        let uuid = "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12";
        assert_eq!(validate_relay_response(uuid, "relay.example"), Ok(()));
        assert_eq!(validate_relay_response("", ""), Ok(()));
        let max_len = "a".repeat(128);
        for value in [
            uuid,
            "E4C181D0-41C7-4AE6-8EF0-36581B6B2B12",
            "e4c181d041c74ae68ef036581b6b2b12",
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "a_b-c",
            max_len.as_str(),
        ] {
            assert_eq!(validate_relay_uuid(value), Ok(()), "rejected {value:?}");
        }
        let too_long = "a".repeat(129);
        for value in [
            "",
            "\r\nPING\r\n",
            "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12\n",
            "e4c181d0 41c7",
            "{e4c181d0-41c7-4ae6-8ef0-36581b6b2b12}",
            "e4c181d0\0",
            "é",
            too_long.as_str(),
        ] {
            assert!(validate_relay_uuid(value).is_err(), "accepted {value:?}");
            assert!(validate_relay_response(value, "relay.example").is_err());
        }
    }

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    // SimpleDesk: devices register over TCP/WebSocket.

    async fn test_server(dir: &tempfile::TempDir) -> RendezvousServer {
        test_server_with(dir, false).await
    }

    async fn test_server_with(dir: &tempfile::TempDir, login_required: bool) -> RendezvousServer {
        let pm = crate::peer::test_peer_map(dir).await;
        let (tx, _rx) = mpsc::unbounded_channel::<Data>();
        RendezvousServer {
            tcp_punch: Default::default(),
            tcp_peers: Default::default(),
            pm,
            tx,
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Default::default(),
            inner: Arc::new(Inner {
                serial: 0,
                version: String::new(),
                software_url: String::new(),
                mask: None,
                local_ip: String::new(),
                sk: None,
                login_required,
            }),
        }
    }

    /// Tests that end in record_punch_req take this, so they do not change PUNCH_REQS while
    /// punch_reqs_bounded counts it.
    static PUNCH_REQS_IN_USE: Lazy<TokioMutex<()>> = Lazy::new(|| TokioMutex::new(()));

    #[hbb_common::tokio::test]
    async fn login_required_lets_only_signed_in_users_connect() {
        let _punch_reqs = PUNCH_REQS_IN_USE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let mut rs = test_server_with(&dir, true).await;
        // An online device.
        {
            let peer = rs.pm.get_or("Felix-Home-PC").await;
            let mut peer = peer.write().await;
            peer.last_reg_time = Instant::now();
            peer.socket_addr = "198.51.100.1:5000".parse().unwrap();
        }
        let requester: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let request = |token: &str| PunchHoleRequest {
            id: "Felix-Home-PC".to_owned(),
            token: token.to_owned(),
            ..Default::default()
        };

        // Without a token or with an unknown one: refused with the message.
        for token in ["", "unknown-token"] {
            let (msg, to) = rs
                .handle_punch_hole_request(requester, request(token), "", true)
                .await
                .unwrap();
            assert!(to.is_none(), "{token:?}");
            assert_eq!(msg.punch_hole_response().other_failure, LOGIN_REQUIRED_MESSAGE);
        }

        // With the token of a signed-in user the request goes to the device.
        rs.pm.db.ensure_external_user("felix").await.unwrap();
        let token = "token-of-felix";
        rs.pm
            .db
            .insert_api_token(&crate::api::token_hash(token), "felix", "Felix-Work-PC")
            .await
            .unwrap();
        let (msg, to) = rs
            .handle_punch_hole_request(requester, request(token), "", true)
            .await
            .unwrap();
        assert_eq!(to, Some("198.51.100.1:5000".parse().unwrap()));
        assert!(!msg.has_punch_hole_response());
    }

    async fn serve_one(rs: &RendezvousServer, ws: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let rs = rs.clone();
        tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            rs.handle_listener(stream, addr, "", ws).await;
        });
        server_addr
    }

    fn register_pk_msg(id: &str) -> Bytes {
        register_pk_msg_for(id, b"simpledesk-test-uuid")
    }

    fn register_pk_msg_for(id: &str, uuid: &'static [u8]) -> Bytes {
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: Bytes::from_static(uuid),
            pk: Bytes::from(vec![7u8; 32]),
            ..Default::default()
        });
        Bytes::from(msg.write_to_bytes().unwrap())
    }

    /// Sends one message on a new TCP connection and returns the RegisterPk result.
    async fn register_result(rs: &RendezvousServer, bytes: Bytes) -> register_pk_response::Result {
        let stream = TcpStream::connect(serve_one(rs, false).await).await.unwrap();
        let mut device = Framed::new(stream, BytesCodec::new());
        device.send(bytes).await.unwrap();
        let msg = next_tcp_msg(&mut device).await;
        msg.register_pk_response().result.enum_value().unwrap()
    }

    fn change_id_msg(old_id: &str, id: &str, uuid: &'static [u8]) -> Bytes {
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            old_id: old_id.to_owned(),
            id: id.to_owned(),
            uuid: Bytes::from_static(uuid),
            ..Default::default()
        });
        Bytes::from(msg.write_to_bytes().unwrap())
    }

    fn punch_hole_msg() -> RendezvousMessage {
        let mut msg = RendezvousMessage::new();
        msg.set_punch_hole(PunchHole {
            relay_server: "relay.example".to_owned(),
            ..Default::default()
        });
        msg
    }

    async fn next_tcp_msg(device: &mut Framed<TcpStream, BytesCodec>) -> RendezvousMessage {
        let bytes = timeout(5_000, device.next()).await.unwrap().unwrap().unwrap();
        RendezvousMessage::parse_from_bytes(&bytes).unwrap()
    }

    async fn next_ws_msg(
        device: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
    ) -> RendezvousMessage {
        loop {
            let msg = timeout(5_000, device.next()).await.unwrap().unwrap().unwrap();
            if let tungstenite::Message::Binary(bytes) = msg {
                return RendezvousMessage::parse_from_bytes(&bytes).unwrap();
            }
        }
    }

    fn assert_registered(msg: &RendezvousMessage) {
        let res = msg.register_pk_response();
        assert_eq!(res.result.enum_value(), Ok(register_pk_response::Result::OK));
        assert_eq!(res.keep_alive, TCP_KEEP_ALIVE_SECS);
    }

    async fn assert_forgotten(rs: &RendezvousServer, addr: SocketAddr) {
        for _ in 0..100 {
            if !rs.tcp_peers.lock().await.contains_key(&addr) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the connection of {addr} was not forgotten");
    }

    #[hbb_common::tokio::test]
    async fn device_registers_over_tcp_and_gets_messages_there() {
        let dir = tempfile::tempdir().unwrap();
        let rs = test_server(&dir).await;
        let stream = TcpStream::connect(serve_one(&rs, false).await).await.unwrap();
        let device_addr = try_into_v4(stream.local_addr().unwrap());
        let mut device = Framed::new(stream, BytesCodec::new());

        device.send(register_pk_msg("simpledesk-tcp")).await.unwrap();
        assert_registered(&next_tcp_msg(&mut device).await);
        assert!(rs.tcp_peers.lock().await.contains_key(&device_addr));
        let peer = rs.pm.get_in_memory("simpledesk-tcp").await.unwrap();
        assert_eq!(peer.read().await.socket_addr, device_addr);

        // A message for the device goes over its connection instead of UDP.
        assert!(rs.send_to_tcp_peer(&punch_hole_msg(), device_addr).await);
        assert!(next_tcp_msg(&mut device).await.has_punch_hole());

        // The echoed heartbeat keeps the connection open.
        device.send(Bytes::new()).await.unwrap();
        assert!(rs.send_to_tcp_peer(&punch_hole_msg(), device_addr).await);
        assert!(next_tcp_msg(&mut device).await.has_punch_hole());
        let online = |peer: &Peer| (peer.last_reg_time.elapsed().as_millis() as i64) < REG_TIMEOUT;
        assert!(online(&*peer.read().await));

        // Without its connection the device is offline at once.
        drop(device);
        assert_forgotten(&rs, device_addr).await;
        for _ in 0..100 {
            if !online(&*peer.read().await) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!online(&*peer.read().await));
    }

    #[hbb_common::tokio::test]
    async fn device_registers_over_websocket_behind_proxy() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let dir = tempfile::tempdir().unwrap();
        let rs = test_server(&dir).await;
        let server_addr = serve_one(&rs, true).await;
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let port = stream.local_addr().unwrap().port();
        let mut req = format!("ws://{server_addr}/ws/id")
            .into_client_request()
            .unwrap();
        // The reverse proxy passes the real address of the device.
        req.headers_mut()
            .insert("X-Real-IP", "203.0.113.7".parse().unwrap());
        let (mut device, _) = tokio_tungstenite::client_async(req, stream).await.unwrap();
        let device_addr: SocketAddr = format!("203.0.113.7:{port}").parse().unwrap();

        device
            .send(tungstenite::Message::Binary(register_pk_msg("simpledesk-ws")))
            .await
            .unwrap();
        assert_registered(&next_ws_msg(&mut device).await);
        assert!(rs.tcp_peers.lock().await.contains_key(&device_addr));

        assert!(rs.send_to_tcp_peer(&punch_hole_msg(), device_addr).await);
        assert!(next_ws_msg(&mut device).await.has_punch_hole());

        device
            .send(tungstenite::Message::Binary(Bytes::new()))
            .await
            .unwrap();
        assert!(rs.send_to_tcp_peer(&punch_hole_msg(), device_addr).await);
        assert!(next_ws_msg(&mut device).await.has_punch_hole());

        drop(device);
        assert_forgotten(&rs, device_addr).await;
    }

    #[hbb_common::tokio::test]
    async fn unregistered_connection_closes_on_empty_message_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let rs = test_server(&dir).await;
        let stream = TcpStream::connect(serve_one(&rs, false).await).await.unwrap();
        let device_addr = try_into_v4(stream.local_addr().unwrap());
        let mut device = Framed::new(stream, BytesCodec::new());
        device.send(Bytes::new()).await.unwrap();
        let next = timeout(5_000, device.next()).await.unwrap();
        assert!(!matches!(next, Some(Ok(_))), "connection stayed open: {next:?}");
        assert!(!rs.send_to_tcp_peer(&punch_hole_msg(), device_addr).await);
    }

    #[hbb_common::tokio::test]
    async fn device_changes_its_id() {
        use register_pk_response::Result::{ID_EXISTS, INVALID_ID_FORMAT, OK};
        let dir = tempfile::tempdir().unwrap();
        let rs = test_server(&dir).await;
        let me: &'static [u8] = b"uuid-of-this-device";
        let other: &'static [u8] = b"uuid-of-other-device";
        assert_eq!(register_result(&rs, register_pk_msg_for("Felix-Old-PC", me)).await, OK);
        assert_eq!(register_result(&rs, register_pk_msg_for("Someone-Else", other)).await, OK);

        // Rename: the old ID is gone, the new one points to the same device.
        assert_eq!(
            register_result(&rs, change_id_msg("Felix-Old-PC", "Felix-Work-PC", me)).await,
            OK
        );
        assert!(rs.pm.get_in_memory("Felix-Old-PC").await.is_none());
        assert!(rs.pm.db.get_peer("Felix-Old-PC").await.unwrap().is_none());
        let renamed = rs.pm.db.get_peer("Felix-Work-PC").await.unwrap().unwrap();
        assert_eq!(renamed.uuid, me.to_vec());

        // Taken by another device, wrong format, or not this device's ID.
        assert_eq!(
            register_result(&rs, change_id_msg("Felix-Work-PC", "Someone-Else", me)).await,
            ID_EXISTS
        );
        assert_eq!(
            register_result(&rs, change_id_msg("Felix-Work-PC", "1-starts-with-digit", me)).await,
            INVALID_ID_FORMAT
        );
        assert_eq!(
            register_result(&rs, change_id_msg("Felix-Work-PC", "Stolen-Name", other)).await,
            UUID_MISMATCH
        );

        // The device registers again under its new ID.
        assert_eq!(register_result(&rs, register_pk_msg_for("Felix-Work-PC", me)).await, OK);
    }

    #[test]
    fn ws_only_moves_other_ports_to_localhost() {
        let any = Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let localhost = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(internal_bind_address(any, false), any);
        assert_eq!(internal_bind_address(None, false), None);
        assert_eq!(internal_bind_address(any, true), localhost);
        assert_eq!(internal_bind_address(None, true), localhost);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let _punch_reqs = PUNCH_REQS_IN_USE.lock().await;
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // one request at least, so MAX_PUNCH_REQUESTS=0 is exercised too
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // the oldest half is evicted and the newest kept
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }
}
