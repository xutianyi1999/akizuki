#[macro_use]
extern crate log;

use std::cell::UnsafeCell;
use std::io::{BufRead, Cursor};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Deref;
use std::os::windows::io::AsRawSocket;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ahash::AHashMap;
use anyhow::anyhow;
use anyhow::Result;
use async_socks5::{AddrKind, SocksDatagram};
use chrono::Utc;
use clap::{Parser, Subcommand};
use crossbeam_channel::Sender;
use ipnet::Ipv4Net;
use iprange::IpRange;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use parking_lot::RwLock;
use simple_wintun::adapter::{WintunAdapter, WintunStream};
use simple_wintun::ReadResult;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const VIRTUAL_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 30, 2);
const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 30, 1);
const INNER_TCP_SERVER_BIND_PORT: u16 = 19980;

// src port -> dst
static mut TCP_NAT_MAP: MaybeUninit<RwLock<AHashMap<u16, (SocketAddrV4, TCPState)>>> =
    MaybeUninit::uninit();
static mut UDP_NAT_MAP: MaybeUninit<
    RwLock<AHashMap<u16, UnboundedSender<(Box<[u8]>, SocketAddrV4)>>>,
> = MaybeUninit::uninit();
static mut DIRECT_INTERFACE_ADDR: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
static mut PROXY_INTERFACE_ADDR: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
static mut SOCKS5_SERVER: MaybeUninit<SocketAddrV4> = MaybeUninit::uninit();
static mut RULE: MaybeUninit<Rule> = MaybeUninit::uninit();
static LOCAL_CLOCK: AtomicI64 = AtomicI64::new(0);

fn set_tcp_nat_map(map: RwLock<AHashMap<u16, (SocketAddrV4, TCPState)>>) {
    unsafe {
        TCP_NAT_MAP.write(map);
    }
}

fn get_tcp_nat_map() -> &'static RwLock<AHashMap<u16, (SocketAddrV4, TCPState)>> {
    unsafe { TCP_NAT_MAP.assume_init_ref() }
}

fn set_udp_nat_map(map: RwLock<AHashMap<u16, UnboundedSender<(Box<[u8]>, SocketAddrV4)>>>) {
    unsafe {
        UDP_NAT_MAP.write(map);
    }
}

fn get_udp_nat_map() -> &'static RwLock<AHashMap<u16, UnboundedSender<(Box<[u8]>, SocketAddrV4)>>> {
    unsafe { UDP_NAT_MAP.assume_init_ref() }
}

fn set_direct_interface_addr(addr: Ipv4Addr) {
    unsafe { DIRECT_INTERFACE_ADDR = addr }
}

fn get_direct_interface_addr() -> Ipv4Addr {
    unsafe { DIRECT_INTERFACE_ADDR }
}

fn set_proxy_interface_addr(addr: Ipv4Addr) {
    unsafe { PROXY_INTERFACE_ADDR = addr }
}

fn get_proxy_interface_addr() -> Ipv4Addr {
    unsafe { PROXY_INTERFACE_ADDR }
}

fn set_proxy(proxy: SocketAddrV4) {
    unsafe { SOCKS5_SERVER.write(proxy) };
}

fn get_proxy() -> SocketAddrV4 {
    unsafe { *SOCKS5_SERVER.assume_init_ref() }
}

fn set_rule(rule: Rule) {
    unsafe { RULE.write(rule) };
}

fn get_rule() -> &'static Rule {
    unsafe { RULE.assume_init_ref() }
}

struct CellWarp<T> {
    v: UnsafeCell<T>,
}

unsafe impl<T> Sync for CellWarp<T> {}

impl<T> Deref for CellWarp<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.v.get() }
    }
}

impl<T> CellWarp<T> {
    fn new(v: UnsafeCell<T>) -> Self {
        CellWarp { v }
    }

    fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.v.get() }
    }
}

fn set_socket_interface<T: AsRawSocket>(socket: &T, addr: Ipv4Addr) -> Result<()> {
    let raw = socket.as_raw_socket();

    unsafe {
        let addr_bytes = addr.octets();

        let code = windows::Win32::Networking::WinSock::setsockopt(
            windows::Win32::Networking::WinSock::SOCKET(raw as usize),
            windows::Win32::Networking::WinSock::IPPROTO_IP as i32,
            windows::Win32::Networking::WinSock::IP_UNICAST_IF as i32,
            windows::core::PCSTR(addr_bytes.as_ptr()),
            4,
        );

        if code == 0 {
            Ok(())
        } else {
            Err(anyhow!("Set socket interface failure"))
        }
    }
}

enum Rule {
    Match(IpRange<Ipv4Net>),
    NotMatch(IpRange<Ipv4Net>),
}

impl Rule {
    fn is_proxy(&self, target: &Ipv4Addr) -> bool {
        match &self {
            Rule::Match(range) => range.contains(target),
            Rule::NotMatch(range) => !range.contains(target),
        }
    }
}

fn get_timestamp() -> i64 {
    LOCAL_CLOCK.load(Ordering::Relaxed)
}

async fn clock_task() {
    loop {
        LOCAL_CLOCK.store(Utc::now().timestamp(), Ordering::Relaxed);
        sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Clone, Copy)]
enum TCPState {
    Handshaking(i64),
    Streaming,
}

async fn connection_timeout_scheduler() {
    loop {
        let now = get_timestamp();

        {
            let mut remove_list = Vec::new();
            let mut guard = get_tcp_nat_map().write();

            for (key, (_, state)) in guard.iter() {
                if let TCPState::Handshaking(time) = state {
                    // 180 secs
                    if now - time > 60 {
                        remove_list.push(*key);
                    }
                }
            }

            for key in remove_list {
                guard.remove(&key);
            }
        }
        sleep(Duration::from_secs(60)).await;
    }
}

struct Socket {
    direct: Option<Arc<UdpSocket>>,
    // proxy_addr -> socks_datagram
    proxy: Option<Arc<SocksDatagram<TcpStream>>>,
    handle_list: Vec<JoinHandle<()>>,
    send_channel: UnboundedSender<Result<(Box<[u8]>, SocketAddr)>>,
    recv_channel: UnboundedReceiver<Result<(Box<[u8]>, SocketAddr)>>,
}

impl Drop for Socket {
    fn drop(&mut self) {
        for x in &self.handle_list {
            x.abort()
        }
    }
}

impl Socket {
    fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            direct: None,
            proxy: None,
            handle_list: Vec::new(),
            send_channel: tx,
            recv_channel: rx,
        }
    }

    async fn send(&mut self, buff: &[u8], dst_addr: SocketAddr) -> Result<()> {
        if let Some(ref v) = self.direct {
            v.send_to(buff, dst_addr).await?;
            return Ok(());
        }

        // direct only support ipv4
        let udp_socket = UdpSocket::bind((get_direct_interface_addr(), 0)).await?;
        set_socket_interface(&udp_socket, get_direct_interface_addr())?;
        let udp_socket = Arc::new(udp_socket);

        self.direct = Some(udp_socket.clone());

        let tx = self.send_channel.clone();
        let inner_udp_socket = udp_socket.clone();
        let handle = tokio::spawn(async move {
            let mut buff = vec![0u8; 65536];

            loop {
                let res = async {
                    let (len, from) = inner_udp_socket.recv_from(&mut buff).await?;
                    Ok((buff[..len].into(), from))
                };
                if let Err(e) = tx.send(res.await) {
                    error!("{}", e);
                    return;
                }
            }
        });

        self.handle_list.push(handle);
        udp_socket.send_to(buff, dst_addr).await?;
        Ok(())
    }

    async fn send_to_proxy(&mut self, buff: &[u8], dst_addr: SocketAddr) -> Result<()> {
        if let Some(ref v) = self.proxy {
            v.send_to(buff, dst_addr).await?;
            return Ok(());
        }

        let tcp_socket = TcpSocket::new_v4()?;
        tcp_socket.bind(SocketAddr::new(IpAddr::V4(get_proxy_interface_addr()), 0))?;
        set_socket_interface(&tcp_socket, get_proxy_interface_addr())?;
        let stream = tcp_socket.connect(SocketAddr::V4(get_proxy())).await?;

        let udp_socket = UdpSocket::bind((get_proxy_interface_addr(), 0)).await?;
        set_socket_interface(&udp_socket, get_proxy_interface_addr())?;
        let socks_datagram = SocksDatagram::associate(
            stream,
            udp_socket,
            None,
            Some((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0)),
        )
        .await?;

        let socks_datagram = Arc::new(socks_datagram);
        self.proxy = Some(socks_datagram.clone());

        let tx = self.send_channel.clone();
        let inner_socks_datagram = socks_datagram.clone();
        let handle = tokio::spawn(async move {
            let mut buff = vec![0u8; 65536];

            loop {
                let res = async {
                    let (len, from) = inner_socks_datagram.recv_from(&mut buff).await?;
                    let from = match from {
                        AddrKind::Ip(v) => v,
                        AddrKind::Domain(domain, port) => tokio::net::lookup_host((domain, port))
                            .await?
                            .next()
                            .ok_or_else(|| anyhow!("Can not resolve peer address"))?,
                    };
                    Ok((buff[..len].into(), from))
                };

                if let Err(e) = tx.send(res.await) {
                    error!("{}", e);
                    return;
                }
            }
        });

        self.handle_list.push(handle);
        socks_datagram.send_to(buff, dst_addr).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<(Box<[u8]>, SocketAddr)> {
        self.recv_channel
            .recv()
            .await
            .ok_or_else(|| anyhow!("Unexpected eof"))?
    }
}

async fn udp_channel(
    tx: Sender<Box<[u8]>>,
    mut rx: UnboundedReceiver<(Box<[u8]>, SocketAddrV4)>,
    local_addr: SocketAddrV4,
) -> Result<()> {
    let socket = CellWarp::new(UnsafeCell::new(Socket::new()));
    let latest_update_time = AtomicI64::new(get_timestamp());

    let fut1 = async {
        loop {
            let (payload, from) = socket.get_mut().recv().await?;
            latest_update_time.store(get_timestamp(), Ordering::Relaxed);

            let udp_len = smoltcp::wire::UDP_HEADER_LEN + payload.len();
            let mut buff = vec![0u8; smoltcp::wire::IPV4_HEADER_LEN + udp_len];
            let mut udp = UdpPacket::new_unchecked(&mut buff[smoltcp::wire::IPV4_HEADER_LEN..]);

            udp.set_src_port(from.port());
            udp.set_dst_port(local_addr.port());
            udp.set_len(udp_len as u16);
            udp.payload_mut().copy_from_slice(&payload);
            let from_ip = match from {
                SocketAddr::V4(v) => *v.ip(),
                SocketAddr::V6(_) => return Err(anyhow!("Unexpected ipv6 address")),
            };
            udp.fill_checksum(
                &IpAddress::Ipv4(Ipv4Address(from_ip.octets())),
                &IpAddress::Ipv4(Ipv4Address(local_addr.ip().octets())),
            );

            let mut ipv4 = Ipv4Packet::new_unchecked(&mut buff);
            ipv4.set_version(0b0100);
            ipv4.set_header_len(0b0101);
            ipv4.set_total_len(smoltcp::wire::IPV4_HEADER_LEN as u16 + udp_len as u16);
            ipv4.set_protocol(IpProtocol::Udp);
            ipv4.set_src_addr(Ipv4Address(from_ip.octets()));
            ipv4.set_dst_addr(Ipv4Address(local_addr.ip().octets()));
            ipv4.fill_checksum();

            tx.send(buff.into_boxed_slice())?;
        }
    };

    let fut2 = async {
        while let Some((packet, dest)) = rx.recv().await {
            let socket = socket.get_mut();
            latest_update_time.store(get_timestamp(), Ordering::Relaxed);

            if get_rule().is_proxy(dest.ip()) {
                socket.send(&packet, SocketAddr::V4(dest)).await
            } else {
                socket.send_to_proxy(&packet, SocketAddr::V4(dest)).await
            }?;
        }
        Ok(())
    };

    let fut3 = async {
        loop {
            let now = get_timestamp();
            let latest_time = latest_update_time.load(Ordering::Relaxed);

            if now - latest_time > 100 {
                break;
            }
            sleep(Duration::from_secs(60)).await;
        }
    };

    tokio::select! {
        res = fut1 => res,
        res = fut2 => res,
        _ = fut3 => Ok(())
    }
}

async fn tcp_handler() -> Result<()> {
    let listener = TcpListener::bind((TUN_ADDR, INNER_TCP_SERVER_BIND_PORT)).await?;

    loop {
        let (mut src_stream, peer_addr) = listener.accept().await?;

        tokio::spawn(async move {
            let future = async move {
                if peer_addr.ip() != VIRTUAL_ADDR {
                    return Err(anyhow!("Illegal connection"));
                }

                let original_peer_addr = {
                    let mut guard = get_tcp_nat_map().write();

                    match guard.get_mut(&peer_addr.port()) {
                        Some((addr, state)) => {
                            *state = TCPState::Streaming;
                            *addr
                        }
                        None => return Ok(()),
                    }
                };

                if get_rule().is_proxy(original_peer_addr.ip()) {
                    let tcp_socket = TcpSocket::new_v4()?;
                    tcp_socket.bind(SocketAddr::new(IpAddr::V4(get_proxy_interface_addr()), 0))?;
                    set_socket_interface(&tcp_socket, get_proxy_interface_addr())?;

                    let mut dst_stream = tcp_socket.connect(SocketAddr::V4(get_proxy())).await?;
                    async_socks5::connect(&mut dst_stream, original_peer_addr, None).await?;
                    tokio::io::copy_bidirectional(&mut src_stream, &mut dst_stream).await?;
                } else {
                    let tcp_socket = TcpSocket::new_v4()?;
                    tcp_socket.bind(SocketAddr::new(IpAddr::V4(get_direct_interface_addr()), 0))?;
                    set_socket_interface(&tcp_socket, get_direct_interface_addr())?;

                    let mut dst_stream = tcp_socket
                        .connect(SocketAddr::V4(original_peer_addr))
                        .await?;
                    tokio::io::copy_bidirectional(&mut src_stream, &mut dst_stream).await?;
                }
                Ok(())
            };

            let res = future.await;

            if let Err(e) = res {
                error!("{:?}", e)
            }

            // todo Wait connection to be released
            sleep(Duration::from_millis(500)).await;

            // todo maybe delete another new record
            get_tcp_nat_map().write().remove(&peer_addr.port());
        });
    }
}

const ADAPTER_NAME: &str = "Akizuki";
const TUNNEL_TYPE: &str = "Proxy";
const ADAPTER_GUID: &str = "{1ADE8592-1070-820B-512D-092D97024C8D}";
//1MB
const ADAPTER_BUFF_SIZE: u32 = 0x100000;

struct Wintun {
    session: MaybeUninit<WintunStream<'static>>,
    _adapter: Box<WintunAdapter>,
}

impl Wintun {
    fn send_packet(&self, packet: &[u8]) -> Result<()> {
        const ERROR_BUFFER_OVERFLOW: i32 = 111;

        loop {
            match unsafe { self.session.assume_init_ref() }.write_packet(packet) {
                Err(e) if e.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW) => continue,
                res => {
                    res?;
                    return Ok(());
                }
            }
        }
    }

    fn recv_packet(&self, buff: &mut [u8]) -> Result<usize> {
        let res = unsafe { self.session.assume_init_ref() }.read_packet(buff)?;

        match res {
            ReadResult::Success(len) => Ok(len),
            ReadResult::NotEnoughSize(_) => Ok(0),
        }
    }
}

fn bridge(tun: Arc<Wintun>, mpsc_rx: crossbeam_channel::Receiver<Box<[u8]>>) -> Result<()> {
    loop {
        let packet = mpsc_rx.recv()?;

        if log::max_level() >= LevelFilter::Debug {
            let ipv4 = Ipv4Packet::new_unchecked(&*packet);

            if ipv4.protocol() != IpProtocol::Udp {
                continue;
            }
            let udp = UdpPacket::new_unchecked(ipv4.payload());
            let src = SocketAddrV4::new(Ipv4Addr::from(ipv4.src_addr().0), udp.src_port());
            let dst = SocketAddrV4::new(Ipv4Addr::from(ipv4.src_addr().0), udp.dst_port());
            debug!("UDP packet {} -> {}", src, dst);
        };

        tun.send_packet(&packet)?;
    }
}

fn tun_handler(tun: Arc<Wintun>, bridge_tx: Sender<Box<[u8]>>) -> Result<()> {
    let mut buff = vec![0u8; 65536];

    loop {
        match tun.recv_packet(&mut buff)? {
            0 => continue,
            len => {
                let mut ipv4 = Ipv4Packet::new_unchecked(&mut buff[..len]);
                let protocol = ipv4.protocol();
                let src_addr = Ipv4Addr::from(ipv4.src_addr().0);
                let dst_addr = Ipv4Addr::from(ipv4.dst_addr().0);

                match protocol {
                    IpProtocol::Tcp => {
                        let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());

                        let src = SocketAddrV4::new(src_addr, tcp.src_port());
                        let dst = SocketAddrV4::new(dst_addr, tcp.dst_port());

                        let (new_src, new_dst) = if src
                            == SocketAddrV4::new(TUN_ADDR, INNER_TCP_SERVER_BIND_PORT)
                            && *dst.ip() == VIRTUAL_ADDR
                        {
                            let new_src = match get_tcp_nat_map().read().get(&dst.port()) {
                                Some((addr, _)) => *addr,
                                None => continue,
                            };
                            let new_dst = SocketAddrV4::new(TUN_ADDR, dst.port());

                            debug!("TCP packet {} -> {}", new_src, new_dst);
                            (new_src, new_dst)
                        } else if *src.ip() == TUN_ADDR {
                            debug!("TCP packet {} -> {}", src, dst);

                            // todo need to check dst address
                            if !get_tcp_nat_map().read().contains_key(&src.port()) {
                                get_tcp_nat_map().write().insert(
                                    src.port(),
                                    (dst, TCPState::Handshaking(get_timestamp())),
                                );
                            }

                            let new_src = SocketAddrV4::new(VIRTUAL_ADDR, src.port());
                            let new_dst = SocketAddrV4::new(TUN_ADDR, INNER_TCP_SERVER_BIND_PORT);

                            (new_src, new_dst)
                        } else {
                            continue;
                        };

                        tcp.set_src_port(new_src.port());
                        tcp.set_dst_port(new_dst.port());
                        tcp.fill_checksum(
                            &IpAddress::Ipv4(Ipv4Address(new_src.ip().octets())),
                            &IpAddress::Ipv4(Ipv4Address(new_dst.ip().octets())),
                        );

                        ipv4.set_src_addr(Ipv4Address(new_src.ip().octets()));
                        ipv4.set_dst_addr(Ipv4Address(new_dst.ip().octets()));
                        ipv4.fill_checksum();

                        tun.send_packet(&buff[..len])?;
                    }
                    IpProtocol::Udp => {
                        if dst_addr.is_broadcast()
                            || dst_addr.is_multicast()
                            || dst_addr.is_loopback()
                            || dst_addr.is_link_local()
                        {
                            continue;
                        }

                        let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
                        let src = SocketAddrV4::new(src_addr, udp.src_port());
                        let dst = SocketAddrV4::new(dst_addr, udp.dst_port());

                        debug!("UDP packet {} -> {}", src, dst);

                        loop {
                            let guard = get_udp_nat_map().read();

                            match guard.get(&src.port()) {
                                None => {
                                    drop(guard);
                                    let (udp_channel_tx, udp_channel_rx) =
                                        mpsc::unbounded_channel();

                                    get_udp_nat_map().write().insert(src.port(), udp_channel_tx);

                                    let bridge_tx = bridge_tx.clone();

                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            udp_channel(bridge_tx, udp_channel_rx, src).await
                                        {
                                            error!("{}", e)
                                        }
                                        get_udp_nat_map().write().remove(&src.port());
                                    });
                                }
                                Some(v) => {
                                    v.send((Box::from(udp.payload_mut() as &[u8]), dst))?;
                                    break;
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
}

fn create_tun_adapter() -> Result<Wintun> {
    // drop old wintun adapter
    {
        let _ = WintunAdapter::open_adapter(ADAPTER_NAME);
    }

    //try to fix the stuck
    std::thread::sleep(Duration::from_millis(100));
    let adapter = WintunAdapter::create_adapter(ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)?;
    adapter.set_ipaddr(&TUN_ADDR.to_string(), 24)?;

    let mut wintun = Wintun {
        _adapter: Box::new(adapter),
        session: MaybeUninit::uninit(),
    };

    let session = wintun._adapter.start_session(ADAPTER_BUFF_SIZE)?;
    // wait update dynamic route
    std::thread::sleep(Duration::from_secs(5));

    let status = Command::new("route")
        .args([
            "add",
            "0.0.0.0",
            "mask",
            "0.0.0.0",
            &TUN_ADDR.to_string(),
            "metric",
            "1",
        ])
        .output()?
        .status;

    if !status.success() {
        return Err(anyhow!("Failed to add route"));
    }
    wintun
        .session
        .write(unsafe { std::mem::transmute(session) });
    Ok(wintun)
}

pub async fn find_interface_addr(dest_addr: SocketAddrV4) -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0)).await?;
    socket.connect(dest_addr).await?;
    let addr = socket.local_addr()?;
    Ok(match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => unreachable!(),
    })
}

async fn parse_rules(file_path: &str) -> Result<IpRange<Ipv4Net>> {
    let mut file = fs::File::open(file_path).await?;
    let mut buff = Vec::with_capacity(file.metadata().await?.len() as usize);
    file.read_to_end(&mut buff).await?;

    let mut lines = Cursor::new(buff).lines();
    let mut ip_range = IpRange::new();

    while let Some(res) = lines.next() {
        let line = res?;
        ip_range.add(Ipv4Net::from_str(&line)?);
    }

    ip_range.simplify();
    Ok(ip_range)
}

async fn process(args: Args) -> Result<()> {
    let socks5_server = tokio::net::lookup_host(args.socks5_server)
        .await?
        .next()
        .ok_or_else(|| anyhow!("Socks5 server host not found"))?;

    let socks5_server = match socks5_server {
        SocketAddr::V4(v) => v,
        SocketAddr::V6(_) => return Err(anyhow!("IPV6 socks5 server address is not supported")),
    };
    set_proxy(socks5_server);

    let rule = match args.rule {
        RuleCmd::Match { path } => {
            let range = parse_rules(&path).await?;
            Rule::Match(range)
        }
        RuleCmd::NotMatch { path } => {
            let range = parse_rules(&path).await?;
            Rule::NotMatch(range)
        }
    };
    set_rule(rule);

    LOCAL_CLOCK.store(Utc::now().timestamp(), Ordering::Relaxed);

    let direct_interface_addr =
        find_interface_addr(SocketAddrV4::from_str("8.8.8.8:53").unwrap()).await?;
    set_direct_interface_addr(direct_interface_addr);

    set_proxy_interface_addr(find_interface_addr(socks5_server).await?);

    set_tcp_nat_map(RwLock::new(AHashMap::new()));
    set_udp_nat_map(RwLock::new(AHashMap::new()));

    info!("Create tun");

    let tun = Arc::new(tokio::task::spawn_blocking(|| create_tun_adapter()).await??);

    let (bridge_tx, bridge_rx) = crossbeam_channel::unbounded::<Box<[u8]>>();
    let inner_tun = tun.clone();
    let handle1 =
        async { tokio::task::spawn_blocking(move || tun_handler(inner_tun, bridge_tx)).await? };
    let handle2 = async { tokio::task::spawn_blocking(|| bridge(tun, bridge_rx)).await? };
    let handle3 = async { tokio::spawn(tcp_handler()).await? };
    let handle4 = async {
        tokio::spawn(clock_task()).await?;
        Ok(())
    };
    let handle5 = async {
        tokio::spawn(connection_timeout_scheduler()).await?;
        Ok(())
    };

    info!("Start");

    tokio::try_join!(handle1, handle2, handle3, handle4, handle5)?;
    Ok(())
}

fn logger_init() -> Result<()> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[Console] {d(%Y-%m-%d %H:%M:%S)} - {l} - {m}{n}",
        )))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(
            Root::builder()
                .appender("stdout")
                .build(LevelFilter::from_str(
                    &std::env::var("AKIZUKI_LOG").unwrap_or_else(|_| String::from("INFO")),
                )?),
        )?;

    log4rs::init_config(config)?;
    Ok(())
}

#[derive(Subcommand)]
enum RuleCmd {
    /// Match ip list proxy
    Match {
        /// Rule file path
        path: String,
    },
    /// Not match ip list proxy
    NotMatch {
        /// Rule file path
        path: String,
    },
}

#[derive(Parser)]
#[clap(version)]
struct Args {
    /// Socks5 server address
    #[clap(short, long)]
    socks5_server: String,

    #[clap(subcommand)]
    rule: RuleCmd,
}

fn main() {
    let args: Args = Args::parse();
    logger_init().unwrap();

    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        if let Err(e) = process(args).await {
            error!("Process error: {}", e)
        }
    });
}
