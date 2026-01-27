use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel as channel;
use serde::Deserialize;

use sn_proto::crypto::{decode_psk_base64, derive_node_key, open, random_nonce12, seal};
use sn_proto::framing::{encode_frames_to_buffer, read_frame, DEFAULT_MAX_FRAME_LEN};
use sn_proto::wire::{
    decode_control, decode_wire, encode_control, encode_wire, Control, Ipv4AddrBytes, MsgType,
    NodeId, WirePacket, WIRE_VERSION,
};

#[derive(Debug, Deserialize)]
struct RelayConfig {
    listen: String,
    #[serde(default)]
    transport: Option<String>,
    #[serde(alias = "psk_base64")]
    relay_psk_base64: String,
    peers: HashMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
    Both,
}

impl Transport {
    fn parse(v: Option<&str>) -> anyhow::Result<Self> {
        match v.unwrap_or("udp").trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "both" => Ok(Self::Both),
            other => anyhow::bail!("unsupported transport: {other} (expected udp|tcp)"),
        }
    }
}

struct PeerInfo {
    node: NodeId,
    virt_ip: std::net::Ipv4Addr,
    key: [u8; 32],
}

fn main() -> Result<()> {
    let config = parse_args(std::env::args())?;
    run(&config)
}

fn is_debug() -> bool {
    matches!(
        std::env::var("RUST_LOG").ok().as_deref(),
        Some("debug") | Some("trace")
    )
}

fn parse_args<I>(args: I) -> Result<String>
where
    I: IntoIterator<Item = String>,
{
    let mut it = args.into_iter();
    let bin = it.next().unwrap_or_else(|| "sn-relay".to_string());

    let mut rest: Vec<String> = it.collect();
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        print_usage(&bin);
        std::process::exit(0);
    }
    if rest.iter().any(|a| a == "-V" || a == "--version") {
        println!("sn-relay {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    if rest.is_empty() {
        print_usage(&bin);
        anyhow::bail!("missing command");
    }

    let cmd = rest.remove(0);
    if cmd != "run" {
        print_usage(&bin);
        anyhow::bail!("unsupported command: {cmd}");
    }

    let mut config: Option<String> = None;
    let mut i = 0usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "--config" => {
                let Some(v) = rest.get(i + 1).cloned() else {
                    anyhow::bail!("--config requires a value");
                };
                config = Some(v);
                i += 2;
            }
            other => {
                anyhow::bail!("unknown arg: {other}");
            }
        }
    }

    config.context("missing --config")
}

fn print_usage(bin: &str) {
    eprintln!("Usage:\n  {bin} run --config <path>\n\nEnvironment:\n  RUST_LOG=info|debug");
}

fn run(config_path: &str) -> Result<()> {
    let cfg_text = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading config {config_path}"))?;
    let cfg: RelayConfig = toml::from_str(&cfg_text).context("parsing relay config")?;
    let transport = Transport::parse(cfg.transport.as_deref())?;

    let relay_psk = decode_psk_base64(&cfg.relay_psk_base64).context("invalid relay_psk_base64")?;

    let mut peers_by_id: HashMap<NodeId, PeerInfo> = HashMap::new();
    let mut node_by_ip: HashMap<std::net::Ipv4Addr, NodeId> = HashMap::new();
    for (node_str, ip_str) in cfg.peers.iter() {
        let node_uuid = uuid::Uuid::parse_str(node_str)
            .with_context(|| format!("invalid node_id UUID: {node_str}"))?;
        let node = NodeId(node_uuid);
        let ip: std::net::Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("invalid IPv4 for {node_str}: {ip_str}"))?;
        let key = derive_node_key(&relay_psk, node);

        node_by_ip.insert(ip, node);

        peers_by_id.insert(
            node,
            PeerInfo {
                node,
                virt_ip: ip,
                key,
            },
        );
    }

    match transport {
        Transport::Udp => run_udp(&cfg.listen, &peers_by_id, &node_by_ip),
        Transport::Tcp => run_tcp(&cfg.listen, &peers_by_id, &node_by_ip),
        Transport::Both => run_both(&cfg.listen, &peers_by_id, &node_by_ip),
    }
}

fn run_udp(
    listen: &str,
    peers_by_id: &HashMap<NodeId, PeerInfo>,
    node_by_ip: &HashMap<std::net::Ipv4Addr, NodeId>,
) -> Result<()> {
    let sock = std::net::UdpSocket::bind(listen)
        .with_context(|| format!("binding UDP socket on {listen}"))?;
    eprintln!(
        "relay started: listen={listen} peers={} transport=udp",
        peers_by_id.len()
    );

    let mut endpoints: HashMap<NodeId, Endpoint> = HashMap::new();
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("warn: recv_from failed: {e}");
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        };

        if let Err(e) = handle_packet_udp(
            &sock,
            &buf[..n],
            from,
            peers_by_id,
            node_by_ip,
            &mut endpoints,
            None,
        ) {
            if is_debug() {
                eprintln!("debug: packet rejected from={from}: {e:#}");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    Udp(SocketAddr),
    Tcp(u64),
}

enum TcpEvent {
    Frame { conn_id: u64, bytes: Vec<u8> },
    Disconnected { conn_id: u64 },
}

enum RelayEvent {
    UdpFrame {
        from: SocketAddr,
        bytes: Vec<u8>,
    },
    TcpAccepted {
        conn_id: u64,
        tx: channel::Sender<Vec<u8>>,
    },
    TcpFrame {
        conn_id: u64,
        bytes: Vec<u8>,
    },
    TcpDisconnected {
        conn_id: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxKind {
    Control,
    Data,
}

fn run_tcp(
    listen: &str,
    peers_by_id: &HashMap<NodeId, PeerInfo>,
    node_by_ip: &HashMap<std::net::Ipv4Addr, NodeId>,
) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let listener = std::net::TcpListener::bind(listen)
        .with_context(|| format!("binding TCP listener on {listen}"))?;

    eprintln!(
        "relay started: listen={listen} peers={} transport=tcp",
        peers_by_id.len()
    );

    let (evt_tx, evt_rx) = channel::unbounded::<TcpEvent>();
    let (accept_tx, accept_rx) = channel::unbounded::<(u64, channel::Sender<Vec<u8>>)>();

    let next_id = AtomicU64::new(1);
    std::thread::spawn(move || {
        for res in listener.incoming() {
            match res {
                Ok(stream) => {
                    let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.set_nodelay(true);

                    let peer_addr = stream.peer_addr().ok();
                    eprintln!("tcp accepted: conn_id={conn_id} peer={peer_addr:?}");

                    let (tx_out, rx_out) = channel::bounded::<Vec<u8>>(2048);
                    if accept_tx.send((conn_id, tx_out.clone())).is_err() {
                        break;
                    }

                    let mut reader = match stream.try_clone() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let mut writer = stream;

                    let evt_tx_r = evt_tx.clone();
                    std::thread::spawn(move || {
                        loop {
                            match read_frame(&mut reader, DEFAULT_MAX_FRAME_LEN) {
                                Ok(frame) => {
                                    if evt_tx_r
                                        .send(TcpEvent::Frame {
                                            conn_id,
                                            bytes: frame,
                                        })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                                Err(e) => {
                                    eprintln!("warn: tcp read failed conn_id={conn_id}: {e}");
                                    break;
                                }
                            }
                        }
                        let _ = evt_tx_r.send(TcpEvent::Disconnected { conn_id });
                    });

                    std::thread::spawn(move || {
                        use std::io::Write;
                        const MAX_BATCH_FRAMES: usize = 64;
                        const MAX_BATCH_BYTES: usize = 512 * 1024;

                        while let Ok(first) = rx_out.recv() {
                            let mut frames: Vec<Vec<u8>> = Vec::with_capacity(8);
                            let mut bytes_total = first.len();
                            frames.push(first);

                            while frames.len() < MAX_BATCH_FRAMES && bytes_total < MAX_BATCH_BYTES {
                                match rx_out.try_recv() {
                                    Ok(next) => {
                                        bytes_total = bytes_total.saturating_add(next.len());
                                        frames.push(next);
                                    }
                                    Err(_) => break,
                                }
                            }

                            let out = match encode_frames_to_buffer(&frames) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!(
                                        "warn: tcp batch encode failed conn_id={conn_id}: {e}"
                                    );
                                    break;
                                }
                            };

                            if let Err(e) = writer.write_all(&out) {
                                eprintln!("warn: tcp write failed conn_id={conn_id}: {e}");
                                break;
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("warn: tcp accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    });

    let mut endpoints: HashMap<NodeId, Endpoint> = HashMap::new();
    let mut writers: HashMap<u64, channel::Sender<Vec<u8>>> = HashMap::new();

    loop {
        channel::select! {
            recv(accept_rx) -> acc => {
                let Ok((conn_id, tx)) = acc else { continue; };
                writers.insert(conn_id, tx);
            }

            recv(evt_rx) -> ev => {
                let Ok(ev) = ev else { continue; };
                match ev {
                    TcpEvent::Disconnected { conn_id } => {
                        writers.remove(&conn_id);
                        endpoints.retain(|_, ep| !matches!(ep, Endpoint::Tcp(id) if *id == conn_id));
                        if is_debug() {
                            eprintln!("debug: tcp disconnected conn_id={conn_id}");
                        }
                    }

                    TcpEvent::Frame { conn_id, bytes } => {
                        if let Err(e) = handle_packet_tcp(
                            conn_id,
                            &bytes,
                            peers_by_id,
                            node_by_ip,
                            &mut endpoints,
                            &writers,
                            None,
                        ) {
                            if is_debug() {
                                eprintln!("debug: packet rejected conn_id={conn_id}: {e:#}");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn run_both(
    listen: &str,
    peers_by_id: &HashMap<NodeId, PeerInfo>,
    node_by_ip: &HashMap<std::net::Ipv4Addr, NodeId>,
) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let udp_sock = std::net::UdpSocket::bind(listen)
        .with_context(|| format!("binding UDP socket on {listen}"))?;
    let tcp_listener = std::net::TcpListener::bind(listen)
        .with_context(|| format!("binding TCP listener on {listen}"))?;

    eprintln!(
        "relay started: listen={listen} peers={} transport=both",
        peers_by_id.len()
    );

    let (evt_tx, evt_rx) = channel::unbounded::<RelayEvent>();

    // UDP receiver thread.
    {
        let sock = udp_sock.try_clone().context("cloning UDP socket")?;
        let evt_tx = evt_tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if n == 0 {
                            continue;
                        }
                        if evt_tx
                            .send(RelayEvent::UdpFrame {
                                from,
                                bytes: buf[..n].to_vec(),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("warn: udp recv_from failed: {e}");
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        });
    }

    // TCP acceptor thread (spawns per-conn reader/writer threads).
    {
        let evt_tx = evt_tx.clone();
        let next_id = AtomicU64::new(1);
        std::thread::spawn(move || {
            for res in tcp_listener.incoming() {
                match res {
                    Ok(stream) => {
                        let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
                        let _ = stream.set_nodelay(true);

                        let peer_addr = stream.peer_addr().ok();
                        eprintln!("tcp accepted: conn_id={conn_id} peer={peer_addr:?}");

                        let (tx_out, rx_out) = channel::bounded::<Vec<u8>>(2048);
                        if evt_tx
                            .send(RelayEvent::TcpAccepted {
                                conn_id,
                                tx: tx_out.clone(),
                            })
                            .is_err()
                        {
                            break;
                        }

                        let mut reader = match stream.try_clone() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let mut writer = stream;

                        let evt_tx_r = evt_tx.clone();
                        std::thread::spawn(move || {
                            loop {
                                match read_frame(&mut reader, DEFAULT_MAX_FRAME_LEN) {
                                    Ok(frame) => {
                                        if evt_tx_r
                                            .send(RelayEvent::TcpFrame {
                                                conn_id,
                                                bytes: frame,
                                            })
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                        break
                                    }
                                    Err(e) => {
                                        eprintln!("warn: tcp read failed conn_id={conn_id}: {e}");
                                        break;
                                    }
                                }
                            }
                            let _ = evt_tx_r.send(RelayEvent::TcpDisconnected { conn_id });
                        });

                        std::thread::spawn(move || {
                            use std::io::Write;
                            const MAX_BATCH_FRAMES: usize = 64;
                            const MAX_BATCH_BYTES: usize = 512 * 1024;

                            while let Ok(first) = rx_out.recv() {
                                let mut frames: Vec<Vec<u8>> = Vec::with_capacity(8);
                                let mut bytes_total = first.len();
                                frames.push(first);

                                while frames.len() < MAX_BATCH_FRAMES
                                    && bytes_total < MAX_BATCH_BYTES
                                {
                                    match rx_out.try_recv() {
                                        Ok(next) => {
                                            bytes_total = bytes_total.saturating_add(next.len());
                                            frames.push(next);
                                        }
                                        Err(_) => break,
                                    }
                                }

                                let out = match encode_frames_to_buffer(&frames) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        eprintln!(
                                            "warn: tcp batch encode failed conn_id={conn_id}: {e}"
                                        );
                                        break;
                                    }
                                };

                                if let Err(e) = writer.write_all(&out) {
                                    eprintln!("warn: tcp write failed conn_id={conn_id}: {e}");
                                    break;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("warn: tcp accept failed: {e}");
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        });
    }

    let mut endpoints: HashMap<NodeId, Endpoint> = HashMap::new();
    let mut writers: HashMap<u64, channel::Sender<Vec<u8>>> = HashMap::new();

    loop {
        let ev = match evt_rx.recv() {
            Ok(v) => v,
            Err(_) => continue,
        };

        match ev {
            RelayEvent::UdpFrame { from, bytes } => {
                if let Err(e) = handle_packet_udp(
                    &udp_sock,
                    &bytes,
                    from,
                    peers_by_id,
                    node_by_ip,
                    &mut endpoints,
                    Some(&writers),
                ) {
                    if is_debug() {
                        eprintln!("debug: packet rejected from={from}: {e:#}");
                    }
                }
            }

            RelayEvent::TcpAccepted { conn_id, tx } => {
                writers.insert(conn_id, tx);
            }

            RelayEvent::TcpDisconnected { conn_id } => {
                writers.remove(&conn_id);
                endpoints.retain(|_, ep| !matches!(ep, Endpoint::Tcp(id) if *id == conn_id));
                if is_debug() {
                    eprintln!("debug: tcp disconnected conn_id={conn_id}");
                }
            }

            RelayEvent::TcpFrame { conn_id, bytes } => {
                if let Err(e) = handle_packet_tcp(
                    conn_id,
                    &bytes,
                    peers_by_id,
                    node_by_ip,
                    &mut endpoints,
                    &writers,
                    Some(&udp_sock),
                ) {
                    if is_debug() {
                        eprintln!("debug: packet rejected conn_id={conn_id}: {e:#}");
                    }
                }
            }
        }
    }
}

fn handle_packet_udp(
    sock: &std::net::UdpSocket,
    bytes: &[u8],
    from: SocketAddr,
    peers_by_id: &HashMap<NodeId, PeerInfo>,
    node_by_ip: &HashMap<std::net::Ipv4Addr, NodeId>,
    endpoints: &mut HashMap<NodeId, Endpoint>,
    tcp_writers: Option<&HashMap<u64, channel::Sender<Vec<u8>>>>,
) -> Result<()> {
    let pkt = decode_wire(bytes).context("decode wire")?;

    if pkt.v != WIRE_VERSION {
        anyhow::bail!("unsupported wire version");
    }

    match pkt.t {
        MsgType::Control => {
            if !pkt.dst.0.is_nil() {
                anyhow::bail!("control packets must have nil dst");
            }

            let src_peer = peers_by_id.get(&pkt.src).context("unknown src node")?;
            // Only update endpoints on authenticated control-plane packets.
            endpoints.insert(pkt.src, Endpoint::Udp(from));

            // AAD binds routing header.
            let aad = aad_bytes(pkt.v, pkt.t, pkt.src, pkt.dst);
            let pt = open(&src_peer.key, &pkt.nonce12, &pkt.ciphertext, &aad)
                .context("decrypt control")?;
            let ctrl = decode_control(&pt).context("decode control")?;

            match ctrl {
                Control::Register { virtual_ip } => {
                    let ip = virtual_ip.to_std();
                    if ip != src_peer.virt_ip {
                        anyhow::bail!("register ip mismatch");
                    }
                    eprintln!(
                        "registered: node={} ip={} from={}",
                        src_peer.node.0, ip, from
                    );
                    Ok(())
                }
                Control::Keepalive => Ok(()),
                Control::Resolve { virtual_ip } => {
                    let ip = virtual_ip.to_std();
                    let resp = match node_by_ip.get(&ip).copied() {
                        Some(node_id) => Control::ResolveOk {
                            virtual_ip: Ipv4AddrBytes::from_std(ip),
                            node_id,
                        },
                        None => Control::ResolveErr {
                            virtual_ip: Ipv4AddrBytes::from_std(ip),
                        },
                    };

                    // Reply to requester (dst=client node). Encrypt with the client's node key.
                    let out_bytes = encode_control(&resp).context("encode control")?;
                    let out_nonce = random_nonce12();
                    let relay_id = NodeId(uuid::Uuid::nil());
                    let out_aad = aad_bytes(WIRE_VERSION, MsgType::Control, relay_id, pkt.src);
                    let out_ciphertext = seal(&src_peer.key, &out_nonce, &out_bytes, &out_aad)
                        .context("encrypt control")?;

                    let out_pkt = WirePacket {
                        v: WIRE_VERSION,
                        t: MsgType::Control,
                        src: relay_id,
                        dst: pkt.src,
                        nonce12: out_nonce,
                        ciphertext: out_ciphertext,
                    };
                    let out_wire = encode_wire(&out_pkt).context("encode wire")?;
                    sock.send_to(&out_wire, from).context("udp send_to")?;
                    Ok(())
                }
                Control::ResolveOk { .. } | Control::ResolveErr { .. } => {
                    anyhow::bail!("unexpected resolve response from client")
                }
            }
        }

        MsgType::Data => {
            if pkt.dst.0.is_nil() {
                anyhow::bail!("data requires non-nil dst");
            }
            if !peers_by_id.contains_key(&pkt.src) {
                anyhow::bail!("unknown src node");
            }
            if !peers_by_id.contains_key(&pkt.dst) {
                anyhow::bail!("unknown dst node");
            }

            let expected_from = endpoints
                .get(&pkt.src)
                .copied()
                .context("no endpoint for src (has it registered yet?)")?;
            if expected_from != Endpoint::Udp(from) {
                anyhow::bail!("src endpoint mismatch (spoof?)");
            }

            let dst_ep = endpoints
                .get(&pkt.dst)
                .copied()
                .context("no endpoint for dst (has it registered yet?)")?;

            // Forward opaquely; relay never decrypts MsgType::Data.
            match dst_ep {
                Endpoint::Udp(dst_addr) => {
                    sock.send_to(bytes, dst_addr).context("udp send_to")?;
                }
                Endpoint::Tcp(dst_conn) => {
                    let writers = tcp_writers.context("tcp not enabled")?;
                    send_tcp(writers, dst_conn, TxKind::Data, bytes.to_vec())?;
                }
            }
            Ok(())
        }
    }
}

fn handle_packet_tcp(
    conn_id: u64,
    bytes: &[u8],
    peers_by_id: &HashMap<NodeId, PeerInfo>,
    node_by_ip: &HashMap<std::net::Ipv4Addr, NodeId>,
    endpoints: &mut HashMap<NodeId, Endpoint>,
    writers: &HashMap<u64, channel::Sender<Vec<u8>>>,
    udp_sock: Option<&std::net::UdpSocket>,
) -> Result<()> {
    let pkt = decode_wire(bytes).context("decode wire")?;

    if pkt.v != WIRE_VERSION {
        anyhow::bail!("unsupported wire version");
    }

    match pkt.t {
        MsgType::Control => {
            if !pkt.dst.0.is_nil() {
                anyhow::bail!("control packets must have nil dst");
            }

            let src_peer = peers_by_id.get(&pkt.src).context("unknown src node")?;

            // AAD binds routing header.
            let aad = aad_bytes(pkt.v, pkt.t, pkt.src, pkt.dst);
            let pt = open(&src_peer.key, &pkt.nonce12, &pkt.ciphertext, &aad)
                .context("decrypt control")?;
            let ctrl = decode_control(&pt).context("decode control")?;

            // Only bind endpoints on authenticated control-plane packets.
            endpoints.insert(pkt.src, Endpoint::Tcp(conn_id));

            match ctrl {
                Control::Register { virtual_ip } => {
                    let ip = virtual_ip.to_std();
                    if ip != src_peer.virt_ip {
                        anyhow::bail!("register ip mismatch");
                    }
                    eprintln!(
                        "registered: node={} ip={} via=tcp conn_id={conn_id}",
                        src_peer.node.0, ip
                    );
                    Ok(())
                }
                Control::Keepalive => Ok(()),
                Control::Resolve { virtual_ip } => {
                    let ip = virtual_ip.to_std();
                    let resp = match node_by_ip.get(&ip).copied() {
                        Some(node_id) => Control::ResolveOk {
                            virtual_ip: Ipv4AddrBytes::from_std(ip),
                            node_id,
                        },
                        None => Control::ResolveErr {
                            virtual_ip: Ipv4AddrBytes::from_std(ip),
                        },
                    };

                    let out_bytes = encode_control(&resp).context("encode control")?;
                    let out_nonce = random_nonce12();
                    let relay_id = NodeId(uuid::Uuid::nil());
                    let out_aad = aad_bytes(WIRE_VERSION, MsgType::Control, relay_id, pkt.src);
                    let out_ciphertext = seal(&src_peer.key, &out_nonce, &out_bytes, &out_aad)
                        .context("encrypt control")?;

                    let out_pkt = WirePacket {
                        v: WIRE_VERSION,
                        t: MsgType::Control,
                        src: relay_id,
                        dst: pkt.src,
                        nonce12: out_nonce,
                        ciphertext: out_ciphertext,
                    };
                    let out_wire = encode_wire(&out_pkt).context("encode wire")?;
                    send_tcp(writers, conn_id, TxKind::Control, out_wire)?;
                    Ok(())
                }
                Control::ResolveOk { .. } | Control::ResolveErr { .. } => {
                    anyhow::bail!("unexpected resolve response from client")
                }
            }
        }

        MsgType::Data => {
            if pkt.dst.0.is_nil() {
                anyhow::bail!("data requires non-nil dst");
            }
            if !peers_by_id.contains_key(&pkt.src) {
                anyhow::bail!("unknown src node");
            }
            if !peers_by_id.contains_key(&pkt.dst) {
                anyhow::bail!("unknown dst node");
            }

            let expected = endpoints
                .get(&pkt.src)
                .copied()
                .context("no endpoint for src (has it registered yet?)")?;
            if expected != Endpoint::Tcp(conn_id) {
                anyhow::bail!("src endpoint mismatch (spoof?)");
            }

            let dst_ep = endpoints
                .get(&pkt.dst)
                .copied()
                .context("no endpoint for dst (has it registered yet?)")?;

            // Avoid building up latency: if the destination is congested, drop data.
            match dst_ep {
                Endpoint::Tcp(dst_conn) => {
                    send_tcp(writers, dst_conn, TxKind::Data, bytes.to_vec())?;
                }
                Endpoint::Udp(dst_addr) => {
                    let sock = udp_sock.context("udp not enabled")?;
                    sock.send_to(bytes, dst_addr).context("udp send_to")?;
                }
            }
            Ok(())
        }
    }
}

fn send_tcp(
    writers: &HashMap<u64, channel::Sender<Vec<u8>>>,
    conn_id: u64,
    kind: TxKind,
    bytes: Vec<u8>,
) -> Result<()> {
    let tx = writers.get(&conn_id).context("no writer for conn")?;

    match kind {
        TxKind::Control => {
            // Keep control responsive but don't allow indefinite blocking.
            tx.send_timeout(bytes, Duration::from_millis(100))
                .map_err(|_| anyhow::anyhow!("tcp control send timeout/closed"))?;
            Ok(())
        }
        TxKind::Data => match tx.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(channel::TrySendError::Full(_)) => Ok(()),
            Err(channel::TrySendError::Disconnected(_)) => {
                Err(anyhow::anyhow!("tcp writer closed"))
            }
        },
    }
}

fn aad_bytes(v: u8, t: MsgType, src: NodeId, dst: NodeId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 1 + 16 + 16);
    aad.push(v);
    aad.push(t as u8);
    aad.extend_from_slice(src.as_bytes());
    aad.extend_from_slice(dst.as_bytes());
    aad
}
