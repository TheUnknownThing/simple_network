use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;

use sn_proto::crypto::{decode_psk_base64, derive_node_key, open, random_nonce12, seal};
use sn_proto::wire::{
    decode_inner, decode_wire, encode_inner, encode_wire, Inner, Ipv4AddrBytes, MsgType, NodeId,
    WirePacket, WIRE_VERSION,
};

#[derive(Debug, Deserialize)]
struct ClientConfig {
    server: String,
    node_id: String,
    virtual_ip: String,
    #[serde(default)]
    netmask: Option<String>,
    #[serde(default)]
    mtu: Option<u16>,
    tun: String,
    psk_base64: String,
    peers: HashMap<String, String>, // ip -> node_id
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
    let bin = it.next().unwrap_or_else(|| "sn-client".to_string());

    let mut rest: Vec<String> = it.collect();
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        print_usage(&bin);
        std::process::exit(0);
    }
    if rest.iter().any(|a| a == "-V" || a == "--version") {
        println!("sn-client {}", env!("CARGO_PKG_VERSION"));
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
    let cfg: ClientConfig = toml::from_str(&cfg_text).context("parsing client config")?;

    let server_addr: SocketAddr = cfg.server.parse().context("parsing server addr")?;
    let node_uuid = uuid::Uuid::parse_str(&cfg.node_id).context("parsing node_id")?;
    let node_id = NodeId(node_uuid);

    let virt_ip: std::net::Ipv4Addr = cfg.virtual_ip.parse().context("parsing virtual_ip")?;

    let mut peer_by_ip: HashMap<std::net::Ipv4Addr, NodeId> = HashMap::new();
    for (ip_str, node_str) in cfg.peers.iter() {
        let ip: std::net::Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("bad peer ip {ip_str}"))?;
        let node_uuid = uuid::Uuid::parse_str(node_str)
            .with_context(|| format!("bad peer node_id {node_str}"))?;
        peer_by_ip.insert(ip, NodeId(node_uuid));
    }

    let psk = decode_psk_base64(&cfg.psk_base64).context("invalid psk_base64")?;
    let node_key = derive_node_key(&psk, node_id);

    let netmask: std::net::Ipv4Addr = cfg
        .netmask
        .as_deref()
        .unwrap_or("255.255.255.0")
        .parse()
        .context("parsing netmask")?;

    // UDP-based overlays are sensitive to underlay MTU (PPPoE, tunnels, etc.).
    // A conservative default avoids fragmentation/blackholing for larger TCP transfers.
    let mtu: i32 = cfg.mtu.unwrap_or(1280) as i32;

    // TUN setup (Linux).
    let mut tun = tun::Configuration::default();
    tun.name(&cfg.tun)
        .address(virt_ip)
        .netmask(netmask)
        .mtu(mtu)
        .up();

    let dev = tun::create(&tun).context("creating TUN device")?;
    let (mut tun_reader, mut tun_writer) = dev.split();

    let sock = std::net::UdpSocket::bind("0.0.0.0:0").context("binding UDP")?;
    sock.connect(server_addr).context("connecting UDP")?;
    sock.set_nonblocking(true).context("set UDP nonblocking")?;

    eprintln!(
        "client started: node={} ip={} server={}",
        node_id.0, virt_ip, server_addr
    );

    // Register.
    send_inner(
        &sock,
        node_id,
        NodeId(uuid::Uuid::nil()),
        &node_key,
        Inner::Register {
            virtual_ip: Ipv4AddrBytes::from_std(virt_ip),
        },
    )?;

    // Use blocking threads for TUN I/O (small + works well on routers).
    let (tun_tx, tun_rx) = mpsc::sync_channel::<Vec<u8>>(256);
    let (net_tx, net_rx) = mpsc::sync_channel::<Vec<u8>>(256);

    std::thread::spawn(move || {
        let mut buf = vec![0u8; 2000];
        loop {
            match tun_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if tun_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    });

    std::thread::spawn(move || {
        while let Ok(pkt) = net_rx.recv() {
            let _ = tun_writer.write_all(&pkt);
        }
    });

    let mut udp_buf = vec![0u8; 2048];
    let mut next_keepalive = Instant::now() + Duration::from_secs(20);

    loop {
        // Keepalive.
        if Instant::now() >= next_keepalive {
            let _ = send_inner(
                &sock,
                node_id,
                NodeId(uuid::Uuid::nil()),
                &node_key,
                Inner::Keepalive,
            );
            next_keepalive = Instant::now() + Duration::from_secs(20);
        }

        // Drain TUN packets.
        while let Ok(pkt) = tun_rx.try_recv() {
            // Minimal IPv4 parsing: destination at bytes 16..20.
            if pkt.len() < 20 {
                continue;
            }
            let dst_ip = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            let dst_node = match peer_by_ip.get(&dst_ip) {
                Some(n) => *n,
                None => {
                    if is_debug() {
                        eprintln!("debug: no peer mapping for dst={dst_ip}");
                    }
                    continue;
                }
            };
            send_inner(
                &sock,
                node_id,
                dst_node,
                &node_key,
                Inner::Data { payload: pkt },
            )?;
        }

        // UDP receive.
        match sock.recv(&mut udp_buf) {
            Ok(n) => {
                if let Err(e) = handle_inbound(&udp_buf[..n], node_id, &node_key, &net_tx) {
                    if is_debug() {
                        eprintln!("debug: drop inbound: {e:#}");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                eprintln!("warn: udp recv failed: {e}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn handle_inbound(
    bytes: &[u8],
    node_id: NodeId,
    node_key: &[u8; 32],
    net_tx: &mpsc::SyncSender<Vec<u8>>,
) -> Result<()> {
    let pkt = decode_wire(bytes).context("decode wire")?;
    if pkt.v != WIRE_VERSION || pkt.t != MsgType::Encrypted {
        anyhow::bail!("unsupported wire");
    }
    if pkt.dst != node_id {
        anyhow::bail!("not for us");
    }

    let aad = aad_bytes(pkt.v, pkt.t, pkt.src, pkt.dst);
    let inner_bytes = open(node_key, &pkt.nonce12, &pkt.ciphertext, &aad).context("decrypt")?;
    let inner = decode_inner(&inner_bytes).context("decode inner")?;

    match inner {
        Inner::Data { payload } => {
            net_tx.send(payload).ok();
            Ok(())
        }
        Inner::Keepalive | Inner::Register { .. } => Ok(()),
    }
}

fn send_inner(
    sock: &std::net::UdpSocket,
    src: NodeId,
    dst: NodeId,
    node_key: &[u8; 32],
    inner: Inner,
) -> Result<()> {
    let inner_bytes = encode_inner(&inner).context("encode inner")?;
    let nonce = random_nonce12();
    let aad = aad_bytes(WIRE_VERSION, MsgType::Encrypted, src, dst);
    let ciphertext = seal(node_key, &nonce, &inner_bytes, &aad).context("encrypt")?;

    let pkt = WirePacket {
        v: WIRE_VERSION,
        t: MsgType::Encrypted,
        src,
        dst,
        nonce12: nonce,
        ciphertext,
    };

    let bytes = encode_wire(&pkt).context("encode wire")?;
    sock.send(&bytes).context("udp send")?;
    Ok(())
}

fn aad_bytes(v: u8, t: MsgType, src: NodeId, dst: NodeId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 1 + 16 + 16);
    aad.push(v);
    aad.push(t as u8);
    aad.extend_from_slice(src.as_bytes());
    aad.extend_from_slice(dst.as_bytes());
    aad
}
