use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel as channel;
use serde::Deserialize;

use sn_proto::crypto::{
    decode_psk_base64, derive_e2e_key, derive_node_key, open, random_nonce12, seal,
};
use sn_proto::framing::{encode_frames_to_buffer, read_frame, DEFAULT_MAX_FRAME_LEN};
use sn_proto::wire::{
    decode_control, decode_wire, encode_control, encode_wire, Control, Ipv4AddrBytes, MsgType,
    NodeId, WirePacket, WIRE_VERSION,
};

#[cfg(target_os = "macos")]
fn macos_pi_header_for_ipv4() -> [u8; 4] {
    // tun crate encodes PI as: flags (u16 native endian) + protocol (u16 network endian).
    // flags is always 0, protocol for IPv4 on macOS is PF_INET (2).
    [0, 0, 0, 2]
}

#[cfg(target_os = "macos")]
fn ipv4_to_u32(ip: std::net::Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

#[cfg(target_os = "macos")]
fn u32_to_ipv4(v: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(v.to_be_bytes())
}

#[cfg(target_os = "macos")]
fn macos_ensure_route(
    dev: &str,
    virt_ip: std::net::Ipv4Addr,
    netmask: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    use std::process::Command;

    let network = u32_to_ipv4(ipv4_to_u32(virt_ip) & ipv4_to_u32(netmask));
    let out = Command::new("/sbin/route")
        .args([
            "-n",
            "add",
            "-net",
            &network.to_string(),
            "-netmask",
            &netmask.to_string(),
            "-interface",
            dev,
        ])
        .output()
        .context("running /sbin/route to add overlay route")?;

    if out.status.success() {
        return Ok(());
    }

    // If the route already exists, consider it success.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{stderr}");
    if combined.contains("File exists") || combined.contains("exists") {
        return Ok(());
    }

    anyhow::bail!("route add failed: {combined}");
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    server: String,
    #[serde(default)]
    transport: Option<String>,
    node_id: String,
    virtual_ip: String,
    #[serde(default)]
    netmask: Option<String>,
    #[serde(default)]
    mtu: Option<u16>,
    tun: String,
    #[serde(alias = "psk_base64")]
    relay_psk_base64: String,
    /// Optional. If omitted, falls back to relay_psk_base64 (reduces E2E security).
    #[serde(default)]
    network_psk_base64: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn parse(v: Option<&str>) -> anyhow::Result<Self> {
        match v.unwrap_or("udp").trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            other => anyhow::bail!("unsupported transport: {other} (expected udp|tcp)"),
        }
    }
}

trait NetOut: Send + Sync {
    fn send(&self, kind: OutKind, bytes: Vec<u8>) -> anyhow::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutKind {
    Control,
    Data,
}

struct UdpOut {
    sock: std::net::UdpSocket,
}

impl NetOut for UdpOut {
    fn send(&self, _kind: OutKind, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.sock.send(&bytes).context("udp send")?;
        Ok(())
    }
}

struct TcpOut {
    tx_control: channel::Sender<Vec<u8>>,
    tx_data: channel::Sender<Vec<u8>>,
}

impl NetOut for TcpOut {
    fn send(&self, kind: OutKind, bytes: Vec<u8>) -> anyhow::Result<()> {
        match kind {
            OutKind::Control => {
                self.tx_control
                    .send(bytes)
                    .map_err(|_| anyhow::anyhow!("tcp control channel closed"))?;
                Ok(())
            }
            OutKind::Data => {
                // For real-time traffic (e.g. game streaming), prefer dropping rather than
                // queueing behind TCP backpressure, which manifests as high latency.
                match self.tx_data.try_send(bytes) {
                    Ok(()) => Ok(()),
                    Err(channel::TrySendError::Full(_)) => Ok(()),
                    Err(channel::TrySendError::Disconnected(_)) => {
                        Err(anyhow::anyhow!("tcp data channel closed"))
                    }
                }
            }
        }
    }
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
    let transport = Transport::parse(cfg.transport.as_deref())?;
    let node_uuid = uuid::Uuid::parse_str(&cfg.node_id).context("parsing node_id")?;
    let node_id = NodeId(node_uuid);

    let virt_ip: std::net::Ipv4Addr = cfg.virtual_ip.parse().context("parsing virtual_ip")?;

    let mut node_by_ip: HashMap<std::net::Ipv4Addr, NodeId> = HashMap::new();

    let relay_psk = decode_psk_base64(&cfg.relay_psk_base64).context("invalid relay_psk_base64")?;
    let network_psk = match cfg.network_psk_base64.as_deref() {
        Some(v) => decode_psk_base64(v).context("invalid network_psk_base64")?,
        None => {
            eprintln!(
                "warn: network_psk_base64 not set; falling back to relay_psk_base64 (not true E2E)"
            );
            relay_psk
        }
    };

    let node_key = derive_node_key(&relay_psk, node_id);

    let netmask: std::net::Ipv4Addr = cfg
        .netmask
        .as_deref()
        .unwrap_or("255.255.255.0")
        .parse()
        .context("parsing netmask")?;

    // UDP-based overlays are sensitive to underlay MTU (PPPoE, tunnels, etc.).
    // A conservative default avoids fragmentation/blackholing for larger TCP transfers.
    let mtu: i32 = cfg.mtu.unwrap_or(1280) as i32;

    // TUN setup.
    // Note: macOS uses `utun*` devices and does not accept arbitrary interface names.
    // If a non-utun name is provided (e.g. "sn0"), we let the OS auto-allocate.
    let mut tun = tun::Configuration::default();

    #[cfg(target_os = "macos")]
    {
        let requested = cfg.tun.trim();
        if !requested.is_empty() && requested != "auto" {
            if requested == "utun" || requested.starts_with("utun") {
                tun.name(requested);
            } else {
                eprintln!(
                    "warn: ignoring tun name '{requested}' on macOS; use 'utun', 'utunX', or 'auto'"
                );
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        tun.name(&cfg.tun);
    }

    #[cfg(target_os = "macos")]
    {
        // utun is point-to-point; setting a destination avoids odd defaults.
        tun.destination(virt_ip);
    }

    tun.address(virt_ip).netmask(netmask).mtu(mtu).up();

    let dev = tun::create(&tun).context("creating TUN device")?;

    #[cfg(target_os = "macos")]
    {
        let dev_name = dev.name().unwrap_or_else(|_| "(unknown)".to_string());
        // Ensure overlay destinations route into utun, not the default gateway.
        if dev_name != "(unknown)" {
            if let Err(e) = macos_ensure_route(&dev_name, virt_ip, netmask) {
                eprintln!("warn: failed to add route for overlay via {dev_name}: {e:#}");
            }
        }
    }

    let (mut tun_reader, mut tun_writer) = dev.split();

    let (net_in_tx, net_in_rx) = channel::bounded::<Vec<u8>>(256);
    let net_out: Box<dyn NetOut> = match transport {
        Transport::Udp => {
            let sock = std::net::UdpSocket::bind("0.0.0.0:0").context("binding UDP")?;
            sock.connect(server_addr).context("connecting UDP")?;

            let sock_rx = sock.try_clone().context("cloning UDP socket")?;
            let net_in_tx = net_in_tx.clone();
            std::thread::spawn(move || {
                let mut udp_buf = vec![0u8; 2048];
                loop {
                    match sock_rx.recv(&mut udp_buf) {
                        Ok(n) if n > 0 => {
                            if net_in_tx.send(udp_buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Ok(_) => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            eprintln!("warn: udp recv failed: {e}");
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            });

            Box::new(UdpOut { sock })
        }

        Transport::Tcp => {
            let stream = std::net::TcpStream::connect(server_addr).context("connecting TCP")?;
            let _ = stream.set_nodelay(true);

            let mut reader = stream
                .try_clone()
                .context("cloning TCP stream for reader")?;
            let mut writer = stream;

            let net_in_tx = net_in_tx.clone();
            std::thread::spawn(move || loop {
                match read_frame(&mut reader, DEFAULT_MAX_FRAME_LEN) {
                    Ok(frame) => {
                        if net_in_tx.send(frame).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => {
                        eprintln!("warn: tcp read failed: {e}");
                        break;
                    }
                }
            });

            // Separate channels so control traffic remains responsive under data congestion.
            let (tcp_ctl_tx, tcp_ctl_rx) = channel::bounded::<Vec<u8>>(128);
            let (tcp_data_tx, tcp_data_rx) = channel::bounded::<Vec<u8>>(2048);
            std::thread::spawn(move || {
                use std::io::Write;

                // Keep batches small to avoid adding latency.
                const MAX_BATCH_FRAMES: usize = 16;
                const MAX_BATCH_BYTES: usize = 64 * 1024;

                loop {
                    // Prefer control frames if present.
                    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(8);
                    let mut bytes_total = 0usize;

                    while let Ok(f) = tcp_ctl_rx.try_recv() {
                        bytes_total = bytes_total.saturating_add(f.len());
                        frames.push(f);
                        if frames.len() >= MAX_BATCH_FRAMES || bytes_total >= MAX_BATCH_BYTES {
                            break;
                        }
                    }

                    if frames.is_empty() {
                        channel::select! {
                            recv(tcp_ctl_rx) -> v => {
                                let Ok(v) = v else { break; };
                                bytes_total = v.len();
                                frames.push(v);
                            }
                            recv(tcp_data_rx) -> v => {
                                let Ok(v) = v else { break; };
                                bytes_total = v.len();
                                frames.push(v);
                            }
                        }
                    }

                    while frames.len() < MAX_BATCH_FRAMES && bytes_total < MAX_BATCH_BYTES {
                        // Drain any waiting control first.
                        match tcp_ctl_rx.try_recv() {
                            Ok(next) => {
                                bytes_total = bytes_total.saturating_add(next.len());
                                frames.push(next);
                                continue;
                            }
                            Err(_) => {}
                        }
                        match tcp_data_rx.try_recv() {
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
                            eprintln!("warn: tcp batch encode failed: {e}");
                            break;
                        }
                    };

                    if let Err(e) = writer.write_all(&out) {
                        eprintln!("warn: tcp write failed: {e}");
                        break;
                    }
                }
            });

            Box::new(TcpOut {
                tx_control: tcp_ctl_tx,
                tx_data: tcp_data_tx,
            })
        }
    };

    eprintln!(
        "client started: node={} ip={} server={} transport={:?}",
        node_id.0, virt_ip, server_addr, transport
    );

    // Register.
    send_control(
        net_out.as_ref(),
        node_id,
        NodeId(uuid::Uuid::nil()),
        &node_key,
        Control::Register {
            virtual_ip: Ipv4AddrBytes::from_std(virt_ip),
        },
    )?;

    // Use blocking threads for TUN I/O and UDP receive.
    // Main thread remains event-driven (no polling sleeps).
    let (tun_tx, tun_rx) = channel::bounded::<Vec<u8>>(256);
    let (net_tx, net_rx) = channel::bounded::<Vec<u8>>(256);

    std::thread::spawn(move || {
        let mut buf = vec![0u8; 2000];
        loop {
            match tun_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    #[cfg(target_os = "macos")]
                    let pkt = {
                        // On macOS, utun always includes a 4-byte packet information header.
                        // Strip it so the rest of the code and the on-wire format stay as raw IPv4.
                        if n <= 4 {
                            continue;
                        }
                        buf[4..n].to_vec()
                    };

                    #[cfg(not(target_os = "macos"))]
                    let pkt = buf[..n].to_vec();

                    if tun_tx.send(pkt).is_err() {
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
            #[cfg(target_os = "macos")]
            {
                // utun expects the 4-byte packet information header.
                // We only tunnel IPv4 packets, so always tag as PF_INET.
                let mut framed = Vec::with_capacity(4 + pkt.len());
                framed.extend_from_slice(&macos_pi_header_for_ipv4());
                framed.extend_from_slice(&pkt);
                let _ = tun_writer.write_all(&framed);
            }

            #[cfg(not(target_os = "macos"))]
            {
                let _ = tun_writer.write_all(&pkt);
            }
        }
    });

    let keepalive_tick = channel::tick(Duration::from_secs(20));

    let mut pending_by_ip: HashMap<std::net::Ipv4Addr, Vec<Vec<u8>>> = HashMap::new();
    let mut last_resolve_sent: HashMap<std::net::Ipv4Addr, Instant> = HashMap::new();
    const MAX_PENDING_PER_IP: usize = 16;
    const RESOLVE_RETRY: Duration = Duration::from_secs(2);

    loop {
        channel::select! {
            recv(keepalive_tick) -> _ => {
                let _ = send_control(
                    net_out.as_ref(),
                    node_id,
                    NodeId(uuid::Uuid::nil()),
                    &node_key,
                    Control::Keepalive,
                );
            }

            recv(tun_rx) -> pkt => {
                let Ok(pkt) = pkt else { return Ok(()); };

                // Minimal IPv4 parsing: destination at bytes 16..20.
                if pkt.len() < 20 {
                    continue;
                }
                let dst_ip = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

                if let Some(dst_node) = node_by_ip.get(&dst_ip).copied() {
                    send_data(net_out.as_ref(), node_id, dst_node, &network_psk, &pkt)?;
                    continue;
                }

                let entry = pending_by_ip.entry(dst_ip).or_default();
                if entry.len() < MAX_PENDING_PER_IP {
                    entry.push(pkt);
                } else if is_debug() {
                    eprintln!("debug: pending queue full for dst={dst_ip}");
                }

                let now = Instant::now();
                let should_send = match last_resolve_sent.get(&dst_ip) {
                    Some(t) => now.duration_since(*t) >= RESOLVE_RETRY,
                    None => true,
                };
                if should_send {
                    let _ = send_control(
                        net_out.as_ref(),
                        node_id,
                        NodeId(uuid::Uuid::nil()),
                        &node_key,
                        Control::Resolve {
                            virtual_ip: Ipv4AddrBytes::from_std(dst_ip),
                        },
                    );
                    last_resolve_sent.insert(dst_ip, now);
                }
            }

            recv(net_in_rx) -> bytes => {
                let Ok(bytes) = bytes else { return Ok(()); };
                if let Err(e) = handle_inbound(
                    net_out.as_ref(),
                    &bytes,
                    node_id,
                    &node_key,
                    &network_psk,
                    &net_tx,
                    &mut node_by_ip,
                    &mut pending_by_ip,
                ) {
                    if is_debug() {
                        eprintln!("debug: drop inbound: {e:#}");
                    }
                }
            }
        }
    }
}

fn handle_inbound(
    out: &dyn NetOut,
    bytes: &[u8],
    node_id: NodeId,
    node_key: &[u8; 32],
    network_psk: &[u8; 32],
    net_tx: &channel::Sender<Vec<u8>>,
    node_by_ip: &mut HashMap<std::net::Ipv4Addr, NodeId>,
    pending_by_ip: &mut HashMap<std::net::Ipv4Addr, Vec<Vec<u8>>>,
) -> Result<()> {
    let pkt = decode_wire(bytes).context("decode wire")?;
    if pkt.v != WIRE_VERSION {
        anyhow::bail!("unsupported wire version");
    }
    if pkt.dst != node_id {
        anyhow::bail!("not for us");
    }

    match pkt.t {
        MsgType::Control => {
            let aad = aad_bytes(pkt.v, pkt.t, pkt.src, pkt.dst);
            let pt =
                open(node_key, &pkt.nonce12, &pkt.ciphertext, &aad).context("decrypt control")?;
            let ctrl = decode_control(&pt).context("decode control")?;

            match ctrl {
                Control::ResolveOk {
                    virtual_ip,
                    node_id: peer,
                } => {
                    let ip = virtual_ip.to_std();
                    node_by_ip.insert(ip, peer);

                    if let Some(mut queued) = pending_by_ip.remove(&ip) {
                        for pkt in queued.drain(..) {
                            let _ = send_data(out, node_id, peer, network_psk, &pkt);
                        }
                    }
                    Ok(())
                }
                Control::ResolveErr { virtual_ip } => {
                    if is_debug() {
                        eprintln!("debug: resolve failed for dst={}", virtual_ip.to_std());
                    }
                    pending_by_ip.remove(&virtual_ip.to_std());
                    Ok(())
                }
                Control::Keepalive | Control::Register { .. } | Control::Resolve { .. } => Ok(()),
            }
        }
        MsgType::Data => {
            let e2e_key = derive_e2e_key(network_psk, pkt.src, pkt.dst);
            let aad = aad_bytes(pkt.v, pkt.t, pkt.src, pkt.dst);
            let payload =
                open(&e2e_key, &pkt.nonce12, &pkt.ciphertext, &aad).context("decrypt data")?;
            if payload.is_empty() {
                anyhow::bail!("empty payload");
            }
            net_tx.send(payload).ok();
            Ok(())
        }
    }
}

fn send_control(
    out: &dyn NetOut,
    src: NodeId,
    dst: NodeId,
    node_key: &[u8; 32],
    ctrl: Control,
) -> Result<()> {
    let inner_bytes = encode_control(&ctrl).context("encode control")?;
    let nonce = random_nonce12();
    let aad = aad_bytes(WIRE_VERSION, MsgType::Control, src, dst);
    let ciphertext = seal(node_key, &nonce, &inner_bytes, &aad).context("encrypt")?;

    let pkt = WirePacket {
        v: WIRE_VERSION,
        t: MsgType::Control,
        src,
        dst,
        nonce12: nonce,
        ciphertext,
    };

    let bytes = encode_wire(&pkt).context("encode wire")?;
    out.send(OutKind::Control, bytes)?;
    Ok(())
}

fn send_data(
    out: &dyn NetOut,
    src: NodeId,
    dst: NodeId,
    network_psk: &[u8; 32],
    payload: &[u8],
) -> Result<()> {
    let e2e_key = derive_e2e_key(network_psk, src, dst);
    let nonce = random_nonce12();
    let aad = aad_bytes(WIRE_VERSION, MsgType::Data, src, dst);
    let ciphertext = seal(&e2e_key, &nonce, payload, &aad).context("encrypt data")?;

    let pkt = WirePacket {
        v: WIRE_VERSION,
        t: MsgType::Data,
        src,
        dst,
        nonce12: nonce,
        ciphertext,
    };

    let bytes = encode_wire(&pkt).context("encode wire")?;
    out.send(OutKind::Data, bytes)?;
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
