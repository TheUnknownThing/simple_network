use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use sn_proto::crypto::{decode_psk_base64, derive_node_key, open, random_nonce12, seal};
use sn_proto::wire::{
    decode_control, decode_wire, encode_control, encode_wire, Control, Ipv4AddrBytes, MsgType,
    NodeId, WirePacket, WIRE_VERSION,
};

#[derive(Debug, Deserialize)]
struct RelayConfig {
    listen: String,
    #[serde(alias = "psk_base64")]
    relay_psk_base64: String,
    peers: HashMap<String, String>,
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

    let sock = std::net::UdpSocket::bind(&cfg.listen)
        .with_context(|| format!("binding UDP socket on {}", cfg.listen))?;
    eprintln!(
        "relay started: listen={} peers={}",
        cfg.listen,
        peers_by_id.len()
    );

    let mut endpoints: HashMap<NodeId, SocketAddr> = HashMap::new();
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

        if let Err(e) = handle_packet(
            &sock,
            &buf[..n],
            from,
            &peers_by_id,
            &node_by_ip,
            &mut endpoints,
        ) {
            if is_debug() {
                eprintln!("debug: packet rejected from={from}: {e:#}");
            }
        }
    }
}

fn handle_packet(
    sock: &std::net::UdpSocket,
    bytes: &[u8],
    from: SocketAddr,
    peers_by_id: &HashMap<NodeId, PeerInfo>,
    node_by_ip: &HashMap<std::net::Ipv4Addr, NodeId>,
    endpoints: &mut HashMap<NodeId, SocketAddr>,
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
            endpoints.insert(pkt.src, from);

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
            if expected_from != from {
                anyhow::bail!("src endpoint mismatch (spoof?)");
            }

            let dst_addr = endpoints
                .get(&pkt.dst)
                .copied()
                .context("no endpoint for dst (has it registered yet?)")?;

            // Forward opaquely; relay never decrypts MsgType::Data.
            sock.send_to(bytes, dst_addr).context("udp send_to")?;
            Ok(())
        }
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
