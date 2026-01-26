# simple_network

Minimal relay-based encrypted overlay network.

This workspace contains:

- `sn-relay`: relay server (UDP or TCP; star topology)
- `sn-client`: client that creates a TUN device and tunnels IPv4 packets through the relay (Linux/macOS)
- `sn-proto`: wire format + crypto helpers

## How it works

- Each client creates a TUN interface (e.g. `sn0`) with a **virtual IPv4** like `10.0.0.2`.
- When the OS sends a packet to some virtual destination (e.g. `10.0.0.3`), the client reads it from the TUN device.
- The client wraps that packet in an end-to-end encrypted message and sends it via UDP to the relay.
- The relay forwards traffic to the destination node **without decrypting**.

Transport options:

- `udp` (default): original design; low overhead and NAT-friendly.
- `tcp`: uses a length-prefixed stream framing layer; can be beneficial on some networks and for long-lived flows.

### Security note

Data-plane traffic is end-to-end encrypted between clients (the relay only forwards opaque ciphertext).

The control-plane (registration, keepalive, peer discovery) is encrypted client <-> relay.

## Configuration model

Configuration is mostly static (TOML):

- Relay config contains a registry mapping `node_id -> virtual_ip`.
- Clients do not need a static routing table; they can resolve `virtual_ip -> node_id` on-demand through the relay.

The repo includes `configs/*.example.toml`.

### Client config fields

In `sn-client` config:

- `server` (string): relay address, e.g. `"1.2.3.4:41641"`
- `transport` (optional, string): `"udp"` (default) or `"tcp"`
- `node_id` (UUID string): unique per node
- `virtual_ip` (IPv4 string): IP assigned to the node on the overlay
- `tun` (string): TUN device name.
	- Linux: an arbitrary name like `sn0`
	- macOS: use `utun`, `utunX`, or `auto` (macOS does not accept arbitrary names)
- `relay_psk_base64` (base64 string): 32-byte shared secret for relay control-plane (must match relay)
- `network_psk_base64` (base64 string): 32-byte shared secret for client end-to-end data-plane (relay does not need this)
- `netmask` (optional, IPv4 string): defaults to `255.255.255.0` (`/24`)
- `mtu` (optional, u16): defaults to `1280` (conservative; helps avoid blackholing)

### Relay config fields

In `sn-relay` config:

- `listen` (string): bind address, e.g. `"0.0.0.0:41641"`
- `transport` (optional, string): `"udp"` (default) or `"tcp"`
- `relay_psk_base64` (base64 string): 32-byte shared secret for relay control-plane (must match clients)
- `peers` (table): map `"<peer uuid>" = "10.0.0.X"`

## Build

```bash
cargo build --release
```

## Run (quickstart)

1) Pick a PSK (32 bytes, base64). Put the same value in relay + all clients.

```bash
openssl rand -base64 32
```

2) Start relay:

```bash
RUST_LOG=info ./target/release/sn-relay run --config configs/relay.example.toml
```

3) Start each client (one per node):

```bash
sudo RUST_LOG=info ./target/release/sn-client run --config configs/client.example.toml
```

4) Verify routing:

```bash
ip addr show dev sn0
ip route get 10.0.0.2
```

On macOS you can use:

```bash
ifconfig | grep -E "^utun"
route -n get 10.0.0.2
```

## Troubleshooting

### Ping works but HTTP “hangs” (router UI after auth)

This is often MTU/fragmentation: small packets succeed (ICMP / small HTTP), but larger responses stall.

- Try setting `mtu = 1280` in the client config (this is now the default).
- If your underlay supports it you can increase to 1400 for throughput.

### Browser stuck but curl works

Some browsers will try `https://10.0.0.2/` (auto-upgrade or cached HSTS). If the router doesn’t listen on 443, it can look like a hang.

- Confirm HTTP works:

```bash
curl -v --max-time 10 http://10.0.0.2/
```

### Login succeeds but UI assets never load

Many router UIs redirect to a different host/IP after auth (sometimes their LAN IP like `192.168.1.1`).

- Use DevTools → Network to see what hostname/IP it requests after login.
- If it redirects to an IP that isn’t on the overlay, you’ll need to route/NAT that network over the tunnel (not implemented by this project yet).

## Notes for MIPS32/OpenWrt

- Cross compiling Rust to MIPS32 is possible; you’ll typically use `mipsel-unknown-linux-musl` (little-endian) for many OpenWrt targets.
- Release profile is already size-optimized (`opt-level=z`, `lto`, `strip`, `panic=abort`).

### Build for MIPS32

Build `sn-client`:

```bash
./scripts/build-mips32.sh mipsel-unknown-linux-musl sn-client
```

Build `sn-relay`:

```bash
./scripts/build-mips32.sh mipsel-unknown-linux-musl sn-relay
```

Outputs land in `target/<target>/release/<pkg>`.

Notes:

- If you have Docker + `cross` installed, the script will use it automatically.
- If not, the script will use `cargo-zigbuild` and will add the required `-msoft-float` linker arg for MIPS32.


