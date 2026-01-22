# simple_network

Minimal relay-based encrypted overlay network.

This workspace contains:

- `sn-relay`: UDP relay server (star topology)
- `sn-client`: Linux client that creates a TUN device and tunnels IPv4 packets through the relay
- `sn-proto`: wire format + crypto helpers

## How it works

- Each client creates a TUN interface (e.g. `sn0`) with a **virtual IPv4** like `10.0.0.2`.
- When the OS sends a packet to some virtual destination (e.g. `10.0.0.3`), the client reads it from the TUN device.
- The client wraps that packet in an encrypted message and sends it via UDP to the relay.
- The relay tracks the UDP source address of each node (learned from incoming packets / registration), then forwards traffic to the destination node.

### Important security note

This is **not end-to-end encryption** between clients. The relay decrypts packets from the source node and re-encrypts them for the destination node.

## Configuration model

Configuration is static (TOML):

- Relay config contains a registry mapping `node_id -> virtual_ip`.
- Client config contains a routing table mapping `virtual_ip -> node_id`.

The repo includes `configs/*.example.toml`. Local configs (with real PSKs / endpoints) are ignored by `.gitignore`.

### Client config fields

In `sn-client` config:

- `server` (string): UDP relay address, e.g. `"1.2.3.4:41641"`
- `node_id` (UUID string): unique per node
- `virtual_ip` (IPv4 string): IP assigned to the node on the overlay
- `tun` (string): TUN device name, e.g. `sn0`
- `psk_base64` (base64 string): 32-byte shared secret (must match relay)
- `peers` (table): map `"10.0.0.X" = "<peer uuid>"`
- `netmask` (optional, IPv4 string): defaults to `255.255.255.0` (`/24`)
- `mtu` (optional, u16): defaults to `1280` (conservative; helps avoid blackholing)

### Relay config fields

In `sn-relay` config:

- `listen` (string): UDP bind address, e.g. `"0.0.0.0:41641"`
- `psk_base64` (base64 string): 32-byte shared secret (must match clients)
- `peers` (table): map `"<peer uuid>" = "10.0.0.X"`

## Build

```bash
cargo build --release
```

## Run (quickstart)

1) Pick a PSK (32 bytes, base64). Put the same value in relay + all clients.

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

### Build flow (MIPS32)

This repo’s helper script prefers:

1) `cross` (Docker-based) if available
2) otherwise `cargo-zigbuild` + Zig + `nightly` + `-Z build-std` (does not require Docker)

The fallback is necessary because `rust-std` for `mipsel-unknown-linux-musl` isn’t available on stable, so the script builds `std` from source.

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

Alternative: OpenWrt SDK toolchain.

- Point the Rust target linker in `.cargo/config.toml`:
	- `linker = "/path/to/mipsel-openwrt-linux-musl-gcc"`
- Then run:

```bash
cargo build --release --target mipsel-unknown-linux-musl -p sn-client
```

