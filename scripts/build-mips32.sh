#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-mipsel-unknown-linux-musl}"
PKG="${2:-sn-client}"

echo "Building ${PKG} for ${TARGET} (release)…" >&2

have() { command -v "$1" >/dev/null 2>&1; }

if command -v cross >/dev/null 2>&1; then
  if cross build --release --target "${TARGET}" -p "${PKG}"; then
    echo "Built: target/${TARGET}/release/${PKG}" >&2
    exit 0
  fi

  echo "cross failed; falling back to cargo-zigbuild." >&2
fi

# --- Fallback: cargo-zigbuild + Zig + nightly + build-std (no Docker required) ---

ZIG_BIN=""
if have zig; then
  ZIG_BIN="zig"
else
  # Best-effort Zig bootstrap for Linux x86_64 (kept local to repo).
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  if [[ "${OS}" == "Linux" && "${ARCH}" == "x86_64" ]]; then
    ZIG_DIR="$ROOT/.tools/zig-linux-x86_64-0.13.0"
    if [[ ! -x "$ZIG_DIR/zig" ]]; then
      mkdir -p "$ROOT/.tools"
      echo "Installing Zig into .tools/ (0.13.0)…" >&2
      curl -L --fail -o "$ROOT/.tools/zig.tar.xz" \
        https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz
      tar -xJf "$ROOT/.tools/zig.tar.xz" -C "$ROOT/.tools"
    fi
    ZIG_BIN="$ZIG_DIR/zig"
  fi
fi

if [[ -z "$ZIG_BIN" ]]; then
  cat >&2 <<'EOF'
Zig is required for the non-Docker fallback build.

Install Zig and ensure `zig` is on PATH, or (Linux x86_64) re-run this script with network access so it can download Zig into .tools/.
EOF
  exit 1
fi

if ! have cargo-zigbuild; then
  echo "Installing cargo-zigbuild…" >&2
  cargo install cargo-zigbuild --locked
fi

if have rustup; then
  if ! rustup toolchain list | grep -q '^nightly'; then
    echo "Installing nightly toolchain (minimal)…" >&2
    rustup toolchain install nightly --profile minimal
  fi
  if ! rustup component list --toolchain nightly --installed | grep -q '^rust-src '; then
    echo "Installing rust-src (nightly)…" >&2
    rustup component add rust-src --toolchain nightly
  fi
else
  echo "rustup is required for the zigbuild fallback (nightly + rust-src)." >&2
  exit 1
fi

# MIPS32: keep ABI consistent (Rust build-std produces soft-float objects).
EXTRA_RUSTFLAGS=""
if [[ "$TARGET" == mipsel-unknown-linux-musl || "$TARGET" == mips-unknown-linux-musl ]]; then
  EXTRA_RUSTFLAGS="-C link-arg=-msoft-float"
fi

echo "Building with cargo-zigbuild (nightly + build-std)…" >&2
PATH="$(dirname "$ZIG_BIN"):$PATH" \
RUSTFLAGS="${RUSTFLAGS-} ${EXTRA_RUSTFLAGS}" \
cargo +nightly zigbuild -Z build-std=std,panic_abort --release --target "${TARGET}" -p "${PKG}"

echo "Built: target/${TARGET}/release/${PKG}" >&2
exit 0

cat >&2 <<'EOF'
cross is not installed.

Option A (recommended on macOS):
  cargo install cross --git https://github.com/cross-rs/cross
  ./scripts/build-mips32.sh mipsel-unknown-linux-musl sn-client

Option B (OpenWrt SDK toolchain):
  - Install/locate the OpenWrt SDK for your router target.
  - Set the target linker in .cargo/config.toml:
      [target.mipsel-unknown-linux-musl]
      linker = "/path/to/mipsel-openwrt-linux-musl-gcc"
  - Then run:
      rustup target add mipsel-unknown-linux-musl
      cargo build --release --target mipsel-unknown-linux-musl -p sn-client
EOF

exit 1
