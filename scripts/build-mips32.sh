#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TARGET="${1:-mipsel-unknown-linux-musl}"
PKG="${2:-sn-client}"

echo "Building ${PKG} for ${TARGET} (release)…" >&2

if command -v cross >/dev/null 2>&1; then
  cross build --release --target "${TARGET}" -p "${PKG}"
  echo "Built: target/${TARGET}/release/${PKG}" >&2
  exit 0
fi

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
