#!/bin/sh
set -eu

RUSTC_PATH="$(rustup which --toolchain 1.90.0 rustc)"
RUST_BIN="$(dirname "$RUSTC_PATH")"
PATH="$RUST_BIN:$PATH"
export PATH

exec cargo "$@"
