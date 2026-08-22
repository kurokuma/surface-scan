#!/usr/bin/env sh
set -eu
cargo build --release --locked
cargo test --all-targets --locked
echo "Built target/release/surface-scan"

