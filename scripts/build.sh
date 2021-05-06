#!/usr/bin/env bash
set -e

export RUSTFLAGS="-D warnings"

cargo fmt -- --check
cargo test --verbose
