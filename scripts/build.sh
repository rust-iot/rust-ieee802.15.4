#!/usr/bin/env bash
set -e

export RUSTFLAGS="-D warnings"

cargo test --verbose
