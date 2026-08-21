#!/usr/bin/env bash
# Builds the wasm package and packs it into an npm tarball at the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf pkg
# Everything after the first EXTRA_OPTION goes to `cargo build`, so wasm-pack's
# own flags must come first and the cargo flags after `--`.
wasm-pack build --target web --out-dir pkg --scope pock-sh -- --features wasm
# wasm-pack writes a pkg/.gitignore that would hide the whole package from
# `npm pack`'s file walk; the tarball is a build artifact either way.
rm -f pkg/.gitignore
( cd pkg && npm pack --pack-destination .. )
