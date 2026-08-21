#!/usr/bin/env bash
# Builds PockCoreFFI.xcframework (iOS device arm64 + iOS simulator arm64) and
# drops the generated Swift wrapper into swift/Sources/PockCore/.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=swift/Sources/PockCore

rm -rf target/xcf PockCoreFFI.xcframework
rm -f "$OUT"/*.swift
mkdir -p target/xcf "$OUT"

for t in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build --release --features uniffi --target "$t"
done

# `--library` mode reads the exported uniffi symbols straight out of the built
# artifact, so the bindings can never drift from the shipped binary.
cargo run --release --features uniffi-cli --bin uniffi-bindgen -- generate \
  --library target/aarch64-apple-ios/release/libpock_core.a \
  --language swift --out-dir target/xcf/bindings

# uniffi.toml names the modules: PockCore.swift + PockCoreFFI.h/.modulemap.
# Glob the Swift so an added module doesn't silently go missing.
mv target/xcf/bindings/*.swift "$OUT"/
mkdir -p target/xcf/headers
mv target/xcf/bindings/PockCoreFFI.h target/xcf/headers/
# xcodebuild only picks up a header dir's module map under this exact name.
mv target/xcf/bindings/PockCoreFFI.modulemap target/xcf/headers/module.modulemap

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libpock_core.a -headers target/xcf/headers \
  -library target/aarch64-apple-ios-sim/release/libpock_core.a -headers target/xcf/headers \
  -output PockCoreFFI.xcframework

echo "built PockCoreFFI.xcframework"
