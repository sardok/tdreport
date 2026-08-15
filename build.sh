#!/usr/bin/env bash
set -e

echo "============================================================"
echo "    Building Intel TDX Bare-Metal Payload & KVM Runner      "
echo "============================================================"

# 1. Ensure target x86_64-unknown-none is present
rustup target add x86_64-unknown-none >/dev/null 2>&1 || true

# 2. Compile the bare-metal payload workspace package.
cargo build --release --target x86_64-unknown-none \
    -p td-payload-report

# 3. Extract raw binary format from ELF
objcopy -O binary target/x86_64-unknown-none/release/tdreport tdreport.bin

# 4. Build a td-shim TDVF containing the ELF payload
if [ -d third_party/td-shim ]; then
    (
        cd third_party/td-shim
        CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu RUSTFLAGS= \
        CC=clang AR=ar CC_x86_64_unknown_none=clang AR_x86_64_unknown_none=ar \
        cargo image -t executable \
          -p ../../target/x86_64-unknown-none/release/tdreport \
          --release --log-level off -o ../../td-shim-tdreport.bin
    )
fi

# 5. Compile the Rust KVM runner workspace package and copy the artifact.
cargo build --release --target x86_64-unknown-linux-gnu \
    -p kvm-runner
cp target/x86_64-unknown-linux-gnu/release/kvm-runner \
   ./kvm-runner.bin

echo "============================================================"
echo " Build Completed Successfully!                              "
echo " Generated artifacts:                                       "
echo "  1. tdreport.bin (Raw 64-bit binary payload, $(wc -c < tdreport.bin) bytes)"
echo "  2. td-shim-tdreport.bin (TDVF plus executable payload)"
echo "  3. kvm-runner.bin (Rust direct KVM runner binary)"
echo "============================================================"
