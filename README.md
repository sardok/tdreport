# Intel TDX Direct KVM `TDREPORT` Runner

A Cargo workspace producing a self-contained `tdreport` executable from a `no_std` Rust bare-metal payload and a Rust KVM hypervisor runner. It creates an **Intel Trust Domain (TDX VM)** through `/dev/kvm`, issues `TDCALL[TDG.MR.REPORT]`, and prints the resulting **`TDREPORT`**.

---

## 🚀 Build and Run

```bash
# 1. Build the payload, TDVF, and self-contained runner
./build.sh

# 2. Run and print the TDREPORT
sudo ./tdreport.bin
```

To also save the raw 1024-byte report:

```bash
sudo ./tdreport.bin --output tdreport-report.bin
```

For development, the standalone runner and TDVF remain available separately:

```bash
sudo ./kvm-runner.bin td-shim-tdreport.bin
```

## Library usage

The `tdreport` package includes its TDVF image, so consumer projects do not need
to set `TDREPORT_TDVF_PATH`:

```toml
[dependencies]
tdreport = { path = "../tdreport/tdreport" }
```

```rust
let report: [u8; 1024] = tdreport::tdreport()?;
```

`TDREPORT_TDVF_PATH` remains available as an optional build-time override for
development with a custom TDVF image.

---
