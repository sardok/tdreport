# Intel TDX Direct KVM `TDREPORT` Runner

A Cargo workspace containing a `no_std` Rust bare-metal payload and a Rust KVM hypervisor runner. It creates an **Intel Trust Domain (TDX VM)** through `/dev/kvm`, issues `TDCALL[TDG.MR.REPORT]`, and prints the resulting **`TDREPORT`**.

---

## 🚀 Build and Run

```bash
# 1. Build the payload and runner
./build.sh

# 2. Run directly with KVM
sudo ./kvm-runner.bin td-shim-tdreport.bin
```

---
