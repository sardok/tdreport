# Intel TDX Direct KVM `TDREPORT` Runner

A minimal, zero-dependency `no_std` Rust bare-metal payload and direct C KVM hypervisor runner designed to run inside an **Intel Trust Domain (TDX VM)** via `/dev/kvm` ioctls, issue `TDCALL[TDG.MR.REPORT]`, and print the resulting **`TDREPORT`**.

---

## 🚀 Build and Run

```bash
# 1. Build the payload and runner
./build.sh

# 2. Run directly with KVM
sudo ./kvm-runner td-shim-tdreport.bin
```

---