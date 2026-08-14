# Intel TDX Direct KVM `TDREPORT` Runner

A minimal, zero-dependency `no_std` Rust bare-metal payload and direct C KVM hypervisor runner designed to run inside an **Intel Trust Domain (TDX VM)** via `/dev/kvm` ioctls, issue `TDCALL[TDG.MR.REPORT]`, and print the resulting **`TDREPORT`**.

---

## 🛠 Project Structure

```
.
├── Cargo.toml                  # Rust package manifest (no_std, x86_64, spin)
├── .cargo/config.toml          # Cargo build flags for x86_64-unknown-none
├── linker.ld                   # Bare-metal kernel linker script (entry: _start, load @ 1MB)
├── build.sh                    # Automated build script
├── kvm-runner                  # Direct KVM runner binary
├── tdreport.bin                # Raw 64-bit binary payload
├── src/
│   ├── main.rs                 # Bare-metal payload entry point (_start) and panic handler
│   ├── serial.rs               # 16550 UART (COM1 0x3F8) driver for console output
│   └── tdx.rs                  # Low-level TDCALL inline assembly & TDREPORT structs
└── tools/
    └── kvm_runner.c            # Direct KVM hypervisor harness using /dev/kvm ioctls
```

---

## ⚡ Direct KVM Execution

The direct KVM runner ([`tools/kvm_runner.c`](file:///home/sinan/dev/tmp/tdreport/tools/kvm_runner.c)) interacts directly with Linux `/dev/kvm` ioctls (`KVM_CREATE_VM`, `KVM_MEMORY_ENCRYPT_OP`, `KVM_SET_USER_MEMORY_REGION`, `KVM_CREATE_VCPU`, `KVM_RUN`):

1. **Lightweight & Instant**: Loads a td-shim TDVF image containing the ELF payload, constructs its TD HOB, and initializes its measured firmware sections through the TDX KVM ABI.
2. **Real-time Console Output**: Intercepts COM1 serial port (`0x3F8`) I/O exits from the guest and streams all kernel `println!` output straight to terminal `stdout`.
3. **Intel TDX Mode**: Directly configures `KVM_X86_TDX_VM`, fetches TDX capabilities (`KVM_TDX_CAPABILITIES`), and initializes the Trust Domain (`KVM_TDX_INIT_VM`).

---

## 🚀 Build and Run

```bash
# 1. Build the payload and runner
./build.sh

# 2. Run directly with KVM
sudo ./kvm-runner td-shim-tdreport.bin
```

---

## 🔍 How `TDCALL[TDG.MR.REPORT]` Works

Intel TDX provides `TDCALL` (`opcode 0x0F 0x01 0xD7`) to communicate with the TDX Module from inside a Trust Domain.

### Register Convention for Leaf 4 (`TDG.MR.REPORT`):
* **`RAX`** = `4` (`TDCALL_TDG_MR_REPORT`)
* **`RCX`** = Guest Physical Address (GPA) of **1024-byte aligned** `TdReport` buffer
* **`RDX`** = Guest Physical Address (GPA) of **64-byte** `ReportData` nonce
* **`R8`**  = `0` (Subtype ID, default 0)
