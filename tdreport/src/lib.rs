//! Self-contained Intel TDX TDREPORT retrieval.

use anyhow::Result;

static TDVF_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/td-shim-tdreport.bin"));

/// Run the embedded TDVF and return the raw 1024-byte TDREPORT.
pub fn tdreport() -> Result<kvm_runner::TdReport> {
    kvm_runner::run_image(TDVF_IMAGE)
}
