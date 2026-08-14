//! Bare-metal Intel TDX Minimal Firmware/Kernel Payload
//!
//! Designed to boot directly via td-shim or low-level virtual firmware,
//! issue TDCALL[TDG.MR.REPORT], parse, and display the Intel TDREPORT.

#![no_std]
#![no_main]

mod console;
mod tdx;

use td_payload as _;

/// Entry point called by td-shim or reset bootloader in 64-bit long mode.
#[no_mangle]
pub extern "C" fn main() -> ! {
    println!();
    println!("************************************************************");
    println!("*   Intel TDX Bare-Metal Firmware/Kernel Payload Initialized *");
    println!("************************************************************");
    println!("[+] Firmware payload loaded at 64-bit long mode.");
    println!("[+] Console output routed through TDX VMCALL I/O at COM1 (0x3F8).");

    // 2. Prepare 64-byte user REPORTDATA nonce
    let mut report_data: tdx::ReportData = [0u8; 64];
    let nonce_msg = b"INTEL_TDX_TDREPORT_NONCE_VERIFICATION_PAYLOAD_2026";
    report_data[..nonce_msg.len()].copy_from_slice(nonce_msg);

    println!("[+] Prepared 64-byte REPORTDATA nonce:");
    println!("    {}", tdx::HexBuffer(&report_data));

    // 3. Issue TDCALL[TDG.MR.REPORT]
    println!("[+] Executing TDCALL[TDG.MR.REPORT] (Leaf 4)...");
    
    let exit_status = match tdx::get_td_report(&report_data) {
        Ok(report) => {
            println!("[+] TDCALL SUCCESS! Status code 0 (TDX_SUCCESS).");
            println!("[+] Parsing TDREPORT structure...");
            tdx::print_td_report(&report);
            println!("[+] Intel TDX TDREPORT retrieval successfully completed!");
            0u8
        }
        Err(status) => {
            println!("[!] TDCALL execution returned error: {:?}", status);
            println!("[!] Note: If running on a host without Intel TDX hardware/module support,");
            println!("    TDCALL will fail or trigger an exception.");
            println!("[!] To test on a real TDX host, launch this payload inside a TDX VM");
            println!("    via QEMU with -machine q35,confidential-guest-support=tdx0.");
            1u8
        }
    };

    println!("************************************************************");
    println!("* Execution finished. Returning control to the KVM runner. *");
    println!("************************************************************");

    // Signal completion through a TDX-safe debug-exit-style I/O port.
    tdx_tdcall::tdx::tdvmcall_io_write_8(0xf4, exit_status);

    // Fallback for VMMs which ignore the completion port.
    loop {
        tdx_tdcall::tdx::tdvmcall_halt();
    }
}
