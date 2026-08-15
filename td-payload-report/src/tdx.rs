//! TDREPORT support using td-shim's aligned, ABI-correct TDX implementation.

pub type ReportData = [u8; tdx_tdcall::tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE];
pub type TdReport = tdx_tdcall::tdreport::TdxReport;

pub const TD_REPORT_SIZE: usize = 1024;
const TD_REPORT_IO_PORT: u16 = 0x500;
pub type TdReportError = tdx_tdcall::TdCallError;

pub fn get_td_report(report_data: &ReportData) -> Result<TdReport, TdReportError> {
    tdx_tdcall::tdreport::tdcall_report(report_data)
}

pub fn send_td_report(report: &TdReport) {
    assert_eq!(core::mem::size_of::<TdReport>(), TD_REPORT_SIZE);
    // SAFETY: TdReport is an initialized, plain ABI structure and the slice is
    // bounded to its exact object size.
    let bytes = unsafe {
        core::slice::from_raw_parts((report as *const TdReport).cast::<u8>(), TD_REPORT_SIZE)
    };
    for &byte in bytes {
        tdx_tdcall::tdx::tdvmcall_io_write_8(TD_REPORT_IO_PORT, byte);
    }
}

pub fn print_td_report(report: &TdReport) {
    crate::println!("============================================================");
    crate::println!("                  INTEL TDX TDREPORT                       ");
    crate::println!("============================================================");
    crate::println!("{}", report);
    crate::println!("============================================================");
}

pub struct HexBuffer<'a>(pub &'a [u8]);

impl core::fmt::Display for HexBuffer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
