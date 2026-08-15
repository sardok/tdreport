//! TDREPORT support using td-shim's aligned, ABI-correct TDX implementation.

pub type ReportData = [u8; tdx_tdcall::tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE];
pub type TdReport = tdx_tdcall::tdreport::TdxReport;
pub type TdReportError = tdx_tdcall::TdCallError;

pub fn get_td_report(report_data: &ReportData) -> Result<TdReport, TdReportError> {
    tdx_tdcall::tdreport::tdcall_report(report_data)
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
        for byte in self.0 { write!(f, "{:02x}", byte)?; }
        Ok(())
    }
}
