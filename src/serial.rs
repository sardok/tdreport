//! TDX-safe serial output through TDG.VP.VMCALL I/O.

use core::fmt;

struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            if byte == b'\n' {
                tdx_tdcall::tdx::tdvmcall_io_write_8(0x3f8, b'\r');
            }
            tdx_tdcall::tdx::tdvmcall_io_write_8(0x3f8, byte);
        }
        Ok(())
    }
}

pub fn init_serial() {}

pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    let _ = Console.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
