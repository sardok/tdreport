use std::env;

use anyhow::{Context, Result};
use log::error;

fn try_main() -> Result<()> {
    let filename = env::args_os()
        .nth(1)
        .context("usage: kvm-runner <tdvf-image>")?;
    kvm_runner::run(filename)
}

fn main() {
    env_logger::init();

    if let Err(error) = try_main() {
        error!("[-] {error:#}");
        error!("============================================================");
        std::process::exit(1);
    }
}
