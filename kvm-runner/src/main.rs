use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::error;

#[derive(Parser)]
#[command(version, about = "Run a TDVF payload in a minimal Intel TDX VM")]
struct Cli {
    #[arg(value_name = "TDVF_IMAGE")]
    filename: PathBuf,
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();
    kvm_runner::run(cli.filename)
}

fn main() {
    env_logger::init();

    if let Err(error) = try_main() {
        error!("[-] {error:#}");
        error!("============================================================");
        std::process::exit(1);
    }
}
