use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error};

#[derive(Parser)]
#[command(
    version,
    about = "Retrieve an Intel TDX TDREPORT using a minimal KVM guest"
)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();
    let report = tdreport::tdreport()?;
    let parsed_report = tdx_tdcall::tdreport::TdxReport::read_from_bytes(&report)
        .context("failed to parse the 1024-byte TDREPORT")?;

    println!("============================================================");
    println!("                  INTEL TDX TDREPORT");
    println!("============================================================");
    println!("{parsed_report}");
    println!("============================================================");

    if let Some(output) = cli.output {
        std::fs::write(&output, &report)
            .with_context(|| format!("failed to write TDREPORT to {}", output.display()))?;
        debug!("Wrote 1024-byte TDREPORT to {}", output.display());
    }
    Ok(())
}

fn main() {
    env_logger::init();

    if let Err(error) = try_main() {
        error!("{error:#}");
        std::process::exit(1);
    }
}
