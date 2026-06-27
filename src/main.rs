//! dotprot — lock up .env files (and anything in .prot) inside a 1Password vault.

mod commands;
mod op;
mod prot;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "dotprot",
    version,
    about = "Lock up .env files (and anything in .prot) inside a 1Password vault.",
    long_about = "dotprot stores the files listed in .prot as documents in a 1Password \
                  vault, verifies each upload, then removes them from disk. Run it again \
                  to restore them.\n\n\
                  With no subcommand it toggles: it locks if the protected files are \
                  present, or unlocks if they're missing."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Upload and verify, but keep the original files on disk (don't delete).
    /// Applies to the bare toggle when it locks.
    #[arg(long, global = true)]
    keep: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create the .prot vault in 1Password (one-time).
    Setup,
    /// Force lock: upload, verify, then delete from disk.
    Lock,
    /// Force unlock: restore files from 1Password.
    Unlock,
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cwd: PathBuf = std::env::current_dir()?;

    match cli.command {
        None => commands::toggle(&cwd, cli.keep),
        Some(Command::Setup) => commands::setup(),
        Some(Command::Lock) => commands::lock(&cwd, cli.keep),
        Some(Command::Unlock) => commands::unlock(&cwd),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Print the top-level message (and any chained context) without a
            // backtrace — these are user-facing errors.
            eprintln!("dotprot: {e}");
            for cause in e.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            ExitCode::FAILURE
        }
    }
}
