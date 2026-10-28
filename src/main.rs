mod accounts;
mod google_migration;
mod qr;
mod workflow;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "google-otp-qr-converter",
    version,
    about = "Offline Google Authenticator QR import/export"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decode one or more Google Authenticator/otpauth QR images to JSON or CSV.
    Decode {
        /// QR image path. Repeat -i for every migration QR; pass the final-index QR last.
        #[arg(short, long, required = true)]
        input: Vec<PathBuf>,
        /// Output data file.
        #[arg(short, long)]
        output: PathBuf,
        /// Output serialization format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Generate migration or individual otpauth QR code(s) from JSON/CSV.
    Encode {
        /// JSON array or CSV file containing OTP accounts.
        #[arg(short, long)]
        input: PathBuf,
        /// Directory to which QR PNG files are written.
        #[arg(short, long)]
        output_dir: PathBuf,
        /// Output protocol. Defaults to Authenticator migration format.
        #[arg(long, value_enum, default_value_t = EncodeFormat::Migration)]
        format: EncodeFormat,
        /// Maximum accounts per migration QR; only used with --format migration (max 10).
        #[arg(long, default_value_t = 10)]
        accounts_per_qr: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EncodeFormat {
    Migration,
    Otpauth,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Decode {
            input,
            output,
            format,
        } => {
            let account_format = match format {
                OutputFormat::Json => accounts::AccountFormat::Json,
                OutputFormat::Csv => accounts::AccountFormat::Csv,
            };
            let count = workflow::decode_images(&input, &output, account_format)?;
            println!("Decoded {} account(s) into {}", count, output.display());
        }
        Command::Encode {
            input,
            output_dir,
            format,
            accounts_per_qr,
        } => {
            let count = workflow::encode_file(&input, &output_dir, format, accounts_per_qr)?;
            let kind = match format {
                EncodeFormat::Migration => "migration",
                EncodeFormat::Otpauth => "individual otpauth",
            };
            println!(
                "Wrote {} {} QR code(s) to {}",
                count,
                kind,
                output_dir.display()
            );
        }
    }

    Ok(())
}
