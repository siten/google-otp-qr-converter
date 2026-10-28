use crate::accounts::{self, AccountFormat, OtpAccount};
use crate::{EncodeFormat, google_migration, qr};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Decode pipeline: image -> QR text -> OTP accounts -> JSON/CSV.
pub fn decode_images(inputs: &[PathBuf], output: &Path, format: AccountFormat) -> Result<usize> {
    let mut accounts = Vec::new();
    // Authenticator 7.2 has no batch ID. It accepts one batch at a time and
    // identifies its QR files by their shared size and unique zero-based index.
    let mut migration_batch_size = None;
    let mut migration_indexes = HashSet::new();

    for path in inputs {
        let qr_texts = qr::scan_image(path)
            .with_context(|| format!("failed to scan image {}", path.display()))?;
        for text in qr_texts {
            if text.starts_with("otpauth-migration://") {
                let (mut decoded, batch) = google_migration::decode_uri(&text)?;
                if let Some(expected_size) = migration_batch_size {
                    if expected_size != batch.batch_size {
                        anyhow::bail!("migration QR batch sizes do not match");
                    }
                } else {
                    migration_batch_size = Some(batch.batch_size);
                }

                let final_index = batch.batch_size - 1;
                if batch.batch_index == final_index
                    && migration_indexes.len() != final_index as usize
                {
                    anyhow::bail!(
                        "final-index migration QR arrived before the other batch QR codes"
                    );
                }
                if !migration_indexes.insert(batch.batch_index) {
                    anyhow::bail!("duplicate migration QR batch index {}", batch.batch_index);
                }
                accounts.append(&mut decoded);
            } else if text.starts_with("otpauth://") {
                accounts.push(accounts::decode_otpauth_uri(&text)?);
            } else {
                anyhow::bail!("QR code is not an otpauth or Google migration QR");
            }
        }
    }

    if accounts.is_empty() {
        anyhow::bail!("no OTP accounts found in the supplied QR images");
    }
    if let Some(batch_size) = migration_batch_size
        && migration_indexes.len() != batch_size as usize
    {
        anyhow::bail!(
            "incomplete migration batch: scanned {} of {batch_size} QR codes",
            migration_indexes.len()
        );
    }
    validate_accounts(&accounts)?;
    accounts::write_accounts(output, format, &accounts)?;
    Ok(accounts.len())
}

/// Encode pipeline: JSON/CSV -> OTP accounts -> URI/protobuf text -> QR PNG.
pub fn encode_file(
    input: &Path,
    output_dir: &Path,
    format: EncodeFormat,
    accounts_per_qr: usize,
) -> Result<usize> {
    let accounts = accounts::read_accounts(input)?;
    if accounts.is_empty() {
        anyhow::bail!("input contains no OTP accounts");
    }
    validate_accounts(&accounts)?;
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("cannot create output directory {}", output_dir.display()))?;

    let uris = match format {
        EncodeFormat::Migration => google_migration::encode_uris(&accounts, accounts_per_qr)?,
        EncodeFormat::Otpauth => accounts::encode_otpauth_uris(&accounts)?,
    };

    for (index, uri) in uris.iter().enumerate() {
        let filename = match format {
            EncodeFormat::Migration => {
                format!("migration-{:03}-of-{:03}.png", index + 1, uris.len())
            }
            EncodeFormat::Otpauth => format!("account-{:03}.png", index + 1),
        };
        let path = output_dir.join(filename);
        qr::write_png(uri, &path).with_context(|| format!("could not write {}", path.display()))?;
    }
    Ok(uris.len())
}

fn validate_accounts(accounts: &[OtpAccount]) -> Result<()> {
    for account in accounts {
        account.validate()?;
    }
    Ok(())
}
