use crate::accounts::{self, AccountFormat, OtpAccount};
use crate::{EncodeFormat, google_migration, qr};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Decode pipeline: image -> QR text -> OTP accounts -> JSON/CSV.
///
/// Migration images may arrive in any order, and a missing image is omitted.
/// A repeated batch index keeps the first image and drops the later ones.
/// Payloads with no batch index are all kept, after the indexed accounts.
pub fn decode_images(inputs: &[PathBuf], output: &Path, format: AccountFormat) -> Result<usize> {
    let mut decoded = Vec::new();
    let mut indexed: BTreeMap<i32, Vec<OtpAccount>> = BTreeMap::new();
    let mut unindexed = Vec::new();
    let mut migration_started = false;

    for path in inputs {
        let qr_texts = qr::scan_image(path)
            .with_context(|| format!("failed to scan image {}", path.display()))?;
        for text in qr_texts {
            if text.starts_with("otpauth-migration://") {
                let (decoded_accounts, batch) = google_migration::decode_uri(&text)?;
                if !migration_started {
                    decoded.push(Decoded::Migration);
                    migration_started = true;
                }
                match batch.batch_index {
                    Some(index) if !indexed.contains_key(&index) => {
                        indexed.insert(index, decoded_accounts);
                    }
                    Some(_) => {}
                    None => unindexed.extend(decoded_accounts),
                }
            } else if text.starts_with("otpauth://") {
                decoded.push(Decoded::Account(accounts::decode_otpauth_uri(&text)?));
            } else {
                anyhow::bail!("QR code is not an otpauth or Google migration QR");
            }
        }
    }

    let mut migration_accounts = indexed.into_values().flatten().collect::<Vec<_>>();
    migration_accounts.append(&mut unindexed);
    let mut accounts = Vec::new();
    for item in decoded {
        match item {
            Decoded::Account(account) => accounts.push(account),
            Decoded::Migration => accounts.append(&mut migration_accounts),
        }
    }
    if accounts.is_empty() {
        anyhow::bail!("no OTP accounts found in the supplied QR images");
    }
    accounts::write_accounts(output, format, &accounts)?;
    Ok(accounts.len())
}

enum Decoded {
    Account(OtpAccount),
    Migration,
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
    let uris = match format {
        EncodeFormat::Migration => google_migration::encode_uris(&accounts, accounts_per_qr)?,
        EncodeFormat::Otpauth => accounts::encode_otpauth_uris(&accounts)?,
    };
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("cannot create output directory {}", output_dir.display()))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn names_from(inputs: &[PathBuf], output: &Path) -> Vec<String> {
        decode_images(inputs, output, AccountFormat::Json).unwrap();
        accounts::read_accounts(output)
            .unwrap()
            .into_iter()
            .map(|account| account.name)
            .collect()
    }

    #[test]
    fn migration_scan_keeps_partial_reordered_and_unindexed_images() {
        let dir = std::env::temp_dir().join(format!(
            "google-otp-qr-converter-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, uri: &str| {
            let path = dir.join(format!("{name}.png"));
            qr::write_png(uri, &path).unwrap();
            path
        };
        let first = write(
            "first",
            &google_migration::account_migration_uri("first", Some(0), Some(3)),
        );
        let second = write(
            "second",
            &google_migration::account_migration_uri("second", Some(0), Some(9)),
        );
        let third = write(
            "third",
            &google_migration::account_migration_uri("third", Some(2), Some(3)),
        );
        let loose_a = write(
            "loose-a",
            &google_migration::account_migration_uri("loose-a", None, None),
        );
        let loose_b = write(
            "loose-b",
            &google_migration::account_migration_uri("loose-b", None, None),
        );

        // Index 2 before either index 0, index 1 missing, index 0 repeated.
        // `second` is the first index 0, so `first` is dropped. Images with
        // no index are all kept after the indexed accounts.
        let names = names_from(
            &[third.clone(), second, loose_a, first.clone(), loose_b],
            &dir.join("accounts.json"),
        );
        assert_eq!(names, vec!["second", "third", "loose-a", "loose-b"]);

        let partial = names_from(&[third, first], &dir.join("partial.json"));
        assert_eq!(partial, vec!["first", "third"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
