//! Google Authenticator migration wire format.
//!
//! Keep protobuf definitions and the `otpauth-migration://` wrapper isolated here.
//! If Google changes its payload schema, this is the protocol adapter to update;
//! image scanning, account files, and workflow orchestration stay unchanged.

use crate::accounts::{OtpAccount, OtpType, validate_for_authenticator_qr};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::{Enumeration, Message};
use url::Url;

/// Authenticator 7.2's export code places at most ten OTPs in each QR.
pub const MAX_ACCOUNTS_PER_QR: usize = 10;

#[derive(Clone, PartialEq, Message)]
pub struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    pub otp_parameters: Vec<OtpParameters>,
    #[prost(enumeration = "PayloadVersion", optional, tag = "2")]
    pub version: Option<i32>,
    #[prost(int32, tag = "3")]
    pub batch_size: i32,
    #[prost(int32, tag = "4")]
    pub batch_index: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct OtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    pub secret: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub issuer: String,
    #[prost(enumeration = "Algorithm", tag = "4")]
    pub algorithm: i32,
    #[prost(enumeration = "DigitCount", tag = "5")]
    pub digits: i32,
    #[prost(enumeration = "MigrationOtpType", tag = "6")]
    pub r#type: i32,
    #[prost(int64, tag = "7")]
    pub counter: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum PayloadVersion {
    Unspecified = 0,
    V1 = 1,
    V2 = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum Algorithm {
    Unspecified = 0,
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum DigitCount {
    Unspecified = 0,
    Six = 1,
    Eight = 2,
    Seven = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum MigrationOtpType {
    Unspecified = 0,
    Hotp = 1,
    Totp = 2,
}

#[derive(Debug, Clone, Copy)]
pub struct BatchInfo {
    pub batch_size: i32,
    pub batch_index: i32,
}

/// Decode URI text into common account records. No image or file handling here.
pub fn decode_uri(text: &str) -> Result<(Vec<OtpAccount>, BatchInfo)> {
    let url = Url::parse(text).context("invalid otpauth-migration URI")?;
    if url.scheme() != "otpauth-migration" {
        bail!("not a Google Authenticator migration URI");
    }
    if url.host_str() != Some("offline") {
        bail!("Google migration URI authority must be offline");
    }
    let encoded_data = url
        .query_pairs()
        .find_map(|(key, value)| (key == "data").then(|| value.into_owned()))
        .context("migration URI is missing the data parameter")?;
    let bytes = STANDARD
        .decode(encoded_data.as_bytes())
        .context("migration URI data is not valid Base64")?;
    let payload = MigrationPayload::decode(bytes.as_slice())
        .context("migration data is not a valid Google Authenticator payload")?;

    // Authenticator 7.2 exports version 2 and its importer accepts <= 2.
    let version = payload
        .version
        .context("migration payload is missing its version field")?;
    if !(0..=2).contains(&version) {
        bail!("unsupported Google migration payload version {version}");
    }

    let accounts = payload
        .otp_parameters
        .into_iter()
        .map(account_from_parameter)
        .collect::<Result<Vec<_>>>()?;
    let batch = BatchInfo {
        batch_size: payload.batch_size,
        batch_index: payload.batch_index,
    };
    validate_batch(batch)?;
    Ok((accounts, batch))
}

/// Encode records as one or more `otpauth-migration://` URI strings.
/// QR image creation deliberately remains in `qr`/`workflow`.
pub fn encode_uris(accounts: &[OtpAccount], accounts_per_qr: usize) -> Result<Vec<String>> {
    if accounts.is_empty() {
        bail!("cannot create migration data without accounts");
    }
    if accounts_per_qr == 0 {
        bail!("accounts-per-qr must be at least 1");
    }
    if accounts_per_qr > MAX_ACCOUNTS_PER_QR {
        bail!("Google Authenticator 7.2 uses at most {MAX_ACCOUNTS_PER_QR} accounts per QR");
    }

    // Validate/convert every record before producing any QR files in the caller.
    let parameters = accounts
        .iter()
        .map(parameter_from_account)
        .collect::<Result<Vec<_>>>()?;
    let chunks: Vec<&[OtpParameters]> = parameters.chunks(accounts_per_qr).collect();
    let batch_size = i32::try_from(chunks.len()).context("too many migration QR batches")?;
    let mut uris = Vec::with_capacity(chunks.len());

    for (index, chunk) in chunks.iter().enumerate() {
        let payload = MigrationPayload {
            otp_parameters: chunk.to_vec(),
            version: Some(PayloadVersion::V2 as i32),
            batch_size,
            batch_index: i32::try_from(index).context("too many migration QR batches")?,
        };
        let mut bytes = Vec::with_capacity(payload.encoded_len());
        payload
            .encode(&mut bytes)
            .context("failed to encode migration protobuf")?;
        let mut uri = Url::parse("otpauth-migration://offline/")?;
        uri.query_pairs_mut()
            .append_pair("data", &STANDARD.encode(bytes));
        uris.push(uri.into());
    }
    Ok(uris)
}

fn account_from_parameter(parameter: OtpParameters) -> Result<OtpAccount> {
    let algorithm = match Algorithm::try_from(parameter.algorithm)
        .context("unknown algorithm value in migration data")?
    {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
        Algorithm::Unspecified => bail!("migration data does not specify an OTP algorithm"),
    };
    let digits = match DigitCount::try_from(parameter.digits)
        .context("unknown digit-count value in migration data")?
    {
        DigitCount::Six => 6,
        DigitCount::Eight => 8,
        DigitCount::Seven => 7,
        DigitCount::Unspecified => bail!("migration data does not specify OTP digits"),
    };
    let otp_type = match MigrationOtpType::try_from(parameter.r#type)
        .context("unknown OTP type in migration data")?
    {
        MigrationOtpType::Totp => OtpType::Totp,
        MigrationOtpType::Hotp => OtpType::Hotp,
        MigrationOtpType::Unspecified => bail!("migration data does not specify an OTP type"),
    };
    let counter = u64::try_from(parameter.counter)
        .context("migration payload contains a negative OTP counter")?;

    Ok(OtpAccount {
        issuer: parameter.issuer,
        name: parameter.name,
        secret: data_encoding::BASE32_NOPAD.encode(&parameter.secret),
        otp_type,
        algorithm: algorithm.to_owned(),
        digits,
        period: 30,
        counter,
    })
}

fn parameter_from_account(account: &OtpAccount) -> Result<OtpParameters> {
    validate_for_authenticator_qr(account)?;
    let algorithm = match account.algorithm.to_ascii_uppercase().as_str() {
        "SHA1" => Algorithm::Sha1,
        "SHA256" => Algorithm::Sha256,
        "SHA512" => Algorithm::Sha512,
        _ => bail!("unsupported OTP algorithm"),
    };
    let digits = match account.digits {
        6 => DigitCount::Six,
        7 => DigitCount::Seven,
        8 => DigitCount::Eight,
        _ => bail!("unsupported OTP digit count"),
    };
    let otp_type = match account.otp_type {
        OtpType::Totp => MigrationOtpType::Totp,
        OtpType::Hotp => MigrationOtpType::Hotp,
    };
    let counter = match account.otp_type {
        OtpType::Totp => 0,
        OtpType::Hotp => i64::try_from(account.counter)
            .context("HOTP counter is too large for Google migration format")?,
    };

    Ok(OtpParameters {
        secret: account.secret_bytes()?,
        name: account.name.clone(),
        issuer: account.issuer.clone(),
        algorithm: algorithm as i32,
        digits: digits as i32,
        r#type: otp_type as i32,
        counter,
    })
}

fn validate_batch(batch: BatchInfo) -> Result<()> {
    if batch.batch_size < 1 || batch.batch_index < 0 || batch.batch_index >= batch.batch_size {
        bail!("migration QR has invalid batch metadata");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OtpAccount {
        OtpAccount {
            issuer: "Example".into(),
            name: "alice@example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            otp_type: OtpType::Totp,
            algorithm: "SHA1".into(),
            digits: 7,
            period: 30,
            counter: 0,
        }
    }

    #[test]
    fn migration_uri_round_trip_preserves_account_and_batch_metadata() {
        let source = sample();
        let uris = encode_uris(std::slice::from_ref(&source), MAX_ACCOUNTS_PER_QR).unwrap();
        let (accounts, batch) = decode_uri(&uris[0]).unwrap();
        assert_eq!(accounts, vec![source]);
        assert_eq!(batch.batch_size, 1);
        assert_eq!(batch.batch_index, 0);
        let encoded = Url::parse(&uris[0]).unwrap();
        let payload_bytes = STANDARD
            .decode(
                encoded
                    .query_pairs()
                    .find(|(key, _)| key == "data")
                    .unwrap()
                    .1
                    .as_bytes(),
            )
            .unwrap();
        let payload = MigrationPayload::decode(payload_bytes.as_slice()).unwrap();
        assert_eq!(payload.version, Some(PayloadVersion::V2 as i32));
    }

    #[test]
    fn parser_rejects_payload_without_explicit_version() {
        let payload = MigrationPayload {
            otp_parameters: Vec::new(),
            version: None,
            batch_size: 1,
            batch_index: 0,
        };
        let mut bytes = Vec::new();
        payload.encode(&mut bytes).unwrap();
        let mut uri = Url::parse("otpauth-migration://offline/").unwrap();
        uri.query_pairs_mut()
            .append_pair("data", &STANDARD.encode(bytes));

        assert!(decode_uri(uri.as_str()).is_err());
    }

    #[test]
    fn ten_account_limit_and_batch_indexes_match_authenticator_export() {
        let accounts = vec![sample(); MAX_ACCOUNTS_PER_QR + 1];
        let uris = encode_uris(&accounts, MAX_ACCOUNTS_PER_QR).unwrap();
        assert_eq!(uris.len(), 2);

        let (first_accounts, first_batch) = decode_uri(&uris[0]).unwrap();
        assert_eq!(first_accounts.len(), 10);
        assert_eq!(first_batch.batch_size, 2);
        assert_eq!(first_batch.batch_index, 0);

        let (second_accounts, second_batch) = decode_uri(&uris[1]).unwrap();
        assert_eq!(second_accounts.len(), 1);
        assert_eq!(second_batch.batch_size, 2);
        assert_eq!(second_batch.batch_index, 1);

        assert!(encode_uris(&accounts, MAX_ACCOUNTS_PER_QR + 1).is_err());
    }
}
