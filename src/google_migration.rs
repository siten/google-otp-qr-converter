//! Google Authenticator migration protocol, pinned to the installed 7.2 APK.
//!
//! Package `com.google.android.apps.authenticator2`, versionName 7.2,
//! versionCode 7002011. The schema below is the protobuf descriptor embedded
//! in that APK (`bmu` payload, `bmv` parameters), and the numeric maps are the
//! ones `bpc.d` / `bpc.a` apply. Image scanning, JSON/CSV, and QR pixels do
//! not live here.
//!
//! ```text
//! message MigrationPayload {            // bmu, fields 1..=4 only (no batch_id)
//!   repeated OtpParameters otp_parameters = 1;
//!   optional int32 version = 2;         // exporter writes 2; scan does not require it
//!   optional int32 batch_size = 3;      // scan does not require a complete batch
//!   optional int32 batch_index = 4;     // absent is not index 0
//! }
//! message OtpParameters {               // bmv
//!   optional bytes secret = 1;          // required by the scan
//!   optional string name = 2;           // required by the scan
//!   optional string issuer = 3;
//!   optional Algorithm algorithm = 4;   // 1 SHA1, 2 SHA256, 3 SHA512; absent stays empty
//!   optional DigitCount digits = 5;     // 1 six, 2 eight, 3 seven; absent stays empty
//!   optional OtpType type = 6;          // required and non-zero; 1 hotp, 2 totp;
//!                                       // any other present value is kept
//!   optional uint64 counter = 7;        // kept when present, including for totp
//!   optional string unique_id = 8;      // exporter writes it; absent stays empty
//! }
//! ```
//!
//! To support a newer Authenticator build, update [`AUTHENTICATOR_7_2`] and the
//! `*_wire` maps. Leave callers on [`OtpAccount`] and [`BatchInfo`].

use crate::accounts::{self, OtpAccount, OtpType, validate_for_authenticator_qr};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use prost::{Enumeration, Message};
use url::Url;

/// Rules read from Authenticator 7.2. Encode uses `exported_version` and
/// `max_accounts_per_qr`. The version range and default batch size are
/// documentation of that APK; scan and encode do not read them.
#[derive(Clone, Copy, Debug)]
pub struct MigrationProfile {
    pub name: &'static str,
    pub version_code: i32,
    /// Value written into `MigrationPayload.version`.
    pub exported_version: i32,
    /// Documentation only. 7.2 accepts payload versions `0..=2`. Scan does not
    /// apply this bound.
    pub min_readable_version: i32,
    /// Documentation only. See [`Self::min_readable_version`].
    pub max_readable_version: i32,
    pub max_accounts_per_qr: usize,
    /// Documentation only. Proto2 default of batch size (`bmu.e` initializes
    /// to 1). Scan leaves a missing `batch_size` missing.
    pub default_batch_size: i32,
}

pub const AUTHENTICATOR_7_2: MigrationProfile = MigrationProfile {
    name: "Google Authenticator 7.2",
    version_code: 7_002_011,
    exported_version: 2,
    min_readable_version: 0,
    max_readable_version: 2,
    max_accounts_per_qr: 10,
    default_batch_size: 1,
};

const ACTIVE: MigrationProfile = AUTHENTICATOR_7_2;

// `min_readable_version`, `max_readable_version`, and `default_batch_size` are
// documentation metadata. These checks only keep those recorded facts consistent.
const _: () = {
    assert!(AUTHENTICATOR_7_2.min_readable_version <= AUTHENTICATOR_7_2.exported_version);
    assert!(AUTHENTICATOR_7_2.exported_version <= AUTHENTICATOR_7_2.max_readable_version);
    assert!(AUTHENTICATOR_7_2.default_batch_size >= 1);
};

impl MigrationProfile {
    fn label(self) -> String {
        format!("{} versionCode {}", self.name, self.version_code)
    }
}

/// Android `Base64.NO_WRAP` on export and `Base64.DEFAULT` on import: standard
/// alphabet, padding emitted, padding and ASCII whitespace accepted on import.
const MIGRATION_B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Clone, PartialEq, Message)]
pub struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    pub otp_parameters: Vec<OtpParameters>,
    #[prost(int32, optional, tag = "2")]
    pub version: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    pub batch_size: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    pub batch_index: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    pub secret: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub issuer: String,
    #[prost(enumeration = "Algorithm", optional, tag = "4")]
    pub algorithm: Option<i32>,
    #[prost(enumeration = "DigitCount", optional, tag = "5")]
    pub digits: Option<i32>,
    #[prost(enumeration = "MigrationOtpType", optional, tag = "6")]
    pub r#type: Option<i32>,
    /// `optional uint64`. `Some(0)` is written for HOTP so the field is present,
    /// matching the exporter's has-bit. TOTP leaves this `None`.
    #[prost(uint64, optional, tag = "7")]
    pub counter: Option<u64>,
    #[prost(string, tag = "8")]
    pub unique_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum Algorithm {
    Unspecified = 0,
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

/// Wire values from `bmv.g`. Seven was added after the original six/eight pair,
/// which is why 8 digits is 2 and 7 digits is 3.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchInfo {
    /// `None` when the payload did not contain field 3.
    pub batch_size: Option<i32>,
    /// `None` when the payload did not contain field 4. That is not index 0.
    pub batch_index: Option<i32>,
}

/// Decode one `otpauth-migration://` URI. No image or file handling here.
pub fn decode_uri(text: &str) -> Result<(Vec<OtpAccount>, BatchInfo)> {
    let url = Url::parse(text).context("invalid otpauth-migration URI")?;
    if url.scheme() != "otpauth-migration" {
        bail!("not a Google Authenticator migration URI");
    }
    accounts::reject_authority_extras(&url)?;
    if url.host_str() != Some("offline") {
        bail!("Google migration URI authority must be offline");
    }
    let encoded_data = migration_data_parameter(&url)?;
    let bytes = decode_migration_base64(&encoded_data)?;
    let payload = MigrationPayload::decode(bytes.as_slice())
        .context("migration data is not a valid Google Authenticator payload")?;
    let batch = BatchInfo {
        batch_size: payload.batch_size,
        batch_index: payload.batch_index,
    };
    let accounts = payload
        .otp_parameters
        .into_iter()
        .map(account_from_parameter)
        .collect::<Result<Vec<_>>>()?;
    Ok((accounts, batch))
}

/// Encode records as one or more `otpauth-migration://offline?data=` URIs.
pub fn encode_uris(accounts: &[OtpAccount], accounts_per_qr: usize) -> Result<Vec<String>> {
    if accounts.is_empty() {
        bail!("cannot create migration data without accounts");
    }
    if accounts_per_qr == 0 {
        bail!("accounts-per-qr must be at least 1");
    }
    if accounts_per_qr > ACTIVE.max_accounts_per_qr {
        bail!(
            "{} puts at most {} accounts in each QR",
            ACTIVE.label(),
            ACTIVE.max_accounts_per_qr
        );
    }

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
            version: Some(ACTIVE.exported_version),
            batch_size: Some(batch_size),
            batch_index: Some(i32::try_from(index).context("too many migration QR batches")?),
        };
        let mut bytes = Vec::with_capacity(payload.encoded_len());
        payload
            .encode(&mut bytes)
            .context("failed to encode migration protobuf")?;
        uris.push(migration_uri(&bytes));
    }
    Ok(uris)
}

fn account_from_parameter(parameter: OtpParameters) -> Result<OtpAccount> {
    let otp_type = otp_type_from_wire(parameter.r#type)?;
    let account = OtpAccount {
        issuer: parameter.issuer,
        name: parameter.name,
        secret: data_encoding::BASE32_NOPAD.encode(&parameter.secret),
        otp_type,
        algorithm: algorithm_from_wire(parameter.algorithm),
        digits: digits_from_wire(parameter.digits),
        // Migration payloads have no period field.
        period: None,
        counter: parameter.counter,
        unique_id: parameter.unique_id,
    };
    accounts::require_scanned_account(&account)?;
    Ok(account)
}

fn parameter_from_account(account: &OtpAccount) -> Result<OtpParameters> {
    validate_for_authenticator_qr(account)?;
    let counter = match account.otp_type {
        // Authenticator's exporter omits the TOTP counter.
        OtpType::Totp => None,
        OtpType::Hotp => Some(account.counter.context("HOTP counter is empty")?),
        OtpType::Other(value) => bail!("OTP type {value} cannot be written as an Authenticator QR"),
    };
    Ok(OtpParameters {
        secret: account.secret_bytes()?,
        name: account.name.clone(),
        issuer: account.issuer.clone(),
        algorithm: Some(algorithm_to_wire(&account.algorithm)?),
        digits: Some(digits_to_wire(
            account.digits.context("OTP digits are empty")?,
        )?),
        r#type: Some(otp_type_to_wire(account.otp_type)?),
        counter,
        unique_id: account.unique_id.clone(),
    })
}

/// Known values become SHA1/SHA256/SHA512. An unknown present value is kept
/// as its decimal wire number. Absence and wire 0 stay empty.
fn algorithm_from_wire(value: Option<i32>) -> String {
    match value {
        Some(value) if value == Algorithm::Sha1 as i32 => {
            accounts::OtpAlgorithm::Sha1.as_str().to_owned()
        }
        Some(value) if value == Algorithm::Sha256 as i32 => {
            accounts::OtpAlgorithm::Sha256.as_str().to_owned()
        }
        Some(value) if value == Algorithm::Sha512 as i32 => {
            accounts::OtpAlgorithm::Sha512.as_str().to_owned()
        }
        Some(value) if value != Algorithm::Unspecified as i32 => value.to_string(),
        _ => String::new(),
    }
}

fn algorithm_to_wire(name: &str) -> Result<i32> {
    let wire = match accounts::canonical_algorithm(name)? {
        accounts::OtpAlgorithm::Sha1 => Algorithm::Sha1,
        accounts::OtpAlgorithm::Sha256 => Algorithm::Sha256,
        accounts::OtpAlgorithm::Sha512 => Algorithm::Sha512,
    };
    Ok(wire as i32)
}

/// Wire 1/2/3 become 6/8/7. Absence and wire 0 stay empty. Any other present
/// value is kept as that integer so the scan does not drop it.
fn digits_from_wire(value: Option<i32>) -> Option<u32> {
    let value = value.filter(|value| *value != DigitCount::Unspecified as i32)?;
    match DigitCount::try_from(value) {
        Ok(DigitCount::Six) => Some(6),
        Ok(DigitCount::Eight) => Some(8),
        Ok(DigitCount::Seven) => Some(7),
        Ok(DigitCount::Unspecified) | Err(_) => u32::try_from(value).ok(),
    }
}

fn digits_to_wire(digits: u32) -> Result<i32> {
    let wire = match digits {
        6 => DigitCount::Six,
        8 => DigitCount::Eight,
        7 => DigitCount::Seven,
        other => bail!(
            "unsupported OTP digit count {other}; Authenticator 7.2 exports 6, 7, or 8. Extend digits_to_wire when it exports another count"
        ),
    };
    Ok(wire as i32)
}

fn otp_type_from_wire(value: Option<i32>) -> Result<OtpType> {
    match value {
        Some(value) if value == MigrationOtpType::Hotp as i32 => Ok(OtpType::Hotp),
        Some(value) if value == MigrationOtpType::Totp as i32 => Ok(OtpType::Totp),
        Some(value) if value != MigrationOtpType::Unspecified as i32 => Ok(OtpType::Other(value)),
        _ => bail!("OTP type must not be empty"),
    }
}

fn otp_type_to_wire(otp_type: OtpType) -> Result<i32> {
    match otp_type {
        OtpType::Hotp => Ok(MigrationOtpType::Hotp as i32),
        OtpType::Totp => Ok(MigrationOtpType::Totp as i32),
        OtpType::Other(value) => {
            bail!("OTP type {value} cannot be written as an Authenticator QR")
        }
    }
}

/// `Uri.getQueryParameter("data")` plus `Base64.decode(..., DEFAULT)`.
/// `+` is kept as plus. Official exports percent-encode it as `%2B`.
fn migration_data_parameter(url: &Url) -> Result<String> {
    accounts::first_query_value(
        url.query()
            .context("migration URI is missing the data parameter")?,
        "data",
    )
    .context("migration URI is missing the data parameter")
}

fn decode_migration_base64(data: &str) -> Result<Vec<u8>> {
    let filtered: String = data
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '\t' | '\n' | '\r'))
        .collect();
    MIGRATION_B64
        .decode(filtered.as_bytes())
        .context("migration URI data is not valid Base64")
}

/// Build one migration URI for scan tests. `batch_index: None` stays unindexed.
#[cfg(test)]
pub(crate) fn account_migration_uri(
    name: &str,
    batch_index: Option<i32>,
    batch_size: Option<i32>,
) -> String {
    let account = OtpAccount {
        issuer: String::new(),
        name: name.to_owned(),
        secret: "JBSWY3DPEHPK3PXP".into(),
        otp_type: OtpType::Totp,
        algorithm: "SHA1".into(),
        digits: Some(6),
        period: Some(30),
        counter: None,
        unique_id: String::new(),
    };
    let payload = MigrationPayload {
        otp_parameters: vec![parameter_from_account(&account).expect("test account")],
        version: Some(ACTIVE.exported_version),
        batch_size,
        batch_index,
    };
    let mut bytes = Vec::new();
    payload.encode(&mut bytes).expect("test payload");
    migration_uri(&bytes)
}

/// `otpauth-migration://offline?data=` with `Base64.NO_WRAP` and `Uri.encode`.
fn migration_uri(payload: &[u8]) -> String {
    let encoded = MIGRATION_B64.encode(payload);
    let data = accounts::encode_query_component(&encoded);
    format!("otpauth-migration://offline?data={data}")
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
            digits: Some(7),
            period: Some(30),
            counter: Some(0),
            unique_id: String::new(),
        }
    }

    fn payload_uri(payload: MigrationPayload) -> String {
        let mut bytes = Vec::new();
        payload.encode(&mut bytes).unwrap();
        migration_uri(&bytes)
    }

    #[test]
    fn profile_is_the_installed_authenticator_build() {
        assert_eq!(AUTHENTICATOR_7_2.version_code, 7_002_011);
        assert_eq!(AUTHENTICATOR_7_2.exported_version, 2);
        assert_eq!(AUTHENTICATOR_7_2.max_accounts_per_qr, 10);
    }

    #[test]
    fn migration_uri_round_trip_preserves_account_batch_and_wrapper() {
        let mut source = sample();
        source.unique_id = "abcd1719000000000".into();
        let uris = encode_uris(std::slice::from_ref(&source), ACTIVE.max_accounts_per_qr).unwrap();
        assert!(uris[0].starts_with("otpauth-migration://offline?data="));
        let data = uris[0].split_once("?data=").unwrap().1;
        let plain = data
            .replace("%2B", "")
            .replace("%2F", "")
            .replace("%3D", "");
        assert!(!plain.contains('+') && !plain.contains('/') && !plain.contains('='));

        let (accounts, batch) = decode_uri(&uris[0]).unwrap();
        assert_eq!(accounts[0].name, source.name);
        assert_eq!(accounts[0].secret, source.secret);
        assert_eq!(accounts[0].otp_type, source.otp_type);
        assert_eq!(accounts[0].algorithm, source.algorithm);
        assert_eq!(accounts[0].digits, source.digits);
        assert_eq!(accounts[0].unique_id, source.unique_id);
        assert_eq!(accounts[0].issuer, source.issuer);
        assert_eq!(accounts[0].period, None);
        assert_eq!(accounts[0].counter, None);
        assert_eq!(batch.batch_size, Some(1));
        assert_eq!(batch.batch_index, Some(0));

        let encoded = Url::parse(&uris[0]).unwrap();
        let payload = MigrationPayload::decode(
            decode_migration_base64(&migration_data_parameter(&encoded).unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        assert_eq!(payload.version, Some(ACTIVE.exported_version));
        assert_eq!(
            payload.otp_parameters[0].digits,
            Some(DigitCount::Seven as i32)
        );
        assert!(payload.otp_parameters[0].counter.is_none());
    }

    #[test]
    fn hotp_counter_zero_is_present_on_the_wire() {
        let mut account = sample();
        account.otp_type = OtpType::Hotp;
        account.counter = Some(0);
        let uris = encode_uris(std::slice::from_ref(&account), 1).unwrap();
        let (decoded, _) = decode_uri(&uris[0]).unwrap();
        assert_eq!(decoded[0].counter, Some(0));
        assert_eq!(decoded[0].otp_type, OtpType::Hotp);

        let payload = MigrationPayload::decode(
            decode_migration_base64(
                &migration_data_parameter(&Url::parse(&uris[0]).unwrap()).unwrap(),
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        assert_eq!(payload.otp_parameters[0].counter, Some(0));
        assert_eq!(
            payload.otp_parameters[0].r#type,
            Some(MigrationOtpType::Hotp as i32)
        );
    }

    #[test]
    fn encode_rejects_values_authenticator_would_not_accept() {
        let mut account = sample();
        account.period = None;
        let uris = encode_uris(std::slice::from_ref(&account), 1).unwrap();
        let (decoded, _) = decode_uri(&uris[0]).unwrap();
        assert_eq!(decoded[0].period, None);
        assert_eq!(account.period, None);
        let otpauth = accounts::encode_otpauth_uris(&decoded).unwrap();
        assert!(otpauth[0].contains("period=30"));
        assert_eq!(decoded[0].period, None);

        account.period = Some(60);
        assert!(encode_uris(std::slice::from_ref(&account), 1).is_err());
        account.period = Some(30);
        account.digits = Some(4);
        assert!(encode_uris(std::slice::from_ref(&account), 1).is_err());
        account.digits = Some(6);
        account.algorithm.clear();
        assert!(encode_uris(std::slice::from_ref(&account), 1).is_err());
        account.algorithm = "SHA1".into();
        account.otp_type = OtpType::Hotp;
        account.counter = None;
        assert!(encode_uris(std::slice::from_ref(&account), 1).is_err());
        account.counter = Some(i32::MAX as u64 + 1);
        assert!(encode_uris(std::slice::from_ref(&account), 1).is_err());
    }

    #[test]
    fn counter_above_i64_max_is_kept() {
        let parameter = parameter_from_account(&sample()).unwrap();
        let payload = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                r#type: Some(MigrationOtpType::Hotp as i32),
                counter: Some(u64::MAX),
                ..parameter
            }],
            version: Some(2),
            batch_size: Some(1),
            batch_index: Some(0),
        };
        let (accounts, _) = decode_uri(&payload_uri(payload)).unwrap();
        assert_eq!(accounts[0].counter, Some(u64::MAX));
        assert!(encode_uris(&accounts, 1).is_err());
    }

    #[test]
    fn absent_fields_stay_empty_and_unknown_values_are_kept() {
        let parameter = parameter_from_account(&sample()).unwrap();
        let payload = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                digits: Some(DigitCount::Unspecified as i32),
                algorithm: None,
                counter: None,
                issuer: String::new(),
                unique_id: String::new(),
                ..parameter.clone()
            }],
            version: None,
            batch_size: None,
            batch_index: None,
        };
        let (accounts, batch) = decode_uri(&payload_uri(payload)).unwrap();
        assert_eq!(batch.batch_size, None);
        assert_eq!(batch.batch_index, None);
        assert_eq!(accounts[0].digits, None);
        assert_eq!(accounts[0].algorithm, "");
        assert_eq!(accounts[0].counter, None);
        assert_eq!(accounts[0].issuer, "");
        assert_eq!(accounts[0].period, None);
        assert_eq!(accounts[0].unique_id, "");
        assert_eq!(accounts[0].name, "alice@example.com");

        let unknown = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                digits: Some(4),
                algorithm: Some(9),
                ..parameter
            }],
            version: Some(9),
            batch_size: Some(0),
            batch_index: Some(-1),
        };
        let (accounts, batch) = decode_uri(&payload_uri(unknown)).unwrap();
        assert_eq!(accounts[0].digits, Some(4));
        assert_eq!(accounts[0].algorithm, "9");
        let unknown_type = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                r#type: Some(4),
                ..parameter_from_account(&sample()).unwrap()
            }],
            version: Some(2),
            batch_size: None,
            batch_index: None,
        };
        let (accounts, _) = decode_uri(&payload_uri(unknown_type)).unwrap();
        assert_eq!(accounts[0].otp_type, OtpType::Other(4));
        assert_eq!(batch.batch_size, Some(0));
        assert_eq!(batch.batch_index, Some(-1));
    }

    #[test]
    fn scan_requires_name_secret_and_type() {
        let parameter = parameter_from_account(&sample()).unwrap();
        let missing_type = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                r#type: None,
                ..parameter.clone()
            }],
            version: Some(2),
            batch_size: Some(1),
            batch_index: Some(0),
        };
        assert!(decode_uri(&payload_uri(missing_type)).is_err());

        let empty_name = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                name: String::new(),
                ..parameter.clone()
            }],
            version: Some(2),
            batch_size: Some(1),
            batch_index: Some(0),
        };
        assert!(decode_uri(&payload_uri(empty_name)).is_err());

        let empty_secret = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                secret: Vec::new(),
                ..parameter
            }],
            version: Some(2),
            batch_size: Some(1),
            batch_index: Some(0),
        };
        assert!(decode_uri(&payload_uri(empty_secret)).is_err());
    }

    #[test]
    fn base64_padding_whitespace_and_raw_plus_follow_android() {
        let uris = encode_uris(std::slice::from_ref(&sample()), 1).unwrap();
        let url = Url::parse(&uris[0]).unwrap();
        let data = migration_data_parameter(&url).unwrap();
        let unpadded = data.trim_end_matches('=').to_owned();
        let relaxed = format!(" {unpadded}\n\t");
        let uri = format!(
            "otpauth-migration://offline?data={}",
            accounts::encode_query_component(&relaxed)
        );
        let (accounts, _) = decode_uri(&uri).unwrap();
        assert_eq!(accounts[0].name, "alice@example.com");

        let raw_plus = Url::parse("otpauth-migration://offline?data=YQ+b%3D").unwrap();
        assert_eq!(migration_data_parameter(&raw_plus).unwrap(), "YQ+b=");
        assert!(decode_uri("otpauth-migration://offline:123?data=YQ").is_err());
        assert!(decode_uri("otpauth-migration://user@offline?data=YQ").is_err());
    }

    #[test]
    fn ten_account_limit_and_batch_indexes_match_authenticator_export() {
        let accounts = vec![sample(); ACTIVE.max_accounts_per_qr + 1];
        let uris = encode_uris(&accounts, ACTIVE.max_accounts_per_qr).unwrap();
        assert_eq!(uris.len(), 2);

        let (first_accounts, first_batch) = decode_uri(&uris[0]).unwrap();
        assert_eq!(first_accounts.len(), 10);
        assert_eq!(first_batch.batch_size, Some(2));
        assert_eq!(first_batch.batch_index, Some(0));

        let (second_accounts, second_batch) = decode_uri(&uris[1]).unwrap();
        assert_eq!(second_accounts.len(), 1);
        assert_eq!(second_batch.batch_size, Some(2));
        assert_eq!(second_batch.batch_index, Some(1));

        assert!(encode_uris(&accounts, ACTIVE.max_accounts_per_qr + 1).is_err());
    }
}
