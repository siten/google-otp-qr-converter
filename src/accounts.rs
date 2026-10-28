use anyhow::{Context, Result, bail};
use data_encoding::BASE32_NOPAD;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::Path;
use url::Url;

/// `Uri.encode` / `Uri.getQueryParameter`: unreserved characters stay literal,
/// space is `%20`, and `+` is `%2B` rather than a form-urlencoded space.
const ANDROID_QUERY: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub(crate) fn encode_query_component(value: &str) -> String {
    utf8_percent_encode(value, ANDROID_QUERY).to_string()
}

/// `Uri.getAuthority()` is the whole authority. 7.2 compares that string, so
/// `host:port` and `user@host` are not the bare host.
pub(crate) fn reject_authority_extras(url: &Url) -> Result<()> {
    if url.port().is_some() || !url.username().is_empty() || url.password().is_some() {
        bail!("URI authority must not include a port or userinfo");
    }
    Ok(())
}

/// First value for `name`. `%XX` is decoded and a raw `+` stays a plus.
/// Android `Uri.getQueryParameter` returns that first match.
pub(crate) fn first_query_value(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_str(raw_key).decode_utf8_lossy();
        if key == name {
            return Some(
                percent_decode_str(raw_value)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
    }
    None
}

fn default_algorithm() -> String {
    "SHA1".to_owned()
}

fn default_digits() -> Option<u32> {
    Some(6)
}

fn default_period() -> Option<u32> {
    Some(30)
}

fn default_counter() -> Option<u64> {
    Some(0)
}

fn default_otp_type() -> OtpType {
    OtpType::Totp
}

/// `totp` and `hotp` are the Authenticator types. `Other` keeps a wire value
/// that is present but not one of those two, so a scan does not drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtpType {
    #[default]
    Totp,
    Hotp,
    Other(i32),
}

impl Serialize for OtpType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Totp => serializer.serialize_str("totp"),
            Self::Hotp => serializer.serialize_str("hotp"),
            Self::Other(value) => serializer.serialize_str(&value.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for OtpType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.to_ascii_lowercase().as_str() {
            "totp" => Ok(Self::Totp),
            "hotp" => Ok(Self::Hotp),
            other => other
                .parse::<i32>()
                .map(Self::Other)
                .map_err(D::Error::custom),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpAccount {
    #[serde(default)]
    pub issuer: String,
    pub name: String,
    pub secret: String,
    #[serde(rename = "type", default = "default_otp_type")]
    pub otp_type: OtpType,
    /// Empty when the scanned QR did not carry an algorithm.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// `None` when the scanned QR did not carry a digit count.
    #[serde(default = "default_digits")]
    pub digits: Option<u32>,
    /// `None` when the scanned QR did not carry a period. Migration payloads
    /// have no period field.
    #[serde(default = "default_period")]
    pub period: Option<u32>,
    /// `None` when the scanned QR did not carry a counter. Migration field 7
    /// is a uint64 and is stored in full; encode applies the 32-bit limit.
    #[serde(default = "default_counter")]
    pub counter: Option<u64>,
    /// Migration protobuf field 8. The 7.2 exporter writes the account id.
    /// Its QR importer discards the value and assigns a new one. Empty means
    /// the field was absent.
    #[serde(default)]
    pub unique_id: String,
}

impl OtpAccount {
    pub fn secret_bytes(&self) -> Result<Vec<u8>> {
        let normalized = normalize_secret(&self.secret);
        let bytes = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .context("secret must be valid Base32")?;
        if bytes.is_empty() {
            bail!("OTP secret must not be empty");
        }
        Ok(bytes)
    }

    /// Encode check. Scan uses [`require_scanned_account`] instead, which only
    /// requires a name, a secret, and a type.
    pub fn validate(&self) -> Result<()> {
        require_scanned_account(self)?;
        if let OtpType::Other(value) = self.otp_type {
            bail!("OTP type {value} cannot be written as an Authenticator QR");
        }
        canonical_algorithm(&self.algorithm)?;
        match self.digits {
            Some(digits) if (6..=8).contains(&digits) => {}
            Some(digits) => {
                bail!("Google Authenticator supports 6, 7, or 8 OTP digits, got {digits}")
            }
            None => bail!("OTP digits are empty"),
        }
        if self.otp_type == OtpType::Hotp {
            match self.counter {
                Some(counter) if counter <= i32::MAX as u64 => {}
                Some(counter) => {
                    bail!("HOTP counter {counter} exceeds Authenticator 7.2's 32-bit range")
                }
                None => bail!("HOTP counter is empty"),
            }
        }
        Ok(())
    }
}

/// Scan rule: account name, secret, and OTP type are required.
/// Type is required by the migration and otpauth parsers before this runs.
pub(crate) fn require_scanned_account(account: &OtpAccount) -> Result<()> {
    if account.name.trim().is_empty() {
        bail!("OTP account name must not be empty");
    }
    if normalize_secret(&account.secret).is_empty() {
        bail!("OTP secret must not be empty");
    }
    Ok(())
}

/// Values Authenticator 7.2 will accept in an exported QR.
/// A missing TOTP period is the APK default of 30 seconds. The account record
/// is not rewritten; only an explicit period other than 30 is rejected.
pub fn validate_for_authenticator_qr(account: &OtpAccount) -> Result<()> {
    account.validate()?;
    if account.otp_type == OtpType::Totp && matches!(account.period, Some(period) if period != 30) {
        bail!(
            "Google Authenticator 7.2 only preserves a 30 second TOTP period for {:?}",
            account.name
        );
    }
    Ok(())
}

/// Hash names Authenticator 7.2 can store. Add a variant here, then map it in
/// `canonical_algorithm` and in the migration wire table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OtpAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// `SHA1` / `HmacSHA1` and the SHA256/SHA512 pair, in any case.
/// Authenticator 7.2 compares those spellings exactly; the extra case folding
/// is local lenience.
pub fn canonical_algorithm(value: &str) -> Result<OtpAlgorithm> {
    match value.trim().to_ascii_uppercase().as_str() {
        "SHA1" | "HMACSHA1" => Ok(OtpAlgorithm::Sha1),
        "SHA256" | "HMACSHA256" => Ok(OtpAlgorithm::Sha256),
        "SHA512" | "HMACSHA512" => Ok(OtpAlgorithm::Sha512),
        _ => bail!(
            "unsupported algorithm {value:?}; Authenticator 7.2 accepts SHA1, SHA256, SHA512 and the HmacSHA* aliases. Extend OtpAlgorithm and canonical_algorithm for a new name"
        ),
    }
}

pub fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '=')
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub enum AccountFormat {
    Json,
    Csv,
}

/// File-format boundary: JSON/CSV data is converted to/from the common account model.
pub fn read_accounts(path: &Path) -> Result<Vec<OtpAccount>> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .context("input file must have a .json or .csv extension")?
        .to_ascii_lowercase();

    match extension.as_str() {
        "json" => {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            let json = contents.strip_prefix('\u{feff}').unwrap_or(&contents);
            serde_json::from_str(json)
                .with_context(|| format!("invalid OTP JSON in {}", path.display()))
        }
        "csv" => {
            let contents = std::fs::read(path)
                .with_context(|| format!("cannot read CSV {}", path.display()))?;
            let csv_bytes = contents
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&contents);
            let mut reader = csv::ReaderBuilder::new().from_reader(csv_bytes);
            reader
                .deserialize()
                .collect::<std::result::Result<Vec<OtpAccount>, csv::Error>>()
                .with_context(|| format!("invalid OTP CSV in {}", path.display()))
        }
        other => bail!("unsupported input extension .{other}; use .json or .csv"),
    }
}

pub fn write_accounts(path: &Path, format: AccountFormat, accounts: &[OtpAccount]) -> Result<()> {
    match format {
        AccountFormat::Json => {
            let file = std::fs::File::create(path)
                .with_context(|| format!("cannot create {}", path.display()))?;
            serde_json::to_writer_pretty(file, accounts)
                .with_context(|| format!("cannot write JSON to {}", path.display()))?;
        }
        AccountFormat::Csv => {
            let mut writer = csv::Writer::from_path(path)
                .with_context(|| format!("cannot create {}", path.display()))?;
            for account in accounts {
                writer
                    .serialize(account)
                    .with_context(|| format!("cannot write CSV to {}", path.display()))?;
            }
            writer
                .flush()
                .with_context(|| format!("cannot flush {}", path.display()))?;
        }
    }
    Ok(())
}

/// Parse a single-account `otpauth://` URI into the shared account model.
pub fn decode_otpauth_uri(text: &str) -> Result<OtpAccount> {
    let url = Url::parse(text).context("invalid otpauth URI")?;
    if url.scheme() != "otpauth" {
        bail!("not an otpauth URI");
    }
    reject_authority_extras(&url)?;

    let otp_type = match url
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "totp" => OtpType::Totp,
        "hotp" => OtpType::Hotp,
        _ => bail!("OTP type must not be empty"),
    };
    let (label_issuer, name) = otpauth_label(url.path())?;
    let query = url.query().unwrap_or("");
    let issuer_param = first_query_value(query, "issuer");
    let secret = first_query_value(query, "secret").unwrap_or_default();
    let account = OtpAccount {
        issuer: issuer_param.unwrap_or(label_issuer).trim().to_owned(),
        name,
        secret: normalize_secret(&secret),
        otp_type,
        algorithm: scanned_algorithm(first_query_value(query, "algorithm")),
        digits: scanned_number(first_query_value(query, "digits")),
        period: scanned_number(first_query_value(query, "period")),
        counter: scanned_counter(first_query_value(query, "counter"))?,
        unique_id: String::new(),
    };
    require_scanned_account(&account)?;
    Ok(account)
}

/// Known hash names are canonicalized. Anything else is kept as written.
/// A missing parameter becomes an empty string.
fn scanned_algorithm(value: Option<String>) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => match canonical_algorithm(&value) {
            Ok(algorithm) => algorithm.as_str().to_owned(),
            Err(_) => value.trim().to_owned(),
        },
        _ => String::new(),
    }
}

/// Parse a present numeric parameter. Missing, blank, or non-numeric values
/// stay empty instead of failing the scan.
fn scanned_number<T: std::str::FromStr>(value: Option<String>) -> Option<T> {
    value.and_then(|value| value.trim().parse().ok())
}

/// Migration counters are uint64. A pure integer that does not fit, including
/// a value above `i128::MAX`, is an error so it is not stored as null. Blank
/// and non-numeric values stay empty.
fn scanned_counter(value: Option<String>) -> Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let (negative, digits) = match value.as_bytes() {
        [b'+' | b'-', digits @ ..] => (value.starts_with('-'), digits),
        digits => (false, digits),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    if negative && digits.iter().any(|digit| *digit != b'0') {
        bail!("OTP counter {value} cannot be stored as an unsigned 64-bit value");
    }
    let digits = std::str::from_utf8(digits).expect("ASCII digits");
    match digits.parse::<u64>() {
        Ok(counter) => Ok(Some(counter)),
        Err(_) => bail!("OTP counter {value} cannot be stored as an unsigned 64-bit value"),
    }
}

/// Authenticator 7.2 splits the otpauth path on every `:` and keeps segment 0
/// as the label issuer and segment 1 as the name. Later segments are dropped.
/// An empty name stays empty so the scan can reject it.
fn otpauth_label(path: &str) -> Result<(String, String)> {
    if !path.starts_with('/') {
        bail!("otpauth path must start with /");
    }
    let label = percent_decode_str(&path[1..])
        .decode_utf8()
        .context("account label is not valid UTF-8")?
        .trim()
        .to_owned();
    let mut segments = label.split(':');
    let first = segments.next().unwrap_or("");
    if let Some(second) = segments.next() {
        Ok((first.trim().to_owned(), second.to_owned()))
    } else if first.is_empty() {
        Ok((String::new(), String::new()))
    } else {
        Ok((String::new(), first.to_owned()))
    }
}

/// Encode one account as a standard `otpauth://` URI. A list of N accounts
/// produces N independent URIs; use migration format for a related batch.
pub fn encode_otpauth_uris(accounts: &[OtpAccount]) -> Result<Vec<String>> {
    accounts
        .iter()
        .map(|account| {
            validate_for_authenticator_qr(account)?;
            if account.issuer.contains(':') || account.name.contains(':') {
                bail!(
                    "otpauth label cannot preserve ':' in {:?} / {:?}; Authenticator 7.2 keeps only the second colon-separated segment",
                    account.issuer,
                    account.name
                );
            }
            let scheme_type = match account.otp_type {
                OtpType::Totp => "totp",
                OtpType::Hotp => "hotp",
                OtpType::Other(value) => bail!("OTP type {value} cannot be written as an otpauth URI"),
            };
            let algorithm = canonical_algorithm(&account.algorithm)?;
            let digits = account.digits.context("OTP digits are empty")?;
            let mut uri = Url::parse(&format!("otpauth://{scheme_type}/"))?;
            let label = if account.issuer.is_empty() {
                account.name.clone()
            } else {
                format!("{}:{}", account.issuer, account.name)
            };
            uri.set_path(&label);
            let mut pairs = vec![
                ("secret", normalize_secret(&account.secret)),
                ("algorithm", algorithm.as_str().to_owned()),
                ("digits", digits.to_string()),
            ];
            if !account.issuer.is_empty() {
                pairs.push(("issuer", account.issuer.clone()));
            }
            match account.otp_type {
                OtpType::Totp => {
                    // Missing period is Authenticator's 30 second default.
                    // `account.period` stays null in the caller's record.
                    let period = account.period.unwrap_or(30);
                    pairs.push(("period", period.to_string()));
                }
                OtpType::Hotp => {
                    let counter = account.counter.context("HOTP counter is empty")?;
                    pairs.push(("counter", counter.to_string()));
                }
                OtpType::Other(value) => {
                    bail!("OTP type {value} cannot be written as an otpauth URI")
                }
            }
            let query = pairs
                .into_iter()
                .map(|(key, value)| format!("{key}={}", encode_query_component(&value)))
                .collect::<Vec<_>>()
                .join("&");
            Ok(format!("{}?{query}", uri.as_str()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_json_without_unique_id_uses_defaults() {
        let account: OtpAccount =
            serde_json::from_str(r#"{"name":"alice","secret":"JBSWY3DPEHPK3PXP"}"#).unwrap();
        assert_eq!(account.unique_id, "");
        assert_eq!(account.algorithm, "SHA1");
        assert_eq!(account.digits, Some(6));
        assert_eq!(account.period, Some(30));
        assert_eq!(account.otp_type, OtpType::Totp);
        assert_eq!(account.counter, Some(0));
    }

    #[test]
    fn otpauth_scan_keeps_present_fields_and_leaves_missing_ones_empty() {
        let uri = "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60";
        let account = decode_otpauth_uri(uri).unwrap();
        assert_eq!(account.name, "alice@example.com");
        assert_eq!(account.algorithm, "SHA256");
        assert_eq!(account.digits, Some(8));
        assert_eq!(account.period, Some(60));
        assert!(decode_otpauth_uri("otpauth://totp:123/alice?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(decode_otpauth_uri("otpauth://user@totp/alice?secret=JBSWY3DPEHPK3PXP").is_err());

        let sparse = decode_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(sparse.issuer, "");
        assert_eq!(sparse.algorithm, "");
        assert_eq!(sparse.digits, None);
        assert_eq!(sparse.period, None);
        assert_eq!(sparse.counter, None);
        assert!(decode_otpauth_uri("otpauth://totp/alice?secret=").is_err());
        assert!(decode_otpauth_uri("otpauth://totp/?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(decode_otpauth_uri("otpauth:///?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn otpauth_label_algorithm_and_empty_counter_match_authenticator() {
        let uri = "otpauth://hotp/Issuer:a:b?secret=JBSWY3DPEHPK3PXP&algorithm=HmacSHA256&digits=7&counter=";
        let account = decode_otpauth_uri(uri).unwrap();
        assert_eq!(account.issuer, "Issuer");
        assert_eq!(account.name, "a");
        assert_eq!(account.algorithm, "SHA256");
        assert_eq!(account.digits, Some(7));
        assert_eq!(account.counter, None);
        assert_eq!(account.otp_type, OtpType::Hotp);
        assert_eq!(
            decode_otpauth_uri(
                "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551615"
            )
            .unwrap()
            .counter,
            Some(u64::MAX)
        );
        assert!(
            decode_otpauth_uri("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=-1").is_err()
        );
        assert!(
            decode_otpauth_uri(
                "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551616"
            )
            .is_err()
        );
        assert!(
            decode_otpauth_uri(&format!(
                "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter={}",
                "9".repeat(40)
            ))
            .is_err()
        );
        assert_eq!(
            decode_otpauth_uri("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=12abc")
                .unwrap()
                .counter,
            None
        );
    }

    #[test]
    fn individual_otpauth_output_is_one_uri_per_account() {
        let account = OtpAccount {
            issuer: "Example".into(),
            name: "alice@example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            otp_type: OtpType::Totp,
            algorithm: "SHA1".into(),
            digits: Some(6),
            period: Some(30),
            counter: Some(0),
            unique_id: String::new(),
        };
        let uris = encode_otpauth_uris(std::slice::from_ref(&account)).unwrap();
        assert_eq!(uris.len(), 1);
        let decoded = decode_otpauth_uri(&uris[0]).unwrap();
        assert_eq!(decoded.name, account.name);
        assert_eq!(decoded.issuer, account.issuer);
        assert_eq!(decoded.secret, account.secret);
        assert_eq!(decoded.period, Some(30));
        assert_eq!(
            encode_otpauth_uris(&[account.clone(), account])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn otpauth_query_keeps_plus_encodes_space_and_uses_the_first_value() {
        let account = OtpAccount {
            issuer: "Example Inc".into(),
            name: "alice".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            otp_type: OtpType::Totp,
            algorithm: "SHA1".into(),
            digits: Some(6),
            period: Some(30),
            counter: Some(0),
            unique_id: String::new(),
        };
        let uri = encode_otpauth_uris(std::slice::from_ref(&account)).unwrap()[0].clone();
        assert!(uri.contains("issuer=Example%20Inc"));
        assert!(uri.contains("Example%20Inc"));
        assert!(!uri.contains("issuer=Example+Inc"));
        assert!(!uri.contains('+'));
        assert!(!uri.contains(' '));
        assert_eq!(decode_otpauth_uri(&uri).unwrap().issuer, "Example Inc");

        let raw = "otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&issuer=Example+Inc&issuer=Other%20Inc&secret=MFRGGZDF";
        let decoded = decode_otpauth_uri(raw).unwrap();
        assert_eq!(decoded.issuer, "Example+Inc");
        assert_eq!(decoded.secret, "JBSWY3DPEHPK3PXP");
    }
}
