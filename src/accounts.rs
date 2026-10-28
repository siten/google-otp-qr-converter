use anyhow::{Context, Result, bail};
use data_encoding::BASE32_NOPAD;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::path::Path;
use url::Url;

fn default_algorithm() -> String {
    "SHA1".to_owned()
}

fn default_digits() -> u32 {
    6
}

fn default_period() -> u32 {
    30
}

fn default_otp_type() -> OtpType {
    OtpType::Totp
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    #[default]
    Totp,
    Hotp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpAccount {
    #[serde(default)]
    pub issuer: String,
    pub name: String,
    pub secret: String,
    #[serde(rename = "type", default = "default_otp_type")]
    pub otp_type: OtpType,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// Retained in the common record. Authenticator 7.2 uses 30 seconds and
    /// ignores a custom period in either QR import format.
    #[serde(default = "default_period")]
    pub period: u32,
    #[serde(default)]
    pub counter: u64,
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

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("OTP account name must not be empty");
        }
        self.secret_bytes()?;
        if !matches!(
            self.algorithm.to_ascii_uppercase().as_str(),
            "SHA1" | "SHA256" | "SHA512"
        ) {
            bail!(
                "unsupported Google Authenticator algorithm {:?}; expected SHA1, SHA256, or SHA512",
                self.algorithm
            );
        }
        if !(6..=8).contains(&self.digits) {
            bail!("Google Authenticator supports 6, 7, or 8 OTP digits");
        }
        if self.otp_type == OtpType::Totp && self.period == 0 {
            bail!("TOTP period must be greater than zero");
        }
        if self.otp_type == OtpType::Hotp && self.counter > i32::MAX as u64 {
            bail!("HOTP counter exceeds Authenticator 7.2's supported range");
        }
        Ok(())
    }
}

/// Validate values that Google Authenticator 7.2 can preserve in migration output.
pub fn validate_for_authenticator_qr(account: &OtpAccount) -> Result<()> {
    account.validate()?;
    if account.otp_type == OtpType::Totp && account.period != 30 {
        bail!(
            "Google Authenticator 7.2 does not preserve custom TOTP periods ({} seconds) for {:?}",
            account.period,
            account.name
        );
    }
    Ok(())
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

    let otp_type = match url
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "totp" => OtpType::Totp,
        "hotp" => OtpType::Hotp,
        other => bail!("unsupported otpauth type {other:?}"),
    };
    let label = percent_decode_str(url.path().trim_start_matches('/'))
        .decode_utf8()
        .context("account label is not valid UTF-8")?
        .trim()
        .to_owned();
    let mut issuer_param = None;
    let mut secret = None;
    let mut algorithm = "SHA1".to_owned();
    let mut digits = 6_u32;
    let period = 30_u32;
    let mut counter = 0_u64;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "issuer" => issuer_param = Some(value.into_owned()),
            "secret" => secret = Some(value.into_owned()),
            "algorithm" => algorithm = value.into_owned().to_ascii_uppercase(),
            "digits" => digits = value.parse().context("invalid digits parameter")?,
            "counter" if otp_type == OtpType::Hotp => {
                let parsed: i32 = value.parse().context("invalid counter parameter")?;
                counter = u64::try_from(parsed).context("HOTP counter must not be negative")?;
            }
            _ => {}
        }
    }
    let secret = secret.context("otpauth URI is missing the secret parameter")?;

    let (label_issuer, name) = match label.split_once(':') {
        Some((issuer, name)) => (issuer.to_owned(), name.to_owned()),
        None => (String::new(), label),
    };
    let name = if name.trim().is_empty() {
        "Untitled".to_owned()
    } else {
        name.trim().to_owned()
    };
    let account = OtpAccount {
        issuer: issuer_param.unwrap_or(label_issuer).trim().to_owned(),
        name,
        secret: normalize_secret(&secret),
        otp_type,
        algorithm,
        digits,
        period,
        counter,
    };
    account.validate()?;
    Ok(account)
}

/// Encode one account as a standard `otpauth://` URI. A list of N accounts
/// produces N independent URIs; use migration format for a related batch.
pub fn encode_otpauth_uris(accounts: &[OtpAccount]) -> Result<Vec<String>> {
    accounts
        .iter()
        .map(|account| {
            validate_for_authenticator_qr(account)?;
            let scheme_type = match account.otp_type {
                OtpType::Totp => "totp",
                OtpType::Hotp => "hotp",
            };
            let mut uri = Url::parse(&format!("otpauth://{scheme_type}/"))?;
            let label = if account.issuer.is_empty() {
                account.name.clone()
            } else {
                format!("{}:{}", account.issuer, account.name)
            };
            uri.set_path(&label);
            {
                let mut query = uri.query_pairs_mut();
                query
                    .append_pair("secret", &normalize_secret(&account.secret))
                    .append_pair("algorithm", &account.algorithm.to_ascii_uppercase())
                    .append_pair("digits", &account.digits.to_string());
                if !account.issuer.is_empty() {
                    query.append_pair("issuer", &account.issuer);
                }
                match account.otp_type {
                    OtpType::Totp => {
                        query.append_pair("period", &account.period.to_string());
                    }
                    OtpType::Hotp => {
                        query.append_pair("counter", &account.counter.to_string());
                    }
                }
            }
            Ok(uri.into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_import_uses_authenticator_default_period() {
        let uri = "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60";
        let account = decode_otpauth_uri(uri).unwrap();
        assert_eq!(account.name, "alice@example.com");
        assert_eq!(account.algorithm, "SHA256");
        assert_eq!(account.digits, 8);
        assert_eq!(account.period, 30);
    }

    #[test]
    fn individual_otpauth_output_is_one_uri_per_account() {
        let account = OtpAccount {
            issuer: "Example".into(),
            name: "alice@example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            otp_type: OtpType::Totp,
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            counter: 0,
        };
        assert_eq!(
            encode_otpauth_uris(std::slice::from_ref(&account))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            encode_otpauth_uris(&[account.clone(), account])
                .unwrap()
                .len(),
            2
        );
    }
}
