# google-otp-qr-converter

An offline Rust CLI for reading Google Authenticator export QR images and individual `otpauth://` QR images, saving OTP records as JSON/CSV, and generating migration or individual `otpauth://` QR codes from JSON/CSV.

## Processing pipeline

```text
decode: image -> QR text -> Google migration/otpauth parser -> OTP accounts -> JSON/CSV
encode: JSON/CSV -> OTP accounts -> migration protobuf/URI or individual otpauth URI -> QR text -> PNG
```

The code follows those boundaries: `qr.rs` handles only QR image/text, `google_migration.rs` owns the migration URI and protobuf schema, `accounts.rs` owns the account model, JSON/CSV, and single-account `otpauth://` decoding, and `workflow.rs` connects the stages. A future protobuf change should be localized to `google_migration.rs`.

## Build

```powershell
cargo build --release
```

All processing is local. The program does not make network requests. OTP secrets are sensitive: exported JSON/CSV and generated QR images contain credentials. Protect them and avoid sharing them.

## Decode image(s) to JSON or CSV

```powershell
google-otp-qr-converter decode -i .\export.png -o .\accounts.json
google-otp-qr-converter decode -i .\batch-1.png -i .\batch-2.png -o .\accounts.csv --format csv
```

The decoder accepts Google migration QR images and individual `otpauth://` QR images. Repeat `-i` to process multiple image files.

## Create QR code(s) from JSON or CSV

By default, `encode` creates Google Authenticator migration QR code(s), including for a one-account input. The 7.2 format packs up to ten accounts in each QR.

```powershell
google-otp-qr-converter encode -i .\accounts.json -o .\migration-qrs
google-otp-qr-converter encode -i .\accounts.csv -o .\migration-qrs --accounts-per-qr 8
```

For 1–10 accounts, one migration QR is written; 11–20 accounts produce two. Scan every QR in a multi-QR batch, with the final-index QR last. `--accounts-per-qr` can lower the batch size, but not raise it above 10.

To create standard `otpauth://` QR images instead, pass `--format otpauth`. It writes one independent QR per account (one account = one image, N accounts = N images):

```powershell
google-otp-qr-converter encode -i .\accounts.json -o .\account-qrs --format otpauth
```

Existing QR image files are not overwritten.

## JSON schema

The decoder writes a JSON array. `type` is `totp` or `hotp`; `secret` is unpadded Base32. The common account record includes `algorithm`, `digits`, `period`, and `counter`. For `otpauth://` scans, period is set to 30 seconds to match Authenticator 7.2, which ignores the URI's `period` parameter.

```json
[
  {
    "issuer": "Example",
    "name": "user@example.com",
    "secret": "JBSWY3DPEHPK3PXP",
    "type": "totp",
    "algorithm": "SHA1",
    "digits": 6,
    "period": 30,
    "counter": 0
  }
]
```

CSV uses the same fields as headers. When importing older files, omitted algorithm/digits/period/type/counter values default to SHA1/6/30/TOTP/0.

Google Authenticator 7.2 exports migration payloads with version 2, up to 10 OTP parameters per QR, `batch_size`, and zero-based `batch_index`; its schema has no `batch_id`. Its standard `otpauth://` parser ignores the `period` parameter, so the tool rejects non-30-second TOTP records for either QR output format. Migration data supports SHA1/SHA256/SHA512 and 6/7/8 digits; unsupported values are rejected instead of silently changed.
