# google-otp-qr-converter

An offline Rust CLI for reading Google Authenticator export QR images and individual `otpauth://` QR images, saving OTP records as JSON/CSV, and generating migration or individual `otpauth://` QR codes from JSON/CSV.

## Processing pipeline

```text
decode: image -> QR text -> Google migration/otpauth parser -> OTP accounts -> JSON/CSV
encode: JSON/CSV -> OTP accounts -> migration protobuf/URI or individual otpauth URI -> QR text -> PNG
```

The code follows those boundaries: `qr.rs` handles only QR image/text, `google_migration.rs` owns the migration URI and protobuf schema, `accounts.rs` owns the account model, JSON/CSV, and single-account `otpauth://` encoding and decoding, and `workflow.rs` connects the stages. A future protobuf change should be localized to `google_migration.rs`.

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

The decoder accepts Google migration QR images and individual `otpauth://` QR images. Repeat `-i` to process multiple image files. Migration images can arrive in any order. A missing image is left out. When two images share a batch index, the later one is ignored. Images with no batch index are all included, after the indexed accounts, in scan order. Indexed accounts are written in index order.

## Create QR code(s) from JSON or CSV

By default, `encode` creates Google Authenticator migration QR code(s), including for a one-account input. The 7.2 format packs up to ten accounts in each QR.

```powershell
google-otp-qr-converter encode -i .\accounts.json -o .\migration-qrs
google-otp-qr-converter encode -i .\accounts.csv -o .\migration-qrs --accounts-per-qr 8
```

For 1–10 accounts, one migration QR is written; 11–20 accounts produce two. `--accounts-per-qr` can lower the batch size, but not raise it above 10.

To create standard `otpauth://` QR images instead, pass `--format otpauth`. It writes one independent QR per account (one account = one image, N accounts = N images):

```powershell
google-otp-qr-converter encode -i .\accounts.json -o .\account-qrs --format otpauth
```

Existing QR image files are not overwritten. Each PNG uses error correction M and the 7.2 export sizing: the bitmap is `max(600, modules + 8)` pixels on each side, and each module is a whole number of pixels centered in that square, which keeps a quiet zone of at least 4 modules.

## JSON schema

The decoder writes a JSON array. A scan requires the account name, the secret, and the OTP type. `otpauth://` type must be `totp` or `hotp`. A migration type of 1 or 2 is `hotp` or `totp`; any other present type wire value is kept as its decimal text, and a missing or 0 type is rejected. Every other field is copied when the QR carries it and left empty when it does not: `algorithm`, `issuer`, and `unique_id` are `""`, and `digits`, `period`, and `counter` are `null`. Migration payloads have no period, and a TOTP parameter has no counter, so a normal export scan looks like this:

```json
[
  {
    "issuer": "Example",
    "name": "user@example.com",
    "secret": "JBSWY3DPEHPK3PXP",
    "type": "totp",
    "algorithm": "SHA1",
    "digits": 6,
    "period": null,
    "counter": null,
    "unique_id": ""
  }
]
```

`unique_id` is migration protobuf field 8. The 7.2 exporter writes it and the QR importer replaces it with a new id; this tool keeps the exported value. The example above is empty only because that field was absent.

CSV uses the same fields as headers. When importing older files, a missing algorithm, digits, period, type, or counter defaults to SHA1, 6, 30, TOTP, or 0. JSON `null` leaves `digits`, `period`, and `counter` empty. An empty CSV cell leaves those three empty as well. `algorithm` and `type` are strings; JSON `null` is rejected for them.

Google Authenticator 7.2 exports migration payloads with version 2, up to 10 OTP parameters per QR, `batch_size`, and zero-based `batch_index`. The schema has no `batch_id`. Scan does not require the version, a complete batch, or a known algorithm or digit count. Digit wire 0 and a missing digit field stay null; wire 1, 2, and 3 are stored as 6, 8, and 7; any other non-negative value is stored as that integer. Algorithm wire 0 and a missing algorithm stay `""`; wire 1, 2, and 3 are SHA1, SHA256, and SHA512; any other value is stored as its decimal wire number. Encode still requires a non-empty name and secret, type `totp` or `hotp`, algorithm SHA1/SHA256/SHA512, and 6/7/8 digits. An `otpauth://` scan keeps the period written in the QR, so `period=60` stays 60 in JSON/CSV. Authenticator 7.2 ignores that parameter and imports the account as 30 seconds; this tool does not rewrite the scan to that import result. Encode treats a missing period as 30 and leaves the stored `null` unchanged, and it rejects an explicit period other than 30. A migration counter is stored as the full uint64. Encode still rejects a HOTP counter above Authenticator's 32-bit range, and it does not fill other empty scan fields.

The 7.2 rules live in `AUTHENTICATOR_7_2` and the wire maps in `src/google_migration.rs`. On that profile, `min_readable_version`, `max_readable_version`, and `default_batch_size` are documentation of the APK and are not applied by scan or encode. The single-account `otpauth://` parser is in `src/accounts.rs`. A newer export should be handled by updating that profile and those maps.
