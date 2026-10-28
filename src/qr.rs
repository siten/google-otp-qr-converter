use anyhow::{Context, Result, bail};
use image::{GrayImage, Luma};
use qrcodegen::{QrCode, QrCodeEcc};
use std::collections::HashSet;
use std::path::Path;

/// Authenticator 7.2 draws export QR codes with ZXing error correction M and a
/// quiet zone of 4 modules (`cbm.a`). The export view (`byh.c`) then renders
/// into `max(600, modules + 8)` pixels on each side. Each module is an integer
/// number of pixels and the matrix is centered, which leaves at least the
/// 4-module quiet zone.
const QUIET_ZONE: u32 = 4;
const MIN_IMAGE_SIZE: u32 = 600;

/// Image boundary: decode every detected QR as raw text without interpreting its payload.
pub fn scan_image(path: &Path) -> Result<Vec<String>> {
    let image = image::open(path)
        .with_context(|| format!("cannot open image {}", path.display()))?
        .to_luma8();
    scan_luma(image)
}

fn scan_luma(image: GrayImage) -> Result<Vec<String>> {
    let width = image.width();
    let height = image.height();
    let mut hints = rxing::DecodeHints {
        PossibleFormats: Some(HashSet::from([rxing::BarcodeFormat::QR_CODE])),
        ..rxing::DecodeHints::default()
    };
    let results = rxing::helpers::detect_multiple_in_luma_with_hints(
        image.into_raw(),
        width,
        height,
        &mut hints,
    )
    .context("no QR code detected")?;
    if results.is_empty() {
        bail!("no QR code detected");
    }
    Ok(results
        .into_iter()
        .map(|result| result.getText().to_owned())
        .collect())
}

pub fn write_png(text: &str, path: &Path) -> Result<()> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).context("QR data is too large")?;
    let module_count = u32::try_from(qr.size()).context("invalid QR dimensions")?;
    let matrix_size = module_count + QUIET_ZONE * 2;
    let image_size = matrix_size.max(MIN_IMAGE_SIZE);
    let scale = image_size / matrix_size;
    let offset = (image_size - module_count * scale) / 2;
    let mut image = GrayImage::from_pixel(image_size, image_size, Luma([255]));

    for y in 0..module_count {
        for x in 0..module_count {
            if qr.get_module(x as i32, y as i32) {
                let left = offset + x * scale;
                let top = offset + y * scale;
                for pixel_y in top..top + scale {
                    for pixel_x in left..left + scale {
                        image.put_pixel(pixel_x, pixel_y, Luma([0]));
                    }
                }
            }
        }
    }

    if path.exists() {
        bail!("refusing to overwrite existing QR image {}", path.display());
    }
    image
        .save(path)
        .with_context(|| format!("cannot save QR image {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_matches_authenticator_export_sizing() {
        let text = "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP";
        let qr = QrCode::encode_text(text, QrCodeEcc::Medium).unwrap();
        let modules = u32::try_from(qr.size()).unwrap();
        let matrix_size = modules + QUIET_ZONE * 2;
        let expected = matrix_size.max(MIN_IMAGE_SIZE);
        let scale = expected / matrix_size;
        let offset = (expected - modules * scale) / 2;

        let path = std::env::temp_dir().join(format!(
            "google-otp-qr-size-{}-{}.png",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_png(text, &path).unwrap();
        let image = image::open(&path).unwrap().to_luma8();
        let _ = std::fs::remove_file(&path);

        assert!(expected >= MIN_IMAGE_SIZE);
        assert_eq!((image.width(), image.height()), (expected, expected));
        assert_eq!(image.get_pixel(0, 0).0, [255]);
        assert!(qr.get_module(0, 0));
        assert_eq!(image.get_pixel(offset, offset).0, [0]);
        assert_eq!(
            image.get_pixel(offset + scale - 1, offset + scale - 1).0,
            [0]
        );
        assert_eq!(image.get_pixel(offset - 1, offset).0, [255]);
    }

    #[test]
    fn scan_failure_keeps_the_detector_error() {
        let path = std::env::temp_dir().join(format!(
            "google-otp-qr-blank-{}-{}.png",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        GrayImage::from_pixel(32, 32, Luma([255]))
            .save(&path)
            .unwrap();
        let error = scan_image(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        let message = format!("{error:#}");
        assert!(message.contains("no QR code detected"), "{message}");
        assert!(message.contains("NotFoundException"), "{message}");
    }
}
