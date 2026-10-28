use anyhow::{Context, Result, bail};
use image::{GrayImage, Luma};
use qrcodegen::{QrCode, QrCodeEcc};
use std::path::Path;

const QUIET_ZONE: u32 = 4;
const PIXELS_PER_MODULE: u32 = 8;

/// Image boundary: decode every detected QR as raw text without interpreting its payload.
pub fn scan_image(path: &Path) -> Result<Vec<String>> {
    let image = image::open(path)
        .with_context(|| format!("cannot open image {}", path.display()))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        bail!("no QR code detected");
    }

    let mut qr_texts = Vec::new();
    for grid in grids {
        let (_metadata, text) = grid.decode().context("could not decode detected QR code")?;
        qr_texts.push(text);
    }
    Ok(qr_texts)
}

pub fn write_png(text: &str, path: &Path) -> Result<()> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).context("QR data is too large")?;
    let module_count = u32::try_from(qr.size()).context("invalid QR dimensions")?;
    let image_size = (module_count + QUIET_ZONE * 2)
        .checked_mul(PIXELS_PER_MODULE)
        .context("QR image dimensions overflow")?;
    let mut image = GrayImage::from_pixel(image_size, image_size, Luma([255]));

    for y in 0..module_count {
        for x in 0..module_count {
            if qr.get_module(x as i32, y as i32) {
                let left = (x + QUIET_ZONE) * PIXELS_PER_MODULE;
                let top = (y + QUIET_ZONE) * PIXELS_PER_MODULE;
                for pixel_y in top..top + PIXELS_PER_MODULE {
                    for pixel_x in left..left + PIXELS_PER_MODULE {
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
