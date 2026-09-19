//! Turning a signed image into a page that animates it as BBQr.
//!
//! The sending half of `Debug → Install from QR`. A device whose USB and card slot have
//! both stopped working can still be shown a screen, and this is the screen: a few
//! hundred QR codes in a loop, which the device catches in whatever order it manages.
//!
//! # Why the matrices are baked in
//!
//! The page carries the finished module grids rather than the text plus a QR library.
//! A library would have to come from a CDN, which means the page only works online and
//! only as long as that CDN serves it -- for a tool whose entire reason to exist is that
//! the normal paths have failed, depending on the network is the wrong trade. Baked in,
//! the file is a few hundred kilobytes and works from a thumb drive on a machine with no
//! network at all.

use anyd::codes::qr::{EcLevel, QrEncoder, Version};
use anyhow::{Context, Result, bail};
use catcard_bbqr::{Encoding, FileType, Header, encode_part_to_slice, part_len, parts_needed};

/// How a part's bytes are written.
///
/// Base32, not `Z`. The device stages an image straight into the memory it will install
/// from, and `Z` compresses the whole file before cutting it up -- so nothing is data
/// until every part is in, and inflating would mean reading that memory while writing
/// it. Roughly half the codes, for the one failure mode this hardware has already had.
const ENCODING: Encoding = Encoding::Base32;

/// The largest symbol this will build. Version 40 is the largest there is; the encoder
/// picks the smallest that fits, so this only sizes the buffers.
const MAX_VERSION: u8 = 40;

/// Bytes per part, unless the caller says otherwise.
///
/// **A multiple of twenty**, which is the constraint neither format states on its own. A
/// BBQr part is five bytes per eight characters, so its size is a multiple of five; the
/// device writes parts straight into PSRAM, which takes whole aligned words, so it must
/// also be a multiple of four. Twenty satisfies both.
///
/// 1260 rather than a rounder number because the device's scanner buffer holds 2048
/// characters, and 1260 bytes is 2024 of them with the header. The next multiple of
/// twenty up does not fit.
pub const DEFAULT_PART: usize = 1260;

/// Build the page.
pub fn render(image: &[u8], part: usize, title: &str) -> Result<String> {
    if part == 0 || !part.is_multiple_of(20) {
        bail!("part size must be a positive multiple of 20 (got {part})");
    }
    let line_len = part_len(ENCODING, part);
    if line_len > 2048 {
        bail!(
            "a {part}-byte part is {line_len} characters, over the device's 2048-character limit"
        );
    }
    let total = parts_needed(image.len(), part);
    if total > 36 * 36 {
        bail!("{total} parts, over BBQr's 1296; use a larger --part (currently {part} bytes)");
    }

    let version = Version::new(MAX_VERSION).expect("40 is a version");
    let buf_len = QrEncoder::buffer_len(version);
    let encoder = QrEncoder::new();
    let mut line = vec![0u8; line_len];
    let mut scratch = vec![0u8; buf_len];
    let mut storage = vec![0u8; buf_len];

    // Every frame's modules, packed a bit per module, row-major. The width is the same
    // for every frame -- the parts are all the same length but the last, and the encoder
    // picks a version from the length -- but it is recorded rather than assumed, because
    // a short last part can land in a smaller symbol.
    let mut frames: Vec<(usize, Vec<u8>)> = Vec::with_capacity(total);
    for index in 0..total {
        let at = index * part;
        let chunk = &image[at..(at + part).min(image.len())];
        // BINARY, because that is what a firmware image is. The device does not dispatch
        // on the letter here -- it was asked for an image -- but a reader that stumbled
        // on these codes should not be told they are JSON.
        let header = Header {
            encoding: ENCODING,
            file_type: FileType::BINARY,
            num_parts: total as u16,
            index: index as u16,
        };
        let n = encode_part_to_slice(&header, chunk, &mut line)
            .map_err(|e| anyhow::anyhow!("could not encode part {index}: {e:?}"))?;
        let (grid, _) = encoder
            .encode_text_into(&line[..n], EcLevel::L, &mut scratch, &mut storage)
            .map_err(|e| anyhow::anyhow!("could not build a QR for part {index}: {e:?}"))?;
        let w = grid.width();
        let mut bits = vec![0u8; w * w / 8 + 1];
        for y in 0..w {
            for x in 0..w {
                if grid.get(x, y) {
                    let i = y * w + x;
                    bits[i / 8] |= 1 << (i % 8);
                }
            }
        }
        frames.push((w, bits));
    }

    Ok(page(&frames, total, image.len(), part, title))
}

/// The HTML, with the frames as base64 bit-planes.
fn page(
    frames: &[(usize, Vec<u8>)],
    total: usize,
    bytes: usize,
    part: usize,
    title: &str,
) -> String {
    let mut data = String::new();
    for (w, bits) in frames {
        data.push_str(&format!("[{w},\"{}\"],", b64(bits)));
    }
    format!(
        r#"<!doctype html>
<meta charset="utf-8">
<title>{title} - CatCard firmware over QR</title>
<style>
  html,body {{ margin:0; height:100%; background:#fff; color:#111;
               font:14px system-ui,-apple-system,sans-serif; }}
  body {{ display:flex; flex-direction:column; align-items:center; justify-content:center; }}
  canvas {{ image-rendering:pixelated; background:#fff; }}
  #bar {{ display:flex; gap:12px; align-items:center; padding:8px; }}
  button {{ font:inherit; padding:4px 10px; }}
  #hint {{ color:#666; max-width:44em; text-align:center; padding:0 12px 8px; }}
</style>
<canvas id="c"></canvas>
<div id="bar">
  <button id="go">pause</button>
  <button id="slower">slower</button>
  <span id="rate"></span>
  <button id="faster">faster</button>
  <span id="at"></span>
</div>
<div id="hint">
  {bytes} bytes in {total} parts of {part}.
  On the device: <b>Debug &rarr; Install from QR</b>, then point it here.
  Parts are caught in any order, so let it loop. Full-screen the window and
  raise the display brightness if it is slow to catch them.
</div>
<script>
const FRAMES = [{data}];
const c = document.getElementById('c'), g = c.getContext('2d');
let i = 0, ms = 200, running = true, timer = null;

function draw() {{
  const [w, b64s] = FRAMES[i];
  const raw = atob(b64s);
  // As large as the window allows, in whole pixels per module -- a module drawn at a
  // fractional size is a module with a grey edge, which is what a camera struggles on.
  const quiet = 4, side = w + 2 * quiet;
  const room = Math.min(window.innerWidth, window.innerHeight - 90);
  const scale = Math.max(1, Math.floor(room / side));
  c.width = c.height = side * scale;
  g.fillStyle = '#fff'; g.fillRect(0, 0, c.width, c.height);
  g.fillStyle = '#000';
  for (let y = 0; y < w; y++) for (let x = 0; x < w; x++) {{
    const n = y * w + x;
    if (raw.charCodeAt(n >> 3) & (1 << (n & 7)))
      g.fillRect((quiet + x) * scale, (quiet + y) * scale, scale, scale);
  }}
  document.getElementById('at').textContent = (i + 1) + ' / ' + FRAMES.length;
  document.getElementById('rate').textContent = ms + ' ms';
}}

function step() {{ i = (i + 1) % FRAMES.length; draw(); }}
function restart() {{ if (timer) clearInterval(timer);
                     timer = running ? setInterval(step, ms) : null; }}

document.getElementById('go').onclick = e => {{
  running = !running; e.target.textContent = running ? 'pause' : 'play'; restart();
}};
document.getElementById('slower').onclick = () => {{ ms = Math.min(2000, ms + 50); restart(); draw(); }};
document.getElementById('faster').onclick = () => {{ ms = Math.max(50, ms - 50); restart(); draw(); }};
window.onresize = draw;
draw(); restart();
</script>
"#
    )
}

/// Base64, so the bit-planes survive being pasted into a script tag.
fn b64(bytes: &[u8]) -> String {
    const SET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b = [
            group[0],
            *group.get(1).unwrap_or(&0),
            *group.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= group.len() {
                out.push(SET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Read an image and write its page.
pub fn run(bin: &std::path::Path, out: &std::path::Path, part: usize) -> Result<()> {
    let image = std::fs::read(bin).with_context(|| format!("reading {}", bin.display()))?;
    if image.starts_with(b"DfuSe") {
        bail!(
            "{} is a DfuSe container; the device stages the element inside it. \
             Run `catcard-image extract` first.",
            bin.display()
        );
    }
    let title = bin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    let html = render(&image, part, &title)?;
    std::fs::write(out, html).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "wrote         {} ({} parts of {} bytes)",
        out.display(),
        parts_needed(image.len(), part),
        part
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_bbqr::fits;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
        assert_eq!(b64(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    /// The constraint the device cannot state for itself: its staging area takes whole
    /// aligned words, so a part that is not a multiple of four lands unaligned at every
    /// offset after the first. A multiple of five is BBQr's own. Only the intersection
    /// works, and this is the number that gets it wrong quietly if it ever drifts.
    #[test]
    fn the_default_part_suits_both_constraints() {
        assert_eq!(DEFAULT_PART % 4, 0, "PSRAM wants whole words");
        assert_eq!(DEFAULT_PART % 5, 0, "BBQr packs five bytes to eight chars");
        assert_eq!(
            fits(ENCODING, part_len(ENCODING, DEFAULT_PART)),
            DEFAULT_PART
        );
        assert!(
            part_len(ENCODING, DEFAULT_PART) <= 2048,
            "over the device's scanner buffer"
        );
    }

    #[test]
    fn a_part_size_that_would_stage_misaligned_is_refused() {
        // 1275 bytes is the largest that fits the line limit, and is a multiple of five
        // -- so BBQr is happy and PSRAM is not. It must not be quietly accepted.
        assert!(render(&[0u8; 4096], 1275, "x").is_err());
        assert!(render(&[0u8; 4096], 0, "x").is_err());
    }
}
