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
use outscript::bbqr::{deflate_len_bound, deflate_to_slice};

/// The longest line the device's scanner will hand over, from `qrscan::MAX_TEXT`.
///
/// Stated here rather than shared, because it is a property of the receiving firmware
/// and this tool has to work against a device it was not built alongside. A part whose
/// line is longer is not read at all -- silently, since the scan just never completes.
const SCANNER_BUFFER: usize = 2048;

/// The largest symbol this will build. Version 40 is the largest there is; the encoder
/// picks the smallest that fits, so this only sizes the buffers.
const MAX_VERSION: u8 = 40;

/// Bytes per part, unless the caller says otherwise.
///
/// **A multiple of twenty.** Five is base32's own constraint -- eight characters carry
/// five bytes, so a part that is not the last must be a whole number of groups or the
/// parts after it do not decode on their own. Four is the device's: parts land in PSRAM,
/// which takes whole aligned words, and a part whose length is not a multiple of four
/// puts every part after it at an unaligned offset.
///
/// The device does **not** require this -- it cannot, since another wallet's BBQr parts
/// are whatever size that wallet chose, and its driver merges an odd edge rather than
/// refusing. But when the sender is ours there is no reason to make it: every part lands
/// as whole words and the medium is never read during the transfer at all.
///
/// **Not the largest that fits.** 1260 was, and its symbol is 125 modules a side --
/// dense enough that reading it off a screen is a struggle, and a part that cannot be
/// read makes the transfer impossible rather than merely slow. 460 bytes is 77 modules,
/// so each one is about 1.6x the size on the same display, at the cost of a longer
/// animation. Fewer, denser codes is the wrong trade when a miss costs a whole loop.
///
/// The floor is BBQr's 1296 parts: below about 340 bytes a half-megabyte image no
/// longer fits in a file, whatever the symbol looks like. `--part` covers the range.
pub const DEFAULT_PART: usize = 460;

/// Compress the image if that makes fewer codes, and say which was used.
///
/// The device reads both. `Z` deflates the whole file before it is cut up, so the parts
/// reassemble into a stream the device expands once they are all in -- the codes are
/// what is saved, not the work. The compressor keeps its back-references within a
/// kilobyte, which is what makes the stream expandable on a device with a window it can
/// afford, and also what stops it compressing very well; on a file with little
/// redundancy it can come out longer, so the shorter of the two wins.
fn best_encoding(image: &[u8]) -> (Encoding, Vec<u8>) {
    let mut packed = vec![0u8; deflate_len_bound(image.len())];
    match deflate_to_slice(image, &mut packed) {
        Ok(n) if n < image.len() => {
            packed.truncate(n);
            (Encoding::Zlib, packed)
        }
        _ => (Encoding::Base32, image.to_vec()),
    }
}

/// Build the page, and say how big a symbol it came out as.
///
/// The module count is what decides whether this is readable at all, so it is reported
/// rather than left for someone to measure off the screen.
pub fn render(image: &[u8], part: usize, title: &str) -> Result<(String, usize)> {
    if part == 0 || !part.is_multiple_of(5) {
        bail!("part size must be a positive multiple of 5 (got {part})");
    }
    let (encoding, body) = best_encoding(image);
    let image = &body[..];
    let line_len = part_len(encoding, part);
    if line_len > SCANNER_BUFFER {
        bail!(
            "a {part}-byte part is {line_len} characters, over the device's \
             {SCANNER_BUFFER}-character limit"
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
            encoding,
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

    let modules = frames.first().map(|(w, _)| *w).unwrap_or(0);
    Ok((
        page(&frames, total, image.len(), part, title, encoding),
        modules,
    ))
}

/// The HTML, with the frames as base64 bit-planes.
fn page(
    frames: &[(usize, Vec<u8>)],
    total: usize,
    bytes: usize,
    part: usize,
    title: &str,
    encoding: Encoding,
) -> String {
    let note = match encoding {
        Encoding::Zlib => " (compressed)",
        _ => "",
    };
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
  {bytes} bytes{note} in {total} parts of {part}.
  On the device: <b>Scan QR</b>, then point it here.
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
    let (html, modules) = render(&image, part, &title)?;
    std::fs::write(out, html).with_context(|| format!("writing {}", out.display()))?;
    let (encoding, body) = best_encoding(&image);
    let parts = parts_needed(body.len(), part);
    println!(
        "wrote         {} ({} parts of {} bytes, {} modules, ~{}s a loop, {})",
        out.display(),
        parts,
        part,
        modules,
        parts / 5,
        match encoding {
            Encoding::Zlib => format!(
                "deflate: {} of {} bytes, {:.1}%",
                body.len(),
                image.len(),
                body.len() as f64 * 100.0 / image.len() as f64
            ),
            _ => "uncompressed".into(),
        }
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

    /// The default is the largest part that satisfies both formats and still fits the
    /// device's scanner buffer. All three fail quietly if they drift: an over-long line
    /// is simply never read, a part that is not a whole number of base32 groups puts
    /// every part after the first at the wrong offset, and one that is not a whole
    /// number of words makes the device merge every part edge instead of writing it.
    #[test]
    fn the_default_part_suits_both_formats_and_the_scanner() {
        assert_eq!(
            DEFAULT_PART % 5,
            0,
            "base32 packs five bytes to eight chars"
        );
        assert_eq!(DEFAULT_PART % 4, 0, "the device stages whole words");
        assert!(part_len(Encoding::Base32, DEFAULT_PART) <= SCANNER_BUFFER);
        // Deliberately *not* the largest that fits: it is chosen for how big the symbol
        // comes out, so there is room above it for a caller who finds the codes easy.
        assert!(DEFAULT_PART < fits(Encoding::Base32, SCANNER_BUFFER));
        // And room below: a half-megabyte image has to stay inside BBQr's 1296 parts,
        // which is the real floor on how small a part can be.
        assert!(parts_needed(512 * 1024, DEFAULT_PART) < 1296);
        // `Z` is base32 underneath, so the line arithmetic is the same either way.
        assert_eq!(
            part_len(Encoding::Zlib, DEFAULT_PART),
            part_len(Encoding::Base32, DEFAULT_PART)
        );
    }

    #[test]
    fn a_part_size_the_format_cannot_carry_is_refused() {
        // Not a whole number of base32 groups.
        assert!(render(&[0u8; 4096], 1024, "x").is_err());
        assert!(render(&[0u8; 4096], 0, "x").is_err());
        // Over the scanner's line buffer, so the device would never read one.
        assert!(render(&[0u8; 4096], 2000, "x").is_err());
    }
}

/// The whole transfer, on the host: what this tool emits, taken apart the way the
/// device takes it apart.
///
/// The two halves are tested separately -- placement in `catcard-bbqr`, expansion in
/// `catcard-upgrade` -- and separately is not enough. What they have to agree about is
/// the part size: this tool chooses it, and the device derives every offset from it. A
/// disagreement there is not an error anywhere, it is an image that assembles and fails
/// its signature, which is the report that reads as bad hardware.
#[cfg(test)]
mod round_trip {
    use super::*;
    use catcard_bbqr::{Collector, decoded_len_bound};

    fn firmwareish(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| match i % 11 {
                0 => 0x00,
                1 => 0xF0,
                2 => 0x4B,
                n => ((i / 11).wrapping_mul(7) + n) as u8,
            })
            .collect()
    }

    /// Cut a payload up exactly as `render` does, and put it back exactly as the device
    /// does: place each part at the offset its index gives, out of order.
    fn reassemble(image: &[u8], part: usize) -> (Vec<u8>, bool) {
        let (encoding, body) = best_encoding(image);
        let total = parts_needed(body.len(), part);
        let mut line = vec![0u8; part_len(encoding, part)];

        let mut out = vec![0u8; body.len()];
        let mut c = Collector::new();
        // Back to front, so nothing can be relying on having seen part zero.
        for index in (0..total).rev() {
            let at = index * part;
            let chunk = &body[at..(at + part).min(body.len())];
            let header = Header {
                encoding,
                file_type: FileType::BINARY,
                num_parts: total as u16,
                index: index as u16,
            };
            let n = encode_part_to_slice(&header, chunk, &mut line).expect("encodes");
            let text = std::str::from_utf8(&line[..n]).expect("ascii");
            // A part whose offset is not yet knowable comes round again, as it does on
            // a looping animation.
            if c.take(text, &mut out).is_err() {
                continue;
            }
        }
        for index in 0..total {
            let at = index * part;
            let chunk = &body[at..(at + part).min(body.len())];
            let header = Header {
                encoding,
                file_type: FileType::BINARY,
                num_parts: total as u16,
                index: index as u16,
            };
            let n = encode_part_to_slice(&header, chunk, &mut line).expect("encodes");
            let text = std::str::from_utf8(&line[..n]).expect("ascii");
            c.take(text, &mut out).expect("a part");
        }
        assert!(c.complete(), "every part was placed");
        assert_eq!(c.file_len(), Some(body.len()), "and the length agrees");
        (out, encoding == Encoding::Zlib)
    }

    /// Compressed, which is what a firmware image takes: the parts reassemble the
    /// deflate stream, and expanding it gives back the image.
    #[test]
    fn a_compressed_image_survives_the_round_trip() {
        let image = firmwareish(300 * 1024);
        let (stream, compressed) = reassemble(&image, DEFAULT_PART);
        assert!(compressed, "this fixture should compress");

        let mut out = vec![0u8; image.len() + 4];
        let n = outscript::bbqr::inflate_to_slice(&stream, &mut out).expect("expands");
        assert_eq!(n, image.len());
        assert_eq!(&out[..n], &image[..]);
    }

    /// Bytes with nothing in them for a compressor to find.
    fn noise(len: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// A payload that does not compress goes as plain base32 -- the compressor can make
    /// a file longer, and the shorter of the two is what gets sent.
    #[test]
    fn an_incompressible_image_goes_uncompressed() {
        let image = noise(200 * 1024);
        let (out, compressed) = reassemble(&image, DEFAULT_PART);
        assert!(!compressed, "nothing to gain, so it should go uncompressed");
        assert_eq!(out, image);
    }

    /// The part the device is told and the part this tool used are the same number, and
    /// the offsets it derives from it land where the bytes were cut.
    #[test]
    fn the_device_derives_the_offsets_this_tool_cut_at() {
        let image = firmwareish(64 * 1024);
        let (_, body) = best_encoding(&image);
        let total = parts_needed(body.len(), DEFAULT_PART);
        let mut line = vec![0u8; part_len(Encoding::Zlib, DEFAULT_PART)];
        let mut c = Collector::new();

        for index in 0..total {
            let at = index * DEFAULT_PART;
            let chunk = &body[at..(at + DEFAULT_PART).min(body.len())];
            let header = Header {
                encoding: Encoding::Zlib,
                file_type: FileType::BINARY,
                num_parts: total as u16,
                index: index as u16,
            };
            let n = encode_part_to_slice(&header, chunk, &mut line).expect("encodes");
            let text = std::str::from_utf8(&line[..n]).expect("ascii");
            let placed = c.accept(text).expect("a part");
            assert_eq!(placed.offset, at, "part {index} placed wrong");
            assert_eq!(placed.len, chunk.len(), "part {index} sized wrong");
            assert_eq!(
                decoded_len_bound(Encoding::Zlib, n - 8),
                chunk.len(),
                "the line length does not imply the part length"
            );
            c.confirm(placed);
        }
    }

    /// Every part's offset is a whole number of words, which is what lets the device
    /// write them without merging anything.
    #[test]
    fn the_default_part_puts_every_offset_on_a_word() {
        let image = firmwareish(300 * 1024);
        let (_, body) = best_encoding(&image);
        let total = parts_needed(body.len(), DEFAULT_PART);
        for index in 0..total {
            assert_eq!((index * DEFAULT_PART) % 4, 0, "part {index} is unaligned");
        }
    }
}
