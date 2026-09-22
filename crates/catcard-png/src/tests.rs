//! What a PNG reader has to get right, written as the ways it could be wrong.
//!
//! Fixtures are built here rather than checked in, so a case is a few lines of "an
//! image like this, encoded like that" instead of an opaque blob: every colour type,
//! every bit depth, every filter, and the awkward sizes where a resize rounds. The one
//! checked-in file is the paw print the Q1 already draws, which is a real encoder's
//! output rather than ours.

extern crate alloc;
extern crate std;

use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// A row of pixels as the encoder will write them, with its filter-type byte.
struct Raw {
    bytes: Vec<u8>,
}

impl Raw {
    fn new() -> Self {
        Raw { bytes: Vec::new() }
    }

    /// One scanline, stored unfiltered.
    fn row(&mut self, data: &[u8]) -> &mut Self {
        self.bytes.push(0);
        self.bytes.extend_from_slice(data);
        self
    }

    /// One scanline under filter `kind`, which is the encoder's job and is done here by
    /// running the reconstruction backwards.
    fn filtered(&mut self, kind: u8, data: &[u8], prev: &[u8], step: usize) -> &mut Self {
        let mut out = vec![0u8; data.len()];
        for i in 0..data.len() {
            let left = if i >= step { data[i - step] as i32 } else { 0 };
            let up = prev[i] as i32;
            let upleft = if i >= step { prev[i - step] as i32 } else { 0 };
            let predictor = match kind {
                0 => 0,
                1 => left,
                2 => up,
                3 => (left + up) / 2,
                4 => paeth_ref(left, up, upleft),
                _ => unreachable!(),
            };
            out[i] = (data[i] as i32).wrapping_sub(predictor) as u8;
        }
        self.bytes.push(kind);
        self.bytes.extend_from_slice(&out);
        self
    }
}

fn paeth_ref(a: i32, b: i32, c: i32) -> i32 {
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn crc_of(parts: &[&[u8]]) -> u32 {
    let mut crc = Crc32::new();
    for p in parts {
        crc.update(p);
    }
    crc.finish()
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc_of(&[kind, data]).to_be_bytes());
    out
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len() * 2 + 1024];
    let mut table = vec![0u16; 32 * 1024];
    let n = minizlib::zlib(data, &mut table, minizlib::Buffer::new(&mut out)).expect("compresses");
    out.truncate(n as usize);
    out
}

/// Assemble a whole file.
struct Png {
    w: u32,
    h: u32,
    depth: u8,
    colour: u8,
    interlace: u8,
    palette: Option<Vec<u8>>,
    trns: Option<Vec<u8>>,
    raw: Vec<u8>,
    /// Extra chunks to place before the image data, as a file from another tool would.
    extra: Vec<([u8; 4], Vec<u8>)>,
}

impl Png {
    fn new(w: u32, h: u32, depth: u8, colour: u8, raw: Vec<u8>) -> Self {
        Png {
            w,
            h,
            depth,
            colour,
            interlace: 0,
            palette: None,
            trns: None,
            raw,
            extra: Vec::new(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&self.w.to_be_bytes());
        ihdr.extend_from_slice(&self.h.to_be_bytes());
        ihdr.extend_from_slice(&[self.depth, self.colour, 0, 0, self.interlace]);

        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE);
        out.extend_from_slice(&chunk(b"IHDR", &ihdr));
        for (kind, data) in &self.extra {
            out.extend_from_slice(&chunk(kind, data));
        }
        if let Some(p) = &self.palette {
            out.extend_from_slice(&chunk(b"PLTE", p));
        }
        if let Some(t) = &self.trns {
            out.extend_from_slice(&chunk(b"tRNS", t));
        }
        out.extend_from_slice(&chunk(b"IDAT", &zlib(&self.raw)));
        out.extend_from_slice(&chunk(b"IEND", &[]));
        out
    }
}

/// Decode a whole file into rows of RGB565, at whatever size `fit` picks.
fn draw(file: &[u8], max_w: usize, max_h: usize) -> Result<(Plan, Vec<Vec<u16>>), Error> {
    draw_on(file, max_w, max_h, [255, 255, 255], 1024)
}

/// As `draw`, with the background and the reader's appetite spelled out.
fn draw_on(
    file: &[u8],
    max_w: usize,
    max_h: usize,
    background: [u8; 3],
    per_read: usize,
) -> Result<(Plan, Vec<Vec<u16>>), Error> {
    let hdr = header(&file[..file.len().min(HEADER_BYTES)])?;
    let plan = fit(&hdr, max_w, max_h);

    let mut window = vec![0u8; WINDOW];
    let mut lines = vec![0u8; hdr.lines_needed()];
    let mut acc = vec![0u32; Buffers::acc_needed(plan.w)];
    let mut out = vec![0u16; plan.w];

    let mut at = 0usize;
    let mut rows: Vec<Vec<u16>> = Vec::new();
    let mut order = Vec::new();
    render(
        &hdr,
        &plan,
        Buffers {
            window: &mut window,
            lines: &mut lines,
            acc: &mut acc,
            out: &mut out,
        },
        background,
        |buf| {
            let n = buf.len().min(per_read).min(file.len() - at);
            buf[..n].copy_from_slice(&file[at..at + n]);
            at += n;
            Ok(n)
        },
        |y, row| {
            order.push(y);
            rows.push(row.to_vec());
            Ok(())
        },
    )?;
    // Every row, once, top to bottom: the contract the firmware draws against.
    assert_eq!(order, (0..plan.h).collect::<Vec<_>>());
    Ok((plan, rows))
}

fn rgb(r: u8, g: u8, b: u8) -> u16 {
    resize::rgb565([r, g, b])
}

/// A 2x2 truecolour image: red, green / blue, white.
fn quad() -> Png {
    let mut raw = Raw::new();
    raw.row(&[255, 0, 0, 0, 255, 0]);
    raw.row(&[0, 0, 255, 255, 255, 255]);
    Png::new(2, 2, 8, 2, raw.bytes)
}

#[test]
fn a_file_that_is_not_a_png_is_refused_before_anything_else() {
    let mut file = quad().bytes();
    file[1] = b'X';
    assert_eq!(header(&file[..HEADER_BYTES]), Err(Error::NotPng));
    assert_eq!(draw(&file, 320, 240), Err(Error::NotPng));
}

#[test]
fn the_header_says_what_the_picture_is() {
    let file = quad().bytes();
    let hdr = header(&file[..HEADER_BYTES]).expect("a header");
    assert_eq!(
        hdr,
        Header {
            width: 2,
            height: 2,
            depth: 8,
            colour: Colour::Rgb,
        }
    );
    assert_eq!(hdr.stride(), 6);
    assert_eq!(hdr.filter_step(), 3);
}

#[test]
fn a_header_shorter_than_the_chunk_is_truncated_not_misread() {
    let file = quad().bytes();
    assert_eq!(header(&file[..20]), Err(Error::Truncated));
}

#[test]
fn an_interlaced_file_is_refused_by_name() {
    let mut png = quad();
    png.interlace = 1;
    let file = png.bytes();
    assert_eq!(header(&file[..HEADER_BYTES]), Err(Error::Interlaced));
    // And the message says so, rather than "damaged".
    assert!(Error::Interlaced.why().contains("interlaced"));
}

#[test]
fn a_depth_the_colour_type_does_not_allow_is_refused() {
    // Truecolour at 4 bits does not exist. Source: PNG spec table 6.1
    let png = Png::new(2, 2, 4, 2, vec![0; 8]);
    assert_eq!(
        header(&png.bytes()[..HEADER_BYTES]),
        Err(Error::BadHeader),
        "a depth outside the table was accepted"
    );
}

#[test]
fn a_small_picture_comes_back_pixel_for_pixel() {
    // 2x2 into a 2x2 space: no resampling at all, so the colours must survive exactly.
    let (plan, rows) = draw(&quad().bytes(), 2, 2).expect("decodes");
    assert_eq!(plan.scale, Scale::Up(1));
    assert_eq!((plan.w, plan.h), (2, 2));
    assert_eq!(rows[0], vec![rgb(255, 0, 0), rgb(0, 255, 0)]);
    assert_eq!(rows[1], vec![rgb(0, 0, 255), rgb(255, 255, 255)]);
}

#[test]
fn every_filter_reconstructs_the_same_picture() {
    // One image, encoded five times, once under each filter. A filter implemented
    // wrongly shows up as a picture that differs from the other four.
    let width = 8usize;
    let rows: Vec<Vec<u8>> = (0..6)
        .map(|y: usize| {
            (0..width * 3)
                .map(|i| ((y * 37 + i * 11) % 256) as u8)
                .collect()
        })
        .collect();

    let mut want = None;
    for kind in 0..=4u8 {
        let mut raw = Raw::new();
        let mut prev = vec![0u8; width * 3];
        for row in &rows {
            raw.filtered(kind, row, &prev, 3);
            prev = row.clone();
        }
        let file = Png::new(width as u32, rows.len() as u32, 8, 2, raw.bytes).bytes();
        let (_, got) = draw(&file, width, rows.len()).expect("decodes");
        match &want {
            None => want = Some(got),
            Some(w) => assert_eq!(&got, w, "filter {kind} reconstructs differently"),
        }
    }
    // And it is the picture that went in, not five copies of the same wrong thing.
    let got = want.expect("five filters");
    for (y, row) in rows.iter().enumerate() {
        let expect: Vec<u16> = row.chunks(3).map(|p| rgb(p[0], p[1], p[2])).collect();
        assert_eq!(got[y], expect, "row {y}");
    }
}

#[test]
fn an_unknown_filter_byte_is_damage_not_a_guess() {
    let mut raw = Raw::new();
    raw.row(&[1, 2, 3, 4, 5, 6]);
    raw.bytes[0] = 9; // no such filter
    let file = Png::new(2, 1, 8, 2, raw.bytes).bytes();
    assert_eq!(draw(&file, 320, 240), Err(Error::Damaged));
}

#[test]
fn shrinking_averages_the_pixels_it_covers() {
    // Four known colours into one pixel: the mean of each channel, not one of them.
    let (plan, rows) = draw(&quad().bytes(), 1, 1).expect("decodes");
    assert_eq!((plan.w, plan.h), (1, 1));
    assert_eq!(plan.scale, Scale::Down);
    // (255+0+0+255)/4 = 127.5 -> 128, (0+255+0+255)/4 = 127.5 -> 128,
    // (0+0+255+255)/4 = 127.5 -> 128. Quantised to 565 afterwards.
    assert_eq!(rows[0][0], rgb(128, 128, 128));
}

#[test]
fn shrinking_by_a_ratio_that_does_not_divide_still_uses_every_pixel() {
    // 3 pixels into 2: the middle source pixel is split between both output pixels,
    // which is the case nearest-neighbour would get visibly wrong.
    let mut raw = Raw::new();
    raw.row(&[0, 0, 0, 120, 120, 120, 240, 240, 240]);
    let file = Png::new(3, 1, 8, 2, raw.bytes).bytes();
    let (plan, rows) = draw(&file, 2, 1).expect("decodes");
    assert_eq!((plan.w, plan.h), (2, 1));
    // Output pixel 0 covers all of source 0 and half of source 1: (0*2 + 120*1)/3 = 40.
    // Output pixel 1 covers half of source 1 and all of source 2: (120 + 240*2)/3 = 200.
    assert_eq!(rows[0], vec![rgb(40, 40, 40), rgb(200, 200, 200)]);
}

#[test]
fn the_proportions_are_kept_whichever_edge_binds() {
    let wide = Header {
        width: 1000,
        height: 500,
        depth: 8,
        colour: Colour::Rgb,
    };
    let plan = fit(&wide, 320, 240);
    assert_eq!((plan.w, plan.h), (320, 160));

    let tall = Header {
        width: 100,
        height: 1000,
        depth: 8,
        colour: Colour::Rgb,
    };
    let plan = fit(&tall, 320, 240);
    assert_eq!((plan.w, plan.h), (24, 240));

    // Never taller or wider than the space, whatever the rounding.
    for w in 1..64u32 {
        for h in 1..64u32 {
            let hdr = Header {
                width: w * 7 + 1,
                height: h * 13 + 1,
                depth: 8,
                colour: Colour::Rgb,
            };
            let plan = fit(&hdr, 320, 240);
            assert!(plan.w <= 320 && plan.h <= 240, "{plan:?} for {hdr:?}");
            assert!(plan.w >= 1 && plan.h >= 1, "{plan:?} for {hdr:?}");
        }
    }
}

#[test]
fn a_small_picture_is_enlarged_by_whole_steps_only() {
    // 4x4 on a 320x240 panel: 60 steps fit vertically, 80 horizontally, so 60.
    let hdr = Header {
        width: 4,
        height: 4,
        depth: 8,
        colour: Colour::Rgb,
    };
    assert_eq!(
        fit(&hdr, 320, 240),
        Plan {
            w: 240,
            h: 240,
            scale: Scale::Up(60)
        }
    );

    // And the pixels are repeated, not interpolated: the 2x2 quad at 2x is four solid
    // blocks with no blended pixel anywhere.
    let (plan, rows) = draw(&quad().bytes(), 5, 4).expect("decodes");
    assert_eq!(plan.scale, Scale::Up(2));
    assert_eq!((plan.w, plan.h), (4, 4));
    assert_eq!(
        rows[0],
        vec![
            rgb(255, 0, 0),
            rgb(255, 0, 0),
            rgb(0, 255, 0),
            rgb(0, 255, 0)
        ]
    );
    assert_eq!(rows[1], rows[0]);
    assert_eq!(
        rows[2],
        vec![
            rgb(0, 0, 255),
            rgb(0, 0, 255),
            rgb(255, 255, 255),
            rgb(255, 255, 255)
        ]
    );
    assert_eq!(rows[3], rows[2]);
}

#[test]
fn grey_at_every_depth_scales_to_the_full_range() {
    // One set pixel and one clear one, at each depth a greyscale file may use. The set
    // one must come out white -- not half grey, which is what shifting instead of
    // scaling would give at depth 1.
    for depth in [1u8, 2, 4, 8, 16] {
        let raw = match depth {
            1 => vec![0, 0b0100_0000],
            2 => vec![0, 0b0011_0000],
            4 => vec![0, 0x0F],
            8 => vec![0, 0x00, 0xFF],
            _ => vec![0, 0x00, 0x00, 0xFF, 0xFF],
        };
        let file = Png::new(2, 1, depth, 0, raw).bytes();
        let (_, rows) = draw(&file, 2, 1).unwrap_or_else(|e| panic!("depth {depth}: {e:?}"));
        assert_eq!(
            rows[0],
            vec![rgb(0, 0, 0), rgb(255, 255, 255)],
            "depth {depth} did not reach both ends of the range"
        );
    }
}

#[test]
fn a_palette_is_looked_up_and_its_alpha_composited() {
    // Three entries; the middle one is half transparent.
    let mut png = Png::new(3, 1, 8, 3, vec![0, 0, 1, 2]);
    png.palette = Some(vec![255, 0, 0, 0, 255, 0, 0, 0, 255]);
    png.trns = Some(vec![255, 128]);
    let (_, rows) = draw_on(&png.bytes(), 3, 1, [0, 0, 0], 1024).expect("decodes");
    assert_eq!(rows[0][0], rgb(255, 0, 0));
    // 128/255 of green over black.
    assert_eq!(rows[0][1], rgb(0, 128, 0));
    // No `tRNS` entry: opaque.
    assert_eq!(rows[0][2], rgb(0, 0, 255));
}

#[test]
fn an_index_the_palette_never_defined_is_refused() {
    let mut png = Png::new(2, 1, 8, 3, vec![0, 0, 5]);
    png.palette = Some(vec![255, 0, 0]);
    assert_eq!(draw(&png.bytes(), 320, 240), Err(Error::BadPalette));
}

#[test]
fn alpha_is_composited_onto_the_background_the_caller_names() {
    // Solid red at half alpha, onto white and onto black.
    let file = Png::new(1, 1, 8, 6, vec![0, 255, 0, 0, 128]).bytes();
    let (_, on_white) = draw_on(&file, 1, 1, [255, 255, 255], 1024).expect("decodes");
    let (_, on_black) = draw_on(&file, 1, 1, [0, 0, 0], 1024).expect("decodes");
    assert_eq!(on_white[0][0], rgb(255, 127, 127));
    assert_eq!(on_black[0][0], rgb(128, 0, 0));
}

#[test]
fn a_transparent_colour_is_honoured_for_types_without_an_alpha_channel() {
    // `tRNS` on a truecolour file names one colour as see-through.
    let mut raw = Raw::new();
    raw.row(&[255, 0, 0, 0, 255, 0]);
    let mut png = Png::new(2, 1, 8, 2, raw.bytes);
    // Green, as the format writes it: two bytes a channel, red first.
    png.trns = Some(vec![0, 0, 0, 255, 0, 0]);
    let (_, rows) = draw_on(&png.bytes(), 2, 1, [0, 0, 255], 1024).expect("decodes");
    assert_eq!(rows[0][0], rgb(255, 0, 0));
    assert_eq!(
        rows[0][1],
        rgb(0, 0, 255),
        "the transparent pixel is not the background"
    );
}

#[test]
fn grey_with_alpha_is_read_as_two_samples() {
    let file = Png::new(2, 1, 8, 4, vec![0, 0xFF, 0xFF, 0xFF, 0x00]).bytes();
    let (_, rows) = draw_on(&file, 2, 1, [0, 0, 0], 1024).expect("decodes");
    assert_eq!(rows[0][0], rgb(255, 255, 255));
    assert_eq!(
        rows[0][1],
        rgb(0, 0, 0),
        "a fully clear pixel is the background"
    );
}

#[test]
fn sixteen_bit_samples_are_taken_at_eight() {
    let file = Png::new(1, 1, 16, 2, vec![0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]).bytes();
    let (_, rows) = draw(&file, 1, 1).expect("decodes");
    assert_eq!(rows[0][0], rgb(0x12, 0x56, 0x9A));
}

#[test]
fn the_file_can_arrive_one_byte_at_a_time() {
    // The reader is allowed to return as little as it likes, and the chunk parser has
    // to hold its place across every boundary -- including inside a chunk header.
    let file = quad().bytes();
    let whole = draw_on(&file, 2, 2, [255, 255, 255], 1024).expect("decodes");
    let dribbled = draw_on(&file, 2, 2, [255, 255, 255], 1).expect("decodes");
    assert_eq!(whole.1, dribbled.1);
}

#[test]
fn chunks_this_does_not_understand_are_stepped_over() {
    let mut png = quad();
    png.extra
        .push((*b"tEXt", b"Comment\0by another tool".to_vec()));
    png.extra
        .push((*b"pHYs", vec![0, 0, 11, 18, 0, 0, 11, 18, 1]));
    let (_, rows) = draw(&png.bytes(), 2, 2).expect("decodes");
    assert_eq!(rows[0], vec![rgb(255, 0, 0), rgb(0, 255, 0)]);
}

#[test]
fn a_file_that_stops_early_is_truncated_not_a_half_picture() {
    let file = quad().bytes();
    let cut = &file[..file.len() - 12];
    assert_eq!(draw(cut, 2, 2), Err(Error::Truncated));
}

#[test]
fn a_chunk_whose_crc_does_not_match_is_refused() {
    let mut file = quad().bytes();
    // The last byte of the IHDR CRC.
    let at = 8 + 8 + 13 + 3;
    file[at] ^= 0xFF;
    assert_eq!(draw(&file, 2, 2), Err(Error::BadCrc));
}

#[test]
fn damaged_image_data_is_refused_rather_than_drawn() {
    let mut file = quad().bytes();
    // Somewhere inside the compressed stream, past its two-byte zlib header.
    let at = file.len() - 20;
    file[at] ^= 0xFF;
    assert!(
        matches!(draw(&file, 2, 2), Err(Error::Damaged | Error::Truncated)),
        "corrupt image data was accepted"
    );
}

#[test]
fn buffers_sized_for_a_different_picture_are_refused_up_front() {
    let file = quad().bytes();
    let hdr = header(&file[..HEADER_BYTES]).expect("a header");
    let plan = fit(&hdr, 2, 2);
    let mut window = vec![0u8; WINDOW - 1]; // one byte short of a deflate window
    let mut lines = vec![0u8; hdr.lines_needed()];
    let mut acc = vec![0u32; Buffers::acc_needed(plan.w)];
    let mut out = vec![0u16; plan.w];
    let got = render(
        &hdr,
        &plan,
        Buffers {
            window: &mut window,
            lines: &mut lines,
            acc: &mut acc,
            out: &mut out,
        },
        [255, 255, 255],
        |_| panic!("the file must not be touched"),
        |_, _| panic!("no row can be produced"),
    );
    assert_eq!(got, Err(Error::Buffers));
}

#[test]
fn a_card_that_goes_away_is_the_cards_fault_and_a_screen_that_refuses_is_the_screens() {
    let file = quad().bytes();
    let hdr = header(&file[..HEADER_BYTES]).expect("a header");
    let plan = fit(&hdr, 2, 2);
    let mut window = vec![0u8; WINDOW];
    let mut lines = vec![0u8; hdr.lines_needed()];
    let mut acc = vec![0u32; Buffers::acc_needed(plan.w)];
    let mut out = vec![0u16; plan.w];

    let got = render(
        &hdr,
        &plan,
        Buffers {
            window: &mut window,
            lines: &mut lines,
            acc: &mut acc,
            out: &mut out,
        },
        [255, 255, 255],
        |_| Err(()),
        |_, _| Ok(()),
    );
    assert_eq!(got, Err(Error::Read));

    let mut at = 0usize;
    let got = render(
        &hdr,
        &plan,
        Buffers {
            window: &mut window,
            lines: &mut lines,
            acc: &mut acc,
            out: &mut out,
        },
        [255, 255, 255],
        |buf| {
            let n = buf.len().min(file.len() - at);
            buf[..n].copy_from_slice(&file[at..at + n]);
            at += n;
            Ok(n)
        },
        |_, _| Err(()),
    );
    assert_eq!(
        got,
        Err(Error::Sink),
        "the sink's refusal was reported as the card's"
    );
}

#[test]
fn a_real_file_from_a_real_encoder_decodes() {
    // The paw print the Q1 draws at login: 27x30, written by an image tool rather than
    // by the fixture builder above, so it exercises whatever that tool chose to do --
    // its filters, its palette or lack of one, its chunk order.
    let file = include_bytes!("../../catcard-ui/src/art/paw-right-27x30.png");
    let hdr = header(&file[..HEADER_BYTES]).expect("a header");
    assert_eq!((hdr.width, hdr.height), (27, 30));

    let (plan, rows) = draw(file, 320, 240).expect("decodes");
    // 320/27 = 11, 240/30 = 8, so eight whole steps.
    assert_eq!(
        plan,
        Plan {
            w: 27 * 8,
            h: 240,
            scale: Scale::Up(8)
        }
    );
    assert_eq!(rows.len(), 240);

    // It is a picture, not a flat field: a decoder that produced one colour everywhere
    // would pass every size assertion above.
    let first = rows[0][0];
    assert!(
        rows.iter().flatten().any(|&px| px != first),
        "every pixel came out the same colour"
    );

    // And shrunk, it still has both light and dark in it.
    let (_, small) = draw(file, 16, 16).expect("decodes small");
    let flat: Vec<u16> = small.into_iter().flatten().collect();
    assert!(flat.iter().any(|&px| px > 0x8000));
    assert!(flat.iter().any(|&px| px < 0x4000));
}

#[test]
fn a_larger_real_file_shrinks_to_the_panel() {
    let file = include_bytes!("../../catcard-ui/src/art/cat-60x60.png");
    let hdr = header(&file[..HEADER_BYTES]).expect("a header");
    assert_eq!((hdr.width, hdr.height), (60, 60));
    // Into a space smaller than it is, so this goes through the averaging path.
    let (plan, rows) = draw(file, 40, 40).expect("decodes");
    assert_eq!((plan.w, plan.h, plan.scale), (40, 40, Scale::Down));
    assert_eq!(rows.len(), 40);
    assert!(rows.iter().all(|r| r.len() == 40));
}

#[test]
fn a_tall_thin_picture_is_reduced_without_losing_a_row() {
    // Heights that do not divide the target are where an off-by-one in the vertical
    // weights shows up: the last output row is finished by the last source row or not
    // at all.
    for h in [7u32, 31, 100, 241, 1000] {
        let mut raw = Raw::new();
        for y in 0..h {
            raw.row(&[(y % 256) as u8, 0, 0]);
        }
        let file = Png::new(1, h, 8, 2, raw.bytes).bytes();
        let (plan, rows) = draw(&file, 320, 240).unwrap_or_else(|e| panic!("h={h}: {e:?}"));
        assert_eq!(rows.len(), plan.h, "h={h}");
    }
}
