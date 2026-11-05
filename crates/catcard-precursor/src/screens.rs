//! Text for the Precursor's own screens.

use core::fmt::Write;

use heapless::String;

use crate::rngcheck::Summary;

/// One line of a screen. `Layout::large()` fits 23 columns on the 336-pixel panel (14-pixel
/// cells after a 12-pixel margin); lines here are written to stay within 22.
pub type Line = String<32>;

/// The entropy self-test, as a screen: one line per source, then the pool's verdict.
/// Verdicts and rates only -- the same things the UART report may say.
pub fn entropy_lines(s: &Summary) -> [Line; 6] {
    let mut out: [Line; 6] = Default::default();
    for (line, src) in out.iter_mut().zip(s.sources.iter()) {
        let verdict = if !src.read_ok {
            "FAIL"
        } else if !src.startup_passed || src.trips > 0 {
            "BAD"
        } else {
            "ok"
        };
        let _ = write!(line, "{:10}{:5}", src.which.label(), verdict);
        if src.read_ok {
            let _ = write!(line, "{}K/s", src.rate / 1000);
        }
    }
    let _ = write!(out[3], "sources   {} of 2", s.hardware_sources);
    let _ = write!(out[4], "credited  {} bits", s.credited_bits);
    let _ = write!(
        out[5],
        "seed      {}",
        if s.granted { "allowed" } else { "REFUSED" }
    );
    out
}
