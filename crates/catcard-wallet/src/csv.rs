//! The address export's rows: index, path, address, one line each.
//!
//! A file written here is read by a spreadsheet, or by a script, on a machine the device
//! knows nothing about. So the shape is RFC 4180 and not "commas and newlines": every
//! field is quoted, an embedded quote is doubled, and every row ends `\r\n`. None of the
//! three fields can contain a comma today -- an index is digits, a path is digits and
//! separators, an address is base58 or bech32 -- but a writer that *depends* on that is
//! one address format away from silently splitting a row in two, and a row that splits
//! puts an address under the wrong index. Quoting costs two bytes and removes the
//! question.
//!
//! Nothing here buffers a row. Each field is streamed into the caller's writer through an
//! escaping adapter, so a fixed-size sink on the device decides how much it will take,
//! and a path of any depth costs no stack here.
//!
//! This lives in the wallet crate rather than in the firmware because it is the part with
//! an answer that can be checked on a host: the firmware side is a card mount and a
//! screen.

use core::fmt::{Display, Write};

use crate::bip32::DerivationPath;

/// The header row's columns, in the order they are written.
pub const ADDRESS_COLUMNS: [&str; 3] = ["index", "path", "address"];

/// Write the header row.
pub fn write_header(out: &mut impl Write) -> core::fmt::Result {
    for (i, name) in ADDRESS_COLUMNS.iter().enumerate() {
        separate(out, i)?;
        quoted(out, name)?;
    }
    end_row(out)
}

/// Write one address row: which index it is, the path it sits at, and the address.
///
/// `index` is the last step of `path` for a normal walk, and is written on its own
/// anyway: a reader sorting or filtering by index should not have to parse the path to
/// find it, and for a registered multisig wallet the path shown is relative to the
/// wallet rather than to any one seed.
pub fn write_address_row(
    out: &mut impl Write,
    index: u32,
    path: &DerivationPath,
    address: &str,
) -> core::fmt::Result {
    quoted(out, index)?;
    separate(out, 1)?;
    quoted(out, path)?;
    separate(out, 2)?;
    quoted(out, address)?;
    end_row(out)
}

/// The comma before every field but the first.
fn separate(out: &mut impl Write, field: usize) -> core::fmt::Result {
    if field > 0 {
        out.write_char(',')?;
    }
    Ok(())
}

/// CRLF, which is what RFC 4180 says and what the spreadsheet on the other end of a
/// microSD card expects. A lone LF is read by some of them as one enormous cell.
fn end_row(out: &mut impl Write) -> core::fmt::Result {
    out.write_str("\r\n")
}

/// One field: opening quote, the value with every quote inside it doubled, closing quote.
fn quoted(out: &mut impl Write, value: impl Display) -> core::fmt::Result {
    out.write_char('"')?;
    write!(Escape(out), "{value}")?;
    out.write_char('"')
}

/// A writer that doubles every `"` on its way through, so a value carrying one cannot
/// close the field it is inside.
struct Escape<'a, W: Write>(&'a mut W);

impl<W: Write> Write for Escape<'_, W> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // Split on the quotes and put two back for each one; the common case writes the
        // whole string in one call.
        let mut rest = s;
        while let Some(at) = rest.find('"') {
            self.0.write_str(&rest[..at])?;
            self.0.write_str("\"\"")?;
            rest = &rest[at + 1..];
        }
        self.0.write_str(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    fn row(index: u32, path: &str, address: &str) -> String {
        let mut out = String::new();
        write_address_row(
            &mut out,
            index,
            &DerivationPath::from_str(path).unwrap(),
            address,
        )
        .unwrap();
        out
    }

    #[test]
    fn a_row_is_index_path_address() {
        assert_eq!(
            row(5, "m/84h/0h/0h/0/5", "bc1qexample"),
            "\"5\",\"m/84h/0h/0h/0/5\",\"bc1qexample\"\r\n"
        );
    }

    #[test]
    fn the_header_names_the_columns_in_the_order_they_are_written() {
        let mut out = String::new();
        write_header(&mut out).unwrap();
        assert_eq!(out, "\"index\",\"path\",\"address\"\r\n");
        // The header has as many fields as a row does; a reader lines them up by
        // position, so one missing column puts every address in the path's place.
        let data = row(0, "m/0", "addr");
        assert_eq!(out.matches(',').count(), data.matches(',').count());
    }

    // The failure mode: an address (or a path) that contains a comma ends up as two
    // fields, so the address column of that row holds half an address -- which still
    // looks like an address.
    #[test]
    fn a_comma_in_a_field_does_not_split_the_row() {
        let line = row(1, "m/0", "one,two");
        assert_eq!(line, "\"1\",\"m/0\",\"one,two\"\r\n");
        assert_eq!(line.lines().count(), 1);
        // Three quoted fields, not four.
        assert_eq!(line.matches('"').count(), 6);
    }

    // The failure mode: a quote inside a field closes it early, and what follows is read
    // as another field -- or as the start of one that never ends, which swallows the
    // rest of the file.
    #[test]
    fn a_quote_in_a_field_is_doubled() {
        assert_eq!(row(1, "m/0", "a\"b"), "\"1\",\"m/0\",\"a\"\"b\"\r\n");
        // Two quotes in, four out, and the field's own pair around them: six.
        assert_eq!(row(1, "m/0", "\"\""), "\"1\",\"m/0\",\"\"\"\"\"\"\r\n");
    }

    // The failure mode: a newline inside a field ends the row, so one address becomes
    // two rows and every index after it is read against the wrong path.
    #[test]
    fn a_newline_in_a_field_stays_inside_its_quotes() {
        let line = row(1, "m/0", "a\nb");
        assert_eq!(line, "\"1\",\"m/0\",\"a\nb\"\r\n");
    }

    // The failure mode: rows written with a bare LF, which some spreadsheets read as one
    // cell -- and a row that does not end at all runs into the next one.
    #[test]
    fn every_row_ends_with_crlf() {
        let mut out = String::new();
        write_header(&mut out).unwrap();
        for i in 0..3 {
            write_address_row(
                &mut out,
                i,
                &DerivationPath::from_str("m/84h/0h/0h/0/0").unwrap(),
                "bc1q",
            )
            .unwrap();
        }
        assert_eq!(out.matches("\r\n").count(), 4);
        assert_eq!(out.matches('\n').count(), 4, "no bare LF anywhere");
    }

    // The failure mode: the hardened marker lost between the path and the file, so the
    // export names a path that derives a different key.
    #[test]
    fn the_path_column_keeps_its_hardened_markers() {
        assert!(row(5, "m/48'/0'/0'/2'/0/5", "bc1q").contains("\"m/48h/0h/0h/2h/0/5\""));
    }

    #[test]
    fn the_deepest_path_is_written_in_full() {
        let deep = core::iter::repeat_n("2147483647h", crate::bip32::MAX_PATH_DEPTH)
            .collect::<Vec<_>>()
            .join("/");
        let line = row(u32::MAX, &format!("m/{deep}"), "bc1q");
        assert!(line.contains("2147483647h/2147483647h"));
        assert!(line.starts_with("\"4294967295\","));
    }
}
