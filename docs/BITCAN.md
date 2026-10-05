# BitCan glyphs

[BitCan](https://bitcan.world) draws each BIP-39 word as a glyph of eleven lines, one per
bit of the word's wordlist index. CatCard shows a seed's words that way and reads them
back in that way, on the mk4, mk5 and Q1. The mk3 has no room for it.

## The format

Source: https://bitcan.world, format definition [C]. Implemented from the definition in
`crates/catcard-ui/src/bitcan.rs`; none of the site's code is used.

- The glyph sits in a box 50 wide and 100 tall: two squares, one on top of the other.
- Every line is drawn. A set bit is **bold** and a clear bit is **light**, so a missing
  line means a damaged glyph, never a zero.
- Line `i` is bit `i` of the index (0 for `abandon` up to 2047 for `zoo`):

  | bit | line |
  |---|---|
  | 0 | top edge |
  | 1 | top square, left edge |
  | 2 | top square, `\` diagonal |
  | 3 | top square, `/` diagonal |
  | 4 | top square, right edge |
  | 5 | middle edge, shared by the two squares |
  | 6 | bottom square, left edge |
  | 7 | bottom square, `\` diagonal |
  | 8 | bottom square, `/` diagonal |
  | 9 | bottom square, right edge |
  | 10 | bottom edge |

- There are two drawings of the same bits. They differ only in the four diagonals:
  - **Stack** crosses each square with an X.
  - **Fold** turns the diagonals into a V in the top square and an inverted V in the bottom
    one, both meeting near the middle edge.
- A glyph has no checksum. The phrase's BIP-39 checksum covers the glyphs, as it covers
  the words.

## Showing a seed as glyphs

Every screen that shows seed words to write down offers the glyphs too: new seed, View
seed words, backup words and Seed XOR parts. The words screen says `1: show as BitCan`.

The glyphs come a page at a time:

- four across the OLED;
- two rows of six on the Q1, with light lines in grey.

Each glyph carries its word number.

| key | action |
|---|---|
| `5` `8` (or `7` `9`) | turn the page |
| `1` | swap between Stack and Fold |
| `OK` | next page; on the last page, finish |
| `x` | back to the words |

As with the words, `OK` cannot finish until every page has been on screen.

## Entering a seed as glyphs

You can enter glyphs in two places:

- `Import` → `BitCan` stores the seed.
- Derive → `Import key` → `BitCan` uses it for this session only.

Either way, it is the same import as `Words`:

1. The word count is asked first.
2. The last word is checked against the checksum-valid set.
3. A phrase that fails its checksum opens the same fix-a-word menu.

Each word is asked line by line, starting at the bottom edge and working up. This is the
order the BitCan site recommends for reading: each line halves the words the glyph could
be. The screen shows the glyph so far, the line being asked (thick and dashed), and the
first and last words still possible.

| key | action |
|---|---|
| `1` | the line is bold |
| `0` | the line is light |
| `x` | back one line; at the first line, back to the previous word |

After the eleventh line, the word is shown in large type and `OK` takes it.

When the count is "not sure", pressing `OK` twice on an empty glyph ends the phrase.
