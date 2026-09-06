#!/usr/bin/env python3
"""Rasterise the CatCard cat logo into a 1-bit bitmap for the splash screen.

Reads the primitives out of the source SVG rather than tracing it by hand, so the art
regenerates if the logo changes. The SVG is plain geometry — triangles, circles,
ellipses, lines and one quadratic — which is why this needs no SVG library.

A monochrome OLED cannot render the original's gradients, so the mapping is chosen for
legibility at ~48 pixels rather than fidelity: the head and ears become **outlines**
(a filled silhouette that size is a heavy blob and reads as nothing), while the eyes
and nose stay **filled**, which is what makes it read as a face. The whiskers are
mirrored to point outward from the head, because inside an empty outline they read as
stray dashes rather than as whiskers.
"""
import math, re, sys


class Canvas:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.px = [[0] * w for _ in range(h)]

    def set(self, x, y):
        x, y = int(round(x)), int(round(y))
        if 0 <= x < self.w and 0 <= y < self.h:
            self.px[y][x] = 1

    def line(self, x0, y0, x1, y1):
        # Bresenham, on rounded endpoints.
        x0, y0, x1, y1 = (int(round(v)) for v in (x0, y0, x1, y1))
        dx, dy = abs(x1 - x0), -abs(y1 - y0)
        sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
        err = dx + dy
        while True:
            self.set(x0, y0)
            if x0 == x1 and y0 == y1:
                return
            e2 = 2 * err
            if e2 >= dy:
                err += dy
                x0 += sx
            if e2 <= dx:
                err += dx
                y0 += sy

    def circle_outline(self, cx, cy, r):
        # Sample by angle: at these radii it closes without gaps and the code stays
        # short. Midpoint would be faster and this runs once, at build time.
        steps = max(64, int(r * 12))
        for i in range(steps):
            a = 2 * math.pi * i / steps
            self.set(cx + r * math.cos(a), cy + r * math.sin(a))

    def ellipse_filled(self, cx, cy, rx, ry):
        for y in range(int(cy - ry - 1), int(cy + ry + 2)):
            for x in range(int(cx - rx - 1), int(cx + rx + 2)):
                if rx > 0 and ry > 0 and ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1.0:
                    self.set(x, y)

    def triangle_filled(self, pts):
        # Point-in-triangle over the bounding box. At a few pixels a scanline fill would
        # be more code for no gain, and this runs once at build time.
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        def side(a, b, px, py):
            return (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])
        for y in range(int(math.floor(min(ys))), int(math.ceil(max(ys))) + 1):
            for x in range(int(math.floor(min(xs))), int(math.ceil(max(xs))) + 1):
                d = [side(pts[i], pts[(i + 1) % 3], x, y) for i in range(3)]
                if all(v >= 0 for v in d) or all(v <= 0 for v in d):
                    self.set(x, y)

    def triangle_outline(self, pts):
        for i in range(3):
            self.line(*pts[i], *pts[(i + 1) % 3])

    def quad(self, p0, p1, p2):
        steps = 32
        for i in range(steps + 1):
            t = i / steps
            u = 1 - t
            self.set(
                u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
                u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1],
            )

    def crop_to_ink(self):
        rows = [y for y in range(self.h) if any(self.px[y])]
        cols = [x for x in range(self.w) if any(self.px[y][x] for y in range(self.h))]
        if not rows:
            return self
        out = Canvas(len(cols), len(rows))
        for yi, y in enumerate(rows):
            for xi, x in enumerate(cols):
                out.px[yi][xi] = self.px[y][x]
        return out


def parse(svg):
    """Pull out the primitives this logo is built from."""
    prim = {"tri": [], "circle": [], "ellipse": [], "line": [], "quad": []}
    for d in re.findall(r'<path d="(M[^"]*?Z)"', svg):
        nums = [float(n) for n in re.findall(r"-?\d+\.?\d*", d)]
        if len(nums) == 6:
            prim["tri"].append([(nums[0], nums[1]), (nums[2], nums[3]), (nums[4], nums[5])])
    for m in re.finditer(r'<circle cx="([\d.]+)" cy="([\d.]+)" r="([\d.]+)"', svg):
        prim["circle"].append(tuple(float(g) for g in m.groups()))
    for m in re.finditer(
        r'<ellipse cx="([\d.]+)" cy="([\d.]+)" rx="([\d.]+)" ry="([\d.]+)"', svg
    ):
        prim["ellipse"].append(tuple(float(g) for g in m.groups()))
    for m in re.finditer(
        r'<line x1="([\d.]+)" y1="([\d.]+)" x2="([\d.]+)" y2="([\d.]+)"', svg
    ):
        prim["line"].append(tuple(float(g) for g in m.groups()))
    for m in re.finditer(r'd="M([\d.]+) ([\d.]+) Q([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+)"', svg):
        n = [float(g) for g in m.groups()]
        prim["quad"].append(((n[0], n[1]), (n[2], n[3]), (n[4], n[5])))
    return prim


def render(prim, size, view=64.0):
    s = size / view
    c = Canvas(size, size)

    # Head: the largest circle. Outline only.
    head = max(prim["circle"], key=lambda t: t[2])
    c.circle_outline(head[0] * s, head[1] * s, head[2] * s)

    # Ears: the two largest triangles, outlined. The inner-ear triangles are dropped —
    # at this size they land on top of the outer ones and just thicken them to mud.
    #
    # Drawn into their own layer and merged only *outside* the head, because the SVG
    # paints the face circle over the ears and that hides their lower edges. Without the
    # occlusion those edges cut straight across the face and it stops reading as a cat.
    ears = sorted(prim["tri"], key=lambda t: -abs(
        (t[1][0] - t[0][0]) * (t[2][1] - t[0][1]) - (t[2][0] - t[0][0]) * (t[1][1] - t[0][1])
    ))[:2]
    layer = Canvas(size, size)
    for t in ears:
        layer.triangle_outline([(x * s, y * s) for x, y in t])
    hx, hy, hr = head[0] * s, head[1] * s, head[2] * s
    for y in range(size):
        for x in range(size):
            if layer.px[y][x] and (x - hx) ** 2 + (y - hy) ** 2 > (hr - 0.5) ** 2:
                c.set(x, y)

    # Nose: the smallest triangle, **filled**. Outlined it is a hollow ring about four
    # pixels across, which reads as a smudge rather than a triangle.
    nose = min(prim["tri"], key=lambda t: abs(
        (t[1][0] - t[0][0]) * (t[2][1] - t[0][1]) - (t[2][0] - t[0][0]) * (t[1][1] - t[0][1])
    ))
    c.triangle_filled([(x * s, y * s) for x, y in nose])

    # Eyes: filled, and what makes it read as a face rather than a circle.
    for cx, cy, rx, ry in prim["ellipse"]:
        c.ellipse_filled(cx * s, cy * s, max(1.0, rx * s * 0.6), max(1.0, ry * s * 0.6))

    # Mouth.
    for p0, p1, p2 in prim["quad"]:
        c.quad(*[(x * s, y * s) for x, y in (p0, p1, p2)])

    # Whiskers, mirrored to point *outward*. In the SVG they run inward across a filled
    # face, which works there because the face is solid and they read as lighter strokes
    # over it. Here the head is an outline and its interior is empty, so inward whiskers
    # land next to the eyes and mouth and read as three stray dashes per cheek. Reflected
    # about the head's edge they read immediately, and they are the reason a 48-pixel
    # outline says "cat" rather than "face".
    #
    # Each is anchored where its line leaves the head rather than at the SVG endpoint:
    # the SVG puts those endpoints on the circle only for the middle pair, and a whisker
    # floating a pixel clear of the outline looks like dirt.
    for x1, y1, x2, y2 in prim["line"]:
        ax, ay = x1 * s, y1 * s
        length = math.hypot(ax - x2 * s, ay - y2 * s)
        if length == 0:
            continue
        dx, dy = (ax - x2 * s) / length, (ay - y2 * s) / length
        # Where the ray from (ax, ay) along (dx, dy) exits the head circle.
        fx, fy = ax - hx, ay - hy
        b = fx * dx + fy * dy
        disc = b * b - (fx * fx + fy * fy - hr * hr)
        t0 = -b + math.sqrt(disc) if disc >= 0 else 0.0
        c.line(ax + t0 * dx, ay + t0 * dy, ax + (t0 + length) * dx, ay + (t0 + length) * dy)

    return c


def main(svg_path, size, out_ident):
    prim = parse(open(svg_path).read())
    c = render(prim, size).crop_to_ink()
    bpr = (c.w + 7) // 8

    rows = []
    for y in range(c.h):
        bs = []
        for b in range(bpr):
            v = 0
            for bit in range(8):
                x = b * 8 + bit
                if x < c.w and c.px[y][x]:
                    v |= 0x80 >> bit
            bs.append(v)
        art = "".join("#" if c.px[y][x] else "." for x in range(c.w))
        rows.append("    " + " ".join(f"0x{v:02x}," for v in bs) + f" // {art}")

    print(f'''//! The CatCard cat, as 1-bit pixel art.
//!
//! Rasterised from `cat-logo.svg` by `tools/artgen/svg2rs.py` — regenerate rather than
//! hand-editing. The original is gradient-filled, which a monochrome panel cannot show,
//! so head and ears become outlines and only the eyes and nose stay solid: a filled
//! silhouette at this size is a blob that reads as nothing. The whiskers are mirrored
//! outward from the head, where an empty outline lets them read.
//!
//! Row-major, most significant bit leftmost, {bpr} byte(s) per row.
//!
//! Generated file — do not hand-edit.

use super::Bitmap;

#[rustfmt::skip]
static PIXELS: [u8; {c.h * bpr}] = [
{chr(10).join(rows)}
];

/// {c.w}x{c.h}.
pub static {out_ident}: Bitmap = Bitmap {{
    width: {c.w},
    height: {c.h},
    bytes_per_row: {bpr},
    pixels: &PIXELS,
}};''', file=sys.stderr if False else sys.stdout)

    print(f"\n// preview:\n" + "\n".join(
        "// " + "".join("#" if c.px[y][x] else "." for x in range(c.w)) for y in range(c.h)
    ), file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])
