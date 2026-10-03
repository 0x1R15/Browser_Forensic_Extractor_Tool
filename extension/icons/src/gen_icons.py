#!/usr/bin/env python3
"""Generates the FBEx toolbar/store icons (16/32/48/128 px) with a pure-stdlib
rasterizer: signed-distance fields + 4x supersampling, encoded as PNG via zlib.

Design: dark slate rounded square, emerald magnifier (forensic lens) with a
data-bar motif inside the lens; matches the tool's dashboard palette.
Run from anywhere:  python3 extension/icons/src/gen_icons.py
"""

import os
import struct
import zlib

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SIZES = [16, 32, 48, 128]
SS = 4  # supersample factor

# palette (dashboard tokens)
BG = (15, 23, 42)       # #0F172A
RING = (16, 185, 129)   # #10B981 emerald
BARS = (125, 178, 251)  # light blue data bars


def clamp01(x):
    return 0.0 if x < 0 else (1.0 if x > 1.0 else x)


def mix(a, b, t):
    t = clamp01(t)
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded_rect_sdf(px, py, cx, cy, hw, hh, r):
    qx = abs(px - cx) - (hw - r)
    qy = abs(py - cy) - (hh - r)
    return min(max(qx, qy), 0.0) + (max(qx, 0.0) ** 2 + max(qy, 0.0) ** 2) ** 0.5 - r


def circle_ring_sdf(px, py, cx, cy, r, w):
    return abs(((px - cx) ** 2 + (py - cy) ** 2) ** 0.5 - r) - w / 2


def segment_sdf(px, py, ax, ay, bx, by, w):
    abx, aby = bx - ax, by - ay
    apx, apy = px - ax, py - ay
    t = clamp01((apx * abx + apy * aby) / (abx * abx + aby * aby))
    dx, dy = apx - t * abx, apy - t * aby
    return (dx * dx + dy * dy) ** 0.5 - w / 2


def render(size):
    """Returns size x size RGB rows: background card + lens + bars."""
    S = size * SS
    # geometry in the supersampled grid
    m = S * 0.04            # outer margin
    # card covers everything (rounded), icon is the card itself
    rows = []
    # lens geometry
    lens_r = S * 0.30
    lens_c = (S * 0.44, S * 0.42)
    ring_w = S * 0.085
    # handle: from lens edge to bottom-right corner area
    hx0, hy0 = S * 0.645, S * 0.635
    hx1, hy1 = S * 0.86, S * 0.85
    handle_w = S * 0.105
    # bars inside lens (three ascending), expressed in lens-local box
    bars = []
    bx0, bw = S * 0.335, S * 0.055
    for i, hfrac in enumerate((0.16, 0.26, 0.20)):
        bxx = bx0 + i * (bw + S * 0.045)
        byy = S * 0.42 + lens_r * 0.42 - hfrac * S  # top of bar
        bars.append((bxx, byy, bxx + bw, byy + hfrac * S))

    for y in range(S):
        row = []
        for x in range(S):
            # background rounded card
            d_card = rounded_rect_sdf(x + 0.5, y + 0.5, S / 2, S / 2, S / 2 - m, S / 2 - m, S * 0.22)
            if d_card > 0.5:
                row.append(None)  # transparent (alpha handled below)
                continue
            color = BG
            # ring
            d_ring = circle_ring_sdf(x + 0.5, y + 0.5, lens_c[0], lens_c[1], lens_r, ring_w)
            if d_ring < 0.5:
                color = mix(RING, color, clamp01(d_ring + 0.5))
            # handle
            d_h = segment_sdf(x + 0.5, y + 0.5, hx0, hy0, hx1, hy1, handle_w)
            if d_h < 0.5:
                color = mix(RING, color, clamp01(d_h + 0.5))
            # bars (only inside lens opening)
            d_open = ((x + 0.5 - lens_c[0]) ** 2 + (y + 0.5 - lens_c[1]) ** 2) ** 0.5
            if d_open < lens_r - ring_w * 0.55:
                for (x0, y0, x1, y1) in bars:
                    if x0 <= x + 0.5 <= x1 and y0 <= y + 0.5 <= y1:
                        color = BARS
                        break
            row.append(color)
        rows.append(row)

    # downsample SS x SS -> 1 px, with alpha coverage
    out = []
    for y in range(size):
        orow = []
        for x in range(size):
            r = g = b = a = 0
            for dy in range(SS):
                for dx in range(SS):
                    c = rows[y * SS + dy][x * SS + dx]
                    if c is not None:
                        r += c[0]; g += c[1]; b += c[2]; a += 1
            if a == 0:
                orow.append((0, 0, 0, 0))
            else:
                n = SS * SS
                # blend against transparent -> premultiplied look is fine on solid bg
                orow.append((round(r / a), round(g / a), round(b / a), round(255 * a / n)))
        out.append(orow)
    return out


def png_rgba(path, size, pixels):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = b"".join(
        b"\x00" + bytes(v for px in row for v in px)
        for row in pixels
    )
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    blob = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(blob)


def main():
    for size in SIZES:
        px = render(size)
        path = os.path.abspath(os.path.join(OUT_DIR, f"icon{size}.png"))
        png_rgba(path, size, px)
        print(f"wrote {path} ({size}x{size})")


if __name__ == "__main__":
    main()
