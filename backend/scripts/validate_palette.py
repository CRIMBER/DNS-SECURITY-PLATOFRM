"""Python port of the data-viz palette validator.

Node.js is not installed in this project's environment (the whole stack is
deliberately Python-only), so the six computable colour checks are ported here
rather than eyeballed. Constants, the Machado-Oliveira-Fernandes (2009)
severity-1.0 CVD matrices and the OKLab conversions are transcribed verbatim
from the reference implementation so results are comparable.

    python backend/scripts/validate_palette.py "#3987e5,#d95926" --mode dark --surface "#121820"

Exit code 1 on any hard FAIL.
"""

import argparse
import math
import sys
from itertools import combinations

BAND = {"light": (0.43, 0.77), "dark": (0.48, 0.67)}
CHROMA_FLOOR = 0.10
CVD_TARGET, CVD_FLOOR = 8.0, 6.0
NORMAL_FLOOR = 15.0
CONTRAST_MIN = 3.0
DEFAULT_SURFACE = {"light": "#fcfcfb", "dark": "#1a1a19"}

MACHADO = {
    "protan": [[0.152286, 1.052583, -0.204868],
               [0.114503, 0.786281, 0.099216],
               [-0.003882, -0.048116, 1.051998]],
    "deutan": [[0.367322, 0.860646, -0.227968],
               [0.280085, 0.672501, 0.047413],
               [-0.011820, 0.042940, 0.968881]],
    "tritan": [[1.255528, -0.076749, -0.178779],
               [-0.078411, 0.930809, 0.147602],
               [0.004733, 0.691367, 0.303900]],
}


def hex2srgb(h):
    h = h.strip().lstrip("#")
    return [int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]


def s2lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def lin(h):
    return [s2lin(c) for c in hex2srgb(h)]


def rel_lum(h):
    r, g, b = lin(h)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    hi, lo = sorted([rel_lum(a), rel_lum(b)], reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def oklab_from_lin(rgb):
    r, g, b = rgb
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return [
        0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
        1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
        0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,
    ]


def oklch(h):
    L, a, b = oklab_from_lin(lin(h))
    return L, math.hypot(a, b)


def simulate(h, kind):
    r, g, b = lin(h)
    M = MACHADO[kind]
    return [
        max(0.0, min(1.0, M[i][0] * r + M[i][1] * g + M[i][2] * b))
        for i in range(3)
    ]


def delta_e(h1, h2, kind=None):
    a = oklab_from_lin(simulate(h1, kind) if kind else lin(h1))
    b = oklab_from_lin(simulate(h2, kind) if kind else lin(h2))
    return 100 * math.dist(a, b)


def validate(palette, mode="light", surface=None, pairs="adjacent"):
    surface = surface or DEFAULT_SURFACE[mode]
    lo, hi = BAND[mode]
    report = []
    ok = True

    offband = [(c, round(oklch(c)[0], 3)) for c in palette
               if not (lo <= oklch(c)[0] <= hi)]
    ok = ok and not offband
    report.append(("Lightness band", not offband,
                   "outside band: {}".format(offband) if offband
                   else "all {} inside L {}-{}".format(len(palette), lo, hi)))

    lowc = [(c, round(oklch(c)[1], 3)) for c in palette if oklch(c)[1] < CHROMA_FLOOR]
    ok = ok and not lowc
    report.append(("Chroma floor", not lowc,
                   "below floor (reads gray): {}".format(lowc) if lowc
                   else "all {} >= {}".format(len(palette), CHROMA_FLOOR)))

    n = len(palette)
    pairlist = (list(combinations(range(n), 2)) if pairs == "all"
                else [(i, i + 1) for i in range(n - 1)])

    worst_cvd, worst_cvd_pair = 999.0, None
    for i, j in pairlist:
        value = min(delta_e(palette[i], palette[j], "protan"),
                    delta_e(palette[i], palette[j], "deutan"))
        if value < worst_cvd:
            worst_cvd, worst_cvd_pair = value, (palette[i], palette[j])
    if pairlist:
        cvd_ok = worst_cvd >= CVD_FLOOR
        status = ("PASS" if worst_cvd >= CVD_TARGET
                  else "WARN (needs secondary encoding)" if cvd_ok else "FAIL")
        ok = ok and cvd_ok
        report.append(("CVD separation ({})".format(pairs), cvd_ok,
                       "worst {:.1f} {} target {} -> {}".format(
                           worst_cvd, worst_cvd_pair, CVD_TARGET, status)))

        worst_norm, worst_norm_pair = 999.0, None
        for i, j in pairlist:
            value = delta_e(palette[i], palette[j])
            if value < worst_norm:
                worst_norm, worst_norm_pair = value, (palette[i], palette[j])
        norm_ok = worst_norm >= NORMAL_FLOOR
        ok = ok and norm_ok
        report.append(("Normal-vision floor", norm_ok,
                       "worst {:.1f} {} floor {}".format(
                           worst_norm, worst_norm_pair, NORMAL_FLOOR)))

    low_contrast = [(c, round(contrast(c, surface), 2)) for c in palette
                    if contrast(c, surface) < CONTRAST_MIN]
    report.append(("Contrast vs {}".format(surface), not low_contrast,
                   "sub-3:1 (relief rule: needs labels/table): {}".format(low_contrast)
                   if low_contrast
                   else "all {} >= {}:1".format(len(palette), CONTRAST_MIN)))

    return ok, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("palette")
    parser.add_argument("--mode", default="light", choices=["light", "dark"])
    parser.add_argument("--surface", default=None)
    parser.add_argument("--pairs", default="adjacent", choices=["adjacent", "all"])
    args = parser.parse_args()

    palette = [c.strip() for c in args.palette.split(",") if c.strip()]
    ok, report = validate(palette, args.mode, args.surface, args.pairs)

    print("palette: {}  mode={}  surface={}".format(
        palette, args.mode, args.surface or DEFAULT_SURFACE[args.mode]))
    print("-" * 78)
    for name, passed, detail in report:
        print("  {:26s} {:4s}  {}".format(name, "PASS" if passed else "FAIL", detail))
    print("-" * 78)
    print("  RESULT: {}".format("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
