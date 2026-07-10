#!/usr/bin/env python3
"""
DST quality checker for PrintReadyArt.

Reads a Tajima .DST embroidery file and returns JSON on stdout:
  { ok, sizeInches:{w,h}, direction, stitches, preview (base64 png), notes[] }

- SIZE comes from the DST header (+X/-X/+Y/-Y), which is authoritative and needs no
  stitch decoding. This is the reliable check.
- DIRECTION (cap center-out/bottom-up vs flat left-to-right) is inferred from the decoded
  stitch order using pyembroidery. Advisory: real designs vary, so we report a best guess
  plus the evidence, and let the caller compare it to the order's expected Placement.
- PREVIEW is a rendered stitch path so a human reviewer can eyeball a flagged file.

Never raises to the caller: any failure is reported as {ok:false, error} so the Node
upload flow degrades gracefully (treat as "couldn't check" -> review, not auto-pass).

Usage:  python3 dst_check.py /path/to/file.dst
"""
import sys, json, base64, io, math

def read_header(path):
    """Parse the 512-byte ASCII header. Returns dict of fields."""
    with open(path, "rb") as f:
        head = f.read(512).decode("latin-1", "replace")
    hdr = {}
    for part in head.replace("\r", "\n").split("\n"):
        if ":" in part:
            k, v = part.split(":", 1)
            hdr[k.strip()] = v.strip()
    return hdr

def size_from_header(hdr):
    """Design extents from +X/-X/+Y/-Y, in 0.1mm units -> inches. Authoritative."""
    def num(k):
        try:
            return float(hdr.get(k, "").strip())
        except (ValueError, AttributeError):
            return None
    px, nx, py, ny = num("+X"), num("-X"), num("+Y"), num("-Y")
    if None in (px, nx, py, ny):
        return None
    w_mm = (px + nx) / 10.0      # +X and -X are magnitudes from center
    h_mm = (py + ny) / 10.0
    return {"w_mm": round(w_mm, 2), "h_mm": round(h_mm, 2),
            "w": round(w_mm / 25.4, 3), "h": round(h_mm / 25.4, 3)}

def analyze(path):
    hdr = read_header(path)
    size = size_from_header(hdr)
    out = {"ok": True, "notes": []}
    if size:
        out["sizeInches"] = {"w": size["w"], "h": size["h"]}
        out["sizeMm"] = {"w": size["w_mm"], "h": size["h_mm"]}
    else:
        out["ok"] = False
        out["notes"].append("Could not read size from DST header.")

    # ---- Stitch decode (direction + preview) via pyembroidery ----
    try:
        import pyembroidery
    except ImportError:
        out["notes"].append("pyembroidery not installed; size-only.")
        out["direction"] = None
        return out

    try:
        pattern = pyembroidery.read(path)
        # stitches: list of [x, y, command]; keep only real stitches for geometry
        pts = []
        for x, y, cmd in pattern.stitches:
            c = cmd & 0xFF
            if c in (pyembroidery.STITCH, pyembroidery.SEQUIN_EJECT):
                pts.append((x, y))
        out["stitches"] = len(pattern.stitches)
        if len(pts) < 20:
            out["direction"] = None
            out["notes"].append("Too few stitches to judge direction.")
            return out

        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
        w = maxx - minx or 1; h = maxy - miny or 1
        cx = (minx + maxx) / 2.0; cy = (miny + maxy) / 2.0

        # Look at the first slice of the sew and where it begins.
        n = len(pts)
        head = pts[: max(10, n // 10)]
        hx = sum(p[0] for p in head) / len(head)
        hy = sum(p[1] for p in head) / len(head)

        # left-to-right: does X trend strongly from left as the sew proceeds?
        # center-out: do early stitches cluster near the centroid, later ones spread out?
        head_dist = sum(math.hypot(p[0]-cx, p[1]-cy) for p in head) / len(head)
        tail = pts[-max(10, n // 10):]
        tail_dist = sum(math.hypot(p[0]-cx, p[1]-cy) for p in tail) / len(tail)
        radius = math.hypot(w, h) / 2.0 or 1

        starts_left = (hx - minx) / w < 0.25         # begins near the left edge
        starts_center = head_dist / radius < 0.45    # begins near the middle
        expands = tail_dist > head_dist              # spreads outward over time
        starts_bottom = (hy - miny) / h < 0.30 or (maxy - hy) / h < 0.30  # near an edge in Y

        if starts_center and expands:
            direction = "center_out"
        elif starts_left and not starts_center:
            direction = "left_to_right"
        else:
            direction = "unclear"

        out["direction"] = direction
        out["directionEvidence"] = {
            "start_x_frac": round((hx - minx) / w, 2),
            "start_center_frac": round(head_dist / radius, 2),
            "expands_outward": bool(expands),
        }

        # ---- Preview PNG ----
        try:
            from PIL import Image, ImageDraw
            W, H = 640, 360; pad = 24
            sx = (W - 2*pad) / w; sy = (H - 2*pad) / h; s = min(sx, sy)
            def tx(x): return pad + (x - minx) * s
            def ty(y): return H - (pad + (y - miny) * s)  # flip Y for screen
            img = Image.new("RGB", (W, H), "white"); d = ImageDraw.Draw(img)
            prev = None
            for (x, y, cmd) in pattern.stitches:
                c = cmd & 0xFF
                p = (tx(x), ty(y))
                if prev is not None and c == pyembroidery.STITCH:
                    d.line([prev, p], fill=(25, 25, 30), width=1)
                prev = p
            buf = io.BytesIO(); img.save(buf, format="PNG")
            out["preview"] = base64.b64encode(buf.getvalue()).decode("ascii")
        except Exception as e:
            out["notes"].append("preview failed: %s" % e)

    except Exception as e:
        out["direction"] = None
        out["notes"].append("stitch decode failed: %s" % e)
    return out

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "usage: dst_check.py <file.dst>"})); return
    try:
        print(json.dumps(analyze(sys.argv[1])))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))

if __name__ == "__main__":
    main()
