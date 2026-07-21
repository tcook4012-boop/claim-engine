#!/usr/bin/env python3
"""
Downscale an image so it fits comfortably within Anthropic's vision API limits
(max ~1568px on the long edge, well under the 5MB/image ceiling).

Reads image bytes from stdin, writes JPEG bytes to stdout. Converts anything
(PNG, JPEG, etc.) to a reasonable-size JPEG. Fails closed: on any error it exits
non-zero with nothing on stdout, so the caller routes the order to review.

Usage:  cat image.png | python3 img_resize.py > out.jpg
"""
import sys, io

def main():
    try:
        from PIL import Image
        raw = sys.stdin.buffer.read()
        if not raw:
            sys.exit(1)
        im = Image.open(io.BytesIO(raw))
        # Flatten transparency onto white (JPEG has no alpha).
        if im.mode in ("RGBA", "LA", "P"):
            im = im.convert("RGBA")
            bg = Image.new("RGB", im.size, (255, 255, 255))
            bg.paste(im, mask=im.split()[-1] if im.mode == "RGBA" else None)
            im = bg
        else:
            im = im.convert("RGB")
        MAX = 1568
        w, h = im.size
        if max(w, h) > MAX:
            if w >= h:
                im = im.resize((MAX, max(1, round(h * MAX / w))))
            else:
                im = im.resize((max(1, round(w * MAX / h)), MAX))
        out = io.BytesIO()
        im.save(out, format="JPEG", quality=85, optimize=True)
        sys.stdout.buffer.write(out.getvalue())
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
