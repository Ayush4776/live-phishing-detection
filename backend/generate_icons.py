import os
import math
from PIL import Image, ImageDraw

icons_dir = os.path.join(os.path.dirname(__file__), "..", "extension", "icons")
os.makedirs(icons_dir, exist_ok=True)

def create_shield_icon(size):
    # Create RGBA canvas
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw rounded shield background
    margin = int(size * 0.1)
    cx, cy = size / 2, size / 2

    # Draw gradient-like circle background
    draw.ellipse([margin, margin, size - margin, size - margin], fill=(15, 23, 42, 255), outline=(59, 130, 246, 255), width=max(1, int(size * 0.05)))

    # Draw shield polygon
    p1 = (cx, margin + int(size * 0.1))
    p2 = (size - margin - int(size * 0.15), margin + int(size * 0.2))
    p3 = (size - margin - int(size * 0.15), cy + int(size * 0.1))
    p4 = (cx, size - margin - int(size * 0.1))
    p5 = (margin + int(size * 0.15), cy + int(size * 0.1))
    p6 = (margin + int(size * 0.15), margin + int(size * 0.2))

    draw.polygon([p1, p2, p3, p4, p5, p6], fill=(16, 185, 129, 255), outline=(52, 211, 153, 255))

    # Draw checkmark inside shield
    if size >= 48:
        chk1 = (cx - size * 0.12, cy)
        chk2 = (cx - size * 0.02, cy + size * 0.1)
        chk3 = (cx + size * 0.15, cy - size * 0.08)
        draw.line([chk1, chk2, chk3], fill=(255, 255, 255, 255), width=max(2, int(size * 0.06)))

    out_path = os.path.join(icons_dir, f"icon{size}.png")
    img.save(out_path, "PNG")
    print(f"Generated icon: {out_path}")

for s in [16, 48, 128]:
    create_shield_icon(s)
