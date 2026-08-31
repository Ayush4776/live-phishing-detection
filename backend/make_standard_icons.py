import os
import struct
import zlib

icons_dir = os.path.join(os.path.dirname(__file__), "..", "extension", "icons")
os.makedirs(icons_dir, exist_ok=True)

def create_valid_png(width, height, filepath):
    # PNG signature
    png_signature = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk
    # Width, Height, Bit depth (8), Color type (6: RGBA), Compression (0), Filter (0), Interlace (0)
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # IDAT chunk - create pixel data (Emerald green shield color #10B981)
    raw_rows = []
    for y in range(height):
        row = [0] # Filter type 0 (None)
        for x in range(width):
            # Check if point is inside shield shape boundary
            dx = (x - width / 2) / (width / 2)
            dy = (y - height / 2) / (height / 2)
            if (dx*dx + dy*dy) <= 0.8:
                # Emerald Green (#10B981)
                row.extend([16, 185, 129, 255])
            else:
                # Dark Blue (#0F172A)
                row.extend([15, 23, 42, 255])
        raw_rows.append(bytes(row))

    compressed_data = zlib.compress(b"".join(raw_rows))
    idat_crc = zlib.crc32(b"IDAT" + compressed_data)
    idat_chunk = struct.pack(">I", len(compressed_data)) + b"IDAT" + compressed_data + struct.pack(">I", idat_crc)

    # IEND chunk
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    with open(filepath, "wb") as f:
        f.write(png_signature + ihdr_chunk + idat_chunk + iend_chunk)

for size in [16, 48, 128]:
    out_file = os.path.join(icons_dir, f"icon{size}.png")
    create_valid_png(size, size, out_file)
    print(f"Generated PNG icon: {out_file}")
