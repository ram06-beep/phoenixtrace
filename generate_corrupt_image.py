import io
import os
from PIL import Image, ImageDraw

os.makedirs("sample_evidence", exist_ok=True)

# 1. Create a clean base forensic image
img = Image.new("RGB", (260, 160), color=(15, 23, 42))
draw = ImageDraw.Draw(img)
draw.rectangle([(20, 20), (240, 140)], outline=(0, 242, 254), width=3)
draw.text((35, 45), "CRITICAL EVIDENCE", fill=(239, 68, 68))
draw.text((35, 75), "CONFIDENTIAL_DOC", fill=(255, 255, 255))
draw.text((35, 105), "SECTOR: 0x00F8A", fill=(16, 185, 129))

buf = io.BytesIO()
img.save(buf, format="PNG")
valid_png_bytes = buf.getvalue()

# 2. Corrupt it: strip the first 6 bytes of the PNG magic signature and inject bad sectors
corrupted_png_bytes = b"\x00\x00\x00[DAMAGED_HEADER]" + valid_png_bytes[8:]

output_path = "sample_evidence/corrupt_evidence_badge.png"
with open(output_path, "wb") as f:
    f.write(corrupted_png_bytes)

print(f"Generated corrupted image test file: {output_path}")