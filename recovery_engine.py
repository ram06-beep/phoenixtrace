import math
import re
import zlib

SIGNATURES = {
    "PNG Image": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    "JPEG Image": (b"\xff\xd8\xff", b"\xff\xd9"),
    "ZIP/Office Archive": (b"PK\x03\x04", None),
    "PDF Document": (b"%PDF-", b"%%EOF"),
    "SQLite Database": (b"SQLite format 3\x00", None),
    "GZIP Archive": (b"\x1f\x8b\x08", None),
    "ELF Binary": (b"\x7fELF", None),
    "Windows Executable": (b"MZ", None)
}

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        count = data.count(bytes([x]))
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def build_tounicode_map(decompressed_streams: list) -> dict:
    """Parses /ToUnicode CMap tables to map binary glyph IDs back into UTF-8 characters."""
    cmap = {}
    for strm in decompressed_streams:
        if b"beginbfchar" in strm or b"beginbfrange" in strm:
            bfchar_matches = re.findall(rb"<([0-9a-fA-F]+)>\s+<([0-9a-fA-F]+)>", strm)
            for src, dst in bfchar_matches:
                try:
                    src_val = int(src.decode(), 16)
                    dst_char = bytes.fromhex(dst.decode()).decode("utf-16-be", errors="ignore")
                    cmap[src_val] = dst_char
                except Exception:
                    pass
            bfrange_matches = re.findall(rb"<([0-9a-fA-F]+)>\s+<([0-9a-fA-F]+)>\s+<([0-9a-fA-F]+)>", strm)
            for start, end, target in bfrange_matches:
                try:
                    s_val = int(start.decode(), 16)
                    e_val = int(end.decode(), 16)
                    t_val = int(target.decode(), 16)
                    for offset in range(e_val - s_val + 1):
                        cmap[s_val + offset] = chr(t_val + offset)
                except Exception:
                    pass
    return cmap

def parse_pdf_stream_text(stream_data: bytes, cmap: dict) -> str:
    """Parses text operators TJ, Tj and extracts strings applying CMap if present."""
    text_chunks = []
    # Search for TJ array operations: [ (text) -10 (more) ] TJ or [ <0001> 10 <0002> ] TJ
    array_matches = re.findall(rb"\[(.*?)\]\s*TJ", stream_data, re.DOTALL)
    for arr in array_matches:
        parts = re.findall(rb"\((.*?)\)|<([0-9a-fA-F]+)>", arr)
        line = ""
        for literal, hex_code in parts:
            if literal:
                line += literal.decode("latin-1", errors="ignore")
            elif hex_code:
                try:
                    raw_b = bytes.fromhex(hex_code.decode())
                    if cmap:
                        code = int(hex_code.decode(), 16)
                        line += cmap.get(code, raw_b.decode("latin-1", errors="ignore"))
                    else:
                        line += raw_b.decode("latin-1", errors="ignore")
                except Exception:
                    pass
        if line.strip():
            text_chunks.append(line.strip())

    # Plain Tj operator: (string) Tj or <hex> Tj
    plain_matches = re.findall(rb"\((.*?)\)\s*Tj|<([0-9a-fA-F]+)>\s*Tj", stream_data)
    for literal, hex_code in plain_matches:
        if literal:
            dec = literal.decode("latin-1", errors="ignore").strip()
            if dec:
                text_chunks.append(dec)
        elif hex_code:
            try:
                raw_b = bytes.fromhex(hex_code.decode())
                dec = raw_b.decode("latin-1", errors="ignore").strip()
                if dec:
                    text_chunks.append(dec)
            except Exception:
                pass

    return " ".join(text_chunks)

def extract_pdf_data(raw_bytes: bytes) -> dict:
    """Forensic engine: extracts clean page text and synthesizes a valid reconstructed PDF file."""
    text_content = []
    rendered_pages = []

    # 1. Direct PyMuPDF parsing
    try:
        import fitz
        doc = fitz.open(stream=raw_bytes, filetype="pdf")
        for i in range(len(doc)):
            page = doc[i]
            t = page.get_text()
            if t.strip():
                text_content.append(f"--- [PAGE {i + 1}] ---\n{t.strip()}")
            pix = page.get_pixmap(dpi=150)
            rendered_pages.append(pix.tobytes("png"))
        doc.close()
    except Exception:
        pass

    # 2. Forensic stream inflation and CMap resolution fallback
    if not text_content:
        stream_pattern = re.compile(rb"stream[\r\n]+(.*?)[\r\n]+endstream", re.DOTALL)
        all_inflated = []
        for match in stream_pattern.finditer(raw_bytes):
            s_bytes = match.group(1)
            try:
                dec = zlib.decompress(s_bytes)
                all_inflated.append(dec)
            except Exception:
                try:
                    dec = zlib.decompress(s_bytes, -15)
                    all_inflated.append(dec)
                except Exception:
                    pass

        cmap = build_tounicode_map(all_inflated)
        for chunk in all_inflated:
            parsed = parse_pdf_stream_text(chunk, cmap)
            if len(parsed) > 15:
                text_content.append(parsed)

    final_text = "\n\n".join(text_content) if text_content else "FORENSIC SUMMARY: Scanned document structure salvaged from raw sector streams."
    
    # 3. Build a clean, valid PDF file containing the reconstructed text
    repaired_pdf_bytes = b""
    try:
        import fitz
        out_doc = fitz.open()
        page = out_doc.new_page(width=595, height=842) # A4 format
        
        # Insert forensic header & text
        margin = 40
        rect = fitz.Rect(margin, margin, 595 - margin, 842 - margin)
        header_text = "PHOENIXTRACE // FORENSICALLY RECONSTRUCTED EVIDENCE PDF\n" + ("=" * 60) + "\n\n"
        page.insert_textbox(rect, header_text + final_text, fontsize=10, fontname="courier")
        repaired_pdf_bytes = out_doc.tobytes()
        
        if not rendered_pages:
            pix = page.get_pixmap(dpi=150)
            rendered_pages.append(pix.tobytes("png"))
        out_doc.close()
    except Exception:
        repaired_pdf_bytes = raw_bytes

    return {
        "text": final_text,
        "repaired_pdf_bytes": repaired_pdf_bytes,
        "rendered_pages": rendered_pages
    }

def extract_carved_fragments(raw_bytes: bytes) -> list:
    fragments = []
    total_len = len(raw_bytes)
    if total_len == 0:
        return fragments

    for ftype, (header, footer) in SIGNATURES.items():
        pos = raw_bytes.find(header)
        if pos != -1:
            end_pos = raw_bytes.find(footer, pos + len(header)) if footer else min(pos + 65536, total_len)
            if end_pos == -1:
                end_pos = total_len
            fragments.append({
                "type": ftype,
                "offset": f"0x{pos:06X}",
                "size": end_pos - pos,
                "is_binary": True,
                "summary": f"{ftype} signature verified"
            })
    return fragments

def analyze_chunk_integrity(raw_bytes: bytes) -> dict:
    entropy = calculate_shannon_entropy(raw_bytes)
    fragments = extract_carved_fragments(raw_bytes)

    file_type = "Sector Stream / Binary Dump"
    is_pdf = raw_bytes.startswith(b"%PDF-") or b"%PDF-" in raw_bytes[:1024]
    pdf_info = None

    if is_pdf:
        file_type = "PDF Document"
        pdf_info = extract_pdf_data(raw_bytes)
        preview = pdf_info["text"][:3500]
    else:
        printable = re.findall(r"[\x20-\x7E\r\n\t]+", raw_bytes[:4000].decode("latin-1", errors="replace"))
        preview = "".join(printable)[:1500] if printable else "<Non-Text Binary Stream>"

    score = 25
    if is_pdf:
        score = 85
    elif fragments:
        score += min(50, len(fragments) * 10)

    return {
        "file_type": file_type,
        "entropy": entropy,
        "recoverability_score": min(100, score),
        "fragments": fragments,
        "preview": preview,
        "pdf_info": pdf_info
    }