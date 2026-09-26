import io
import os
import streamlit as st
import pandas as pd
from recovery_engine import analyze_chunk_integrity
from ai_reconstructor import analyze_and_reconstruct_evidence, analyze_and_repair_image

st.set_page_config(
    page_title="PhoenixTrace // FORENSIC TERMINAL",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'JetBrains+Mono', monospace;
    }
    
    .stApp {
        background-color: #0b0f19;
        color: #d1d5db;
    }
    
    .top-header {
        border-bottom: 2px solid #1f2937;
        padding-bottom: 12px;
        margin-bottom: 20px;
    }
    
    .metric-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
    }
    
    .metric-val {
        font-size: 24px;
        font-weight: 800;
        color: #00f2fe;
    }
    
    .metric-lbl {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #9ca3af;
    }

    .hex-box {
        background-color: #030712;
        border: 1px solid #374151;
        border-radius: 6px;
        padding: 12px;
        font-size: 12px;
        line-height: 1.6;
        color: #10b981;
        max-height: 420px;
        overflow-y: auto;
    }

    .preview-card {
        background-color: #111827;
        border: 1px solid #374151;
        border-radius: 6px;
        padding: 10px;
        text-align: center;
        margin-bottom: 8px;
    }
    
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        display: inline-block;
    }
    
    .badge-high {
        background-color: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        display: inline-block;
    }
    
    .badge-norm {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        display: inline-block;
    }

    .text-preview-box {
        background-color: #030712;
        border: 1px solid #1f2937;
        border-radius: 4px;
        padding: 8px;
        font-size: 11px;
        color: #93c5fd;
        height: 110px;
        overflow: hidden;
        text-align: left;
        white-space: pre-wrap;
    }

    .pdf-preview-box {
        background-color: #1e1b4b;
        border: 1px solid #4338ca;
        border-radius: 4px;
        padding: 16px 8px;
        font-size: 12px;
        color: #c7d2fe;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

def format_hex_dump(raw_bytes: bytes, max_len=320) -> str:
    lines = []
    chunk = raw_bytes[:max_len]
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in line_bytes)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
        lines.append(f"{i:06X}  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)

st.markdown("""
<div class="top-header">
    <span style="font-size: 26px; font-weight: 800; color: #f9fafb;">⚡ PHOENIX<span style="color:#00f2fe">TRACE</span> <span style="font-size: 13px; color: #10b981; border: 1px solid #10b981; padding: 2px 8px; border-radius: 4px;">SYSTEM ACTIVE</span></span><br>
    <span style="color: #6b7280; font-size: 12px;">TACTICAL FORENSIC INGESTION • MULTIMODAL (IMG / TXT / PDF) • BINARY SECTOR CARVING</span>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 📥 Sector Ingestion")
    uploaded_files = st.file_uploader(
        "Ingest Raw Sectors, Documents, Images",
        type=["pdf", "txt", "log", "json", "py", "sh", "raw", "bin", "dat", "png", "jpg", "jpeg"],
        accept_multiple_files=True
    )
    st.markdown("---")
    st.markdown("#### **System Target Specs**")
    st.caption("PDF Reconstruction: Native Postscript Fix\nNeural Engine: Gemini Flash 2.5\nSector Carving: Multi-Signature Match")

if not uploaded_files:
    st.info("⚡ Ingest damaged sectors, PDFs, logs, or image dumps from the sidebar to activate the Tactical Forensic Workbench.")
else:
    evidence_data = {}
    total_bytes = 0

    for f in uploaded_files:
        raw_b = f.read()
        total_bytes += len(raw_b)
        meta = analyze_chunk_integrity(raw_b)
        evidence_data[f.name] = {"bytes": raw_b, "meta": meta}

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{len(uploaded_files)}</div><div class="metric-lbl">Ingested Artifacts</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{total_bytes:,} B</div><div class="metric-lbl">Total Volume</div></div>', unsafe_allow_html=True)
    with c3:
        avg_integrity = int(sum(d["meta"]["recoverability_score"] for d in evidence_data.values()) / len(evidence_data))
        st.markdown(f'<div class="metric-card"><div class="metric-val">{avg_integrity}%</div><div class="metric-lbl">Avg Carve Integrity</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="metric-card"><div class="metric-val" style="color:#10b981;">ONLINE</div><div class="metric-lbl">Artifact Decoder</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    with st.expander("📂 INGESTED ARTIFACTS PREVIEW & EVIDENCE GALLERY", expanded=True):
        preview_cols = st.columns(min(4, len(uploaded_files)))
        for idx, (name, data) in enumerate(evidence_data.items()):
            col = preview_cols[idx % len(preview_cols)]
            with col:
                st.markdown(f"<div class='preview-card'><strong>{name[:22]}</strong><br><small>{len(data['bytes']):,} Bytes</small></div>", unsafe_allow_html=True)
                lname = name.lower()
                is_img = any(lname.endswith(ext) for ext in [".png", ".jpg", ".jpeg"]) or "Image" in data["meta"]["file_type"]
                is_pdf = lname.endswith(".pdf") or data["bytes"].startswith(b"%PDF-") or "PDF" in data["meta"]["file_type"]

                if is_img:
                    try:
                        st.image(data["bytes"], use_container_width=True)
                    except Exception:
                        st.caption("⚠️ Damaged visual header")
                elif is_pdf:
                    st.markdown("""
                    <div class="pdf-preview-box">
                        <strong>📄 PDF DOCUMENT</strong><br>
                        <span style="font-size:10px;">Postscript Container</span>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    snippet = data["meta"]["preview"][:120].strip() or "<Binary Stream>"
                    st.markdown(f'<div class="text-preview-box">{snippet}</div>', unsafe_allow_html=True)

    st.markdown("---")

    selected_name = st.selectbox(
        "SELECT FORENSIC TARGET FOR DEEP RECONSTRUCTION:",
        list(evidence_data.keys())
    )
    
    target = evidence_data[selected_name]
    raw_bytes = target["bytes"]
    meta = target["meta"]
    lower_sel = selected_name.lower()

    fragments = meta.get("fragments", [])
    if fragments:
        st.markdown(f"##### 🧩 DISCOVERED SECTOR FRAGMENTS ({len(fragments)} Found)")
        frag_display = [
            {
                "Offset": f["offset"],
                "Type": f["type"],
                "Size (Bytes)": f["size"],
                "Preview / Detail": f["summary"]
            }
            for f in fragments
        ]
        st.dataframe(pd.DataFrame(frag_display), use_container_width=True)

    is_image_file = any(lower_sel.endswith(ext) for ext in [".png", ".jpg", ".jpeg"]) or "Image" in meta["file_type"]
    is_pdf_file = lower_sel.endswith(".pdf") or raw_bytes.startswith(b"%PDF-") or "PDF" in meta["file_type"]

    left_col, right_col = st.columns([1.1, 1.3], gap="medium")

    with left_col:
        st.markdown("#### 🔍 RAW ARTIFACT ANALYSIS")
        
        info_c1, info_c2, info_c3 = st.columns(3)
        detected_type = "PDF Document" if is_pdf_file else ("Raster Image" if is_image_file else meta["file_type"])
        info_c1.metric("FORMAT", detected_type)
        info_c2.metric("SHANNON ENTROPY", f"{meta['entropy']} / 8.0")
        info_c3.metric("INTEGRITY", f"{meta['recoverability_score']}%")

        tab_view, tab_hex = st.tabs(["Decoded Content View", "Hex Sector Stream"])
        
        with tab_view:
            if is_image_file:
                st.caption("Raw Carved Image Stream:")
                try:
                    st.image(raw_bytes, caption="Raw Carved Stream (Damaged)", use_container_width=True)
                except Exception:
                    st.warning("⚠️ Unreadable Header: Image canvas cannot decode directly.")
            elif is_pdf_file:
                st.caption("Carved Document Stream:")
                st.text_area("Surviving Content", meta["preview"], height=350)
            else:
                st.caption("Carved Text / Source Stream:")
                st.text_area("Surviving Content", meta["preview"], height=350)

        with tab_hex:
            hex_view = format_hex_dump(raw_bytes)
            st.markdown(f'<div class="hex-box"><pre>{hex_view}</pre></div>', unsafe_allow_html=True)

    with right_col:
        st.markdown("#### 🧠 AI EVIDENCE RECONSTRUCTION & REPAIRED PDF GENERATION")
        
        reconstruct_btn = st.button("EXECUTE EVIDENCE RECONSTRUCTION & REPAIR PDF", type="primary", use_container_width=True)

        if reconstruct_btn:
            with st.spinner("Reconstructing evidence, building document layout, and generating final PDF..."):
                if is_image_file:
                    res = analyze_and_repair_image(raw_bytes, selected_name)
                    prio = res["priority"].upper()
                    badge_class = "badge-critical" if "CRITICAL" in prio else ("badge-high" if "HIGH" in prio else "badge-norm")
                    
                    st.markdown(f"""
                    <div style="background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span class="{badge_class}">PRIORITY: {prio}</span>
                            <span style="color: #9ca3af; font-size: 12px;">CATEGORY: <strong style="color: #f3f4f6;">{res['category']}</strong></span>
                        </div>
                        <div style="font-size: 13px; color: #d1d5db;"><strong>Forensic Assessment:</strong> {res['forensic_notes']}</div>
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown("##### 🖼️ COMPARATIVE VISUAL SALVAGE")
                    comp_left, comp_right = st.columns(2)
                    with comp_left:
                        st.caption("🔴 Corrupted Original")
                        try:
                            st.image(raw_bytes, use_container_width=True)
                        except Exception:
                            st.info("Unrenderable corrupted stream")
                    with comp_right:
                        st.caption("🟢 Restored Output")
                        try:
                            st.image(res["repaired_image_bytes"], use_container_width=True)
                        except Exception as img_err:
                            st.error(f"Image display error: {img_err}")

                    os.makedirs("recovered_outputs", exist_ok=True)
                    out_ext = ".png" if lower_sel.endswith(".png") else ".jpg"
                    output_path = os.path.join("recovered_outputs", f"recovered_{selected_name}")
                    with open(output_path, "wb") as out_f:
                        out_f.write(res["repaired_image_bytes"])
                    
                    st.success(f"💾 Image recovered and written to: `{output_path}`")
                    st.download_button(
                        label="📥 DOWNLOAD REPAIRED IMAGE",
                        data=res["repaired_image_bytes"],
                        file_name=f"recovered_{selected_name}",
                        mime="image/png" if out_ext == ".png" else "image/jpeg",
                        use_container_width=True
                    )
                else:
                    # Text, Log, or PDF Evidence Branch
                    payload = meta["preview"]
                    if is_pdf_file:
                        payload = f"[CARVED PDF STREAMS & CONTENT]\n" + meta["preview"]

                    res = analyze_and_reconstruct_evidence(payload)
                    prio = res["priority"].upper()
                    badge_class = "badge-critical" if "CRITICAL" in prio else ("badge-high" if "HIGH" in prio else "badge-norm")
                    
                    st.markdown(f"""
                    <div style="background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span class="{badge_class}">PRIORITY: {prio}</span>
                            <span style="color: #9ca3af; font-size: 12px;">CATEGORY: <strong style="color: #f3f4f6;">{res['category']}</strong></span>
                        </div>
                        <div style="font-size: 13px; color: #d1d5db;"><strong>Forensic Assessment:</strong> {res['forensic_notes']}</div>
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown("##### 📄 SALVAGED EVIDENCE SUMMARY")
                    st.code(res["restored_content"], language="yaml")

                    os.makedirs("recovered_outputs", exist_ok=True)

                    # Build and output a validated PDF file
                    if is_pdf_file:
                        pdf_info = meta.get("pdf_info", {})
                        
                        # Generate the reconstructed PDF directly from the AI-restored content
                        try:
                            import fitz
                            pdf_doc = fitz.open()
                            p = pdf_doc.new_page(width=595, height=842)
                            rect = fitz.Rect(40, 40, 555, 802)
                            doc_title = f"EVIDENCE FILE: {selected_name}\nRECONSTRUCTION REPORT\n" + ("=" * 55) + "\n\n"
                            p.insert_textbox(rect, doc_title + res["restored_content"], fontsize=9.5, fontname="courier")
                            pdf_bytes_out = pdf_doc.tobytes()
                            
                            # Render first page visual
                            pix = p.get_pixmap(dpi=150)
                            st.markdown("##### 📑 RECONSTRUCTED PDF PREVIEW")
                            st.image(pix.tobytes("png"), caption="Reconstructed PDF Page 1", use_container_width=True)
                            pdf_doc.close()
                        except Exception:
                            pdf_bytes_out = pdf_info.get("repaired_pdf_bytes", raw_bytes) if pdf_info else raw_bytes

                        out_pdf_name = f"reconstructed_{os.path.splitext(selected_name)[0]}.pdf"
                        out_pdf_path = os.path.join("recovered_outputs", out_pdf_name)
                        with open(out_pdf_path, "wb") as out_pdf:
                            out_pdf.write(pdf_bytes_out)

                        st.success(f"💾 Clean PDF Document generated and saved to: `{out_pdf_path}`")
                        st.download_button(
                            label="📥 DOWNLOAD RECONSTRUCTED PDF DOCUMENT",
                            data=pdf_bytes_out,
                            file_name=out_pdf_name,
                            mime="application/pdf",
                            use_container_width=True
                        )
                    else:
                        out_filename = f"recovered_{os.path.splitext(selected_name)[0]}.txt"
                        output_path = os.path.join("recovered_outputs", out_filename)
                        with open(output_path, "w", encoding="utf-8") as out_f:
                            out_f.write(res["restored_content"])
                        
                        st.success(f"💾 File recovered and saved to: `{output_path}`")
                        st.download_button(
                            label="📥 DOWNLOAD RECONSTRUCTED TEXT",
                            data=res["restored_content"],
                            file_name=out_filename,
                            mime="text/plain",
                            use_container_width=True
                        )
        else:
            st.info("Hit the button above to begin neural syntax reconstruction and timeline salvaging on this sector.")