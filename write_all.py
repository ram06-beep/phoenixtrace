import os

recovery_engine_code = '''import math

FILE_SIGNATURES = {
    "PNG Image": b"\\x89PNG\\r\\n\\x1a\\n",
    "JPEG Image": b"\\xff\\xd8\\xff",
    "PDF Document": b"%PDF-",
    "ZIP Archive": b"PK\\x03\\x04"
}

def calculate_entropy(byte_data: bytes) -> float:
    if not byte_data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(byte_data.count(bytes([x]))) / len(byte_data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def analyze_chunk_integrity(raw_bytes: bytes) -> dict:
    total_len = len(raw_bytes)
    if total_len == 0:
        return {"file_type": "Empty", "size_bytes": 0, "entropy": 0.0, "recoverability_score": 0, "preview": ""}

    detected_type = "Orphaned Sector / Fragment"
    for file_type, signature in FILE_SIGNATURES.items():
        if signature in raw_bytes[:16]:
            detected_type = file_type
            break

    entropy = calculate_entropy(raw_bytes)
    try:
        decoded_text = raw_bytes.decode('utf-8', errors='ignore')
        printable_count = sum(1 for c in decoded_text if c.isprintable() or c in "\\r\\n\\t")
        text_ratio = printable_count / max(len(decoded_text), 1)
        if text_ratio > 0.70 and detected_type == "Orphaned Sector / Fragment":
            detected_type = "Text / System Log / Config"
    except Exception:
        text_ratio = 0.0
        decoded_text = ""

    if detected_type.startswith("Text"):
        score = int(min(1.0, text_ratio * 1.15) * 100)
    elif detected_type != "Orphaned Sector / Fragment":
        score = 75
    else:
        score = max(10, int((1.0 - (entropy / 8.0)) * 50))

    return {
        "file_type": detected_type,
        "size_bytes": total_len,
        "entropy": entropy,
        "recoverability_score": score,
        "preview": decoded_text[:1200] if text_ratio > 0.35 else "<Non-Text Binary Stream>"
    }
'''

ai_reconstructor_code = '''import os
from google import genai

client = genai.Client()

def analyze_and_reconstruct_evidence(fragment_text: str) -> dict:
    if not fragment_text or fragment_text == "<Non-Text Binary Stream>":
        return {
            "category": "Raw Binary Blob",
            "priority": "Low",
            "forensic_notes": "Contains non-text instructions or machine code. Deep hex analysis required.",
            "restored_content": "No semantic textual data found to reconstruct."
        }

    prompt = (
        "You are an AI Digital Forensics and Evidence Reconstruction expert.\\n"
        "Analyze the following fragmented or partially corrupted data extracted from damaged disk sectors.\\n\\n"
        "--- DATA FRAGMENT START ---\\n"
        + fragment_text + "\\n"
        "--- DATA FRAGMENT END ---\\n\\n"
        "Analyze the contents and respond strictly in this structured format:\\n"
        "CATEGORY: [Credentials / Security Log / Source Code / Network Dump / General Document]\\n"
        "PRIORITY: [CRITICAL / HIGH / MEDIUM / LOW]\\n"
        "FORENSIC_NOTES: [A concise 1-2 sentence forensic interpretation of what happened or what this data proves]\\n"
        "RECONSTRUCTED_CONTENT: [Repair broken syntax, format clean timeline or JSON, and salvage all surviving meaningful data]"
    )

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        output = response.text

        category = "Unknown Fragment"
        priority = "Medium"
        notes = "No notes generated."
        restored = ""

        for line in output.splitlines():
            if line.startswith("CATEGORY:"):
                category = line.replace("CATEGORY:", "").strip()
            elif line.startswith("PRIORITY:"):
                priority = line.replace("PRIORITY:", "").strip()
            elif line.startswith("FORENSIC_NOTES:"):
                notes = line.replace("FORENSIC_NOTES:", "").strip()
            elif line.startswith("RECONSTRUCTED_CONTENT:"):
                restored = output.split("RECONSTRUCTED_CONTENT:")[1].strip()
                break

        return {
            "category": category,
            "priority": priority,
            "forensic_notes": notes,
            "restored_content": restored or output
        }
    except Exception as e:
        return {
            "category": "Raw Text",
            "priority": "Medium",
            "forensic_notes": f"Reconstruction engine status: {str(e)}",
            "restored_content": fragment_text
        }
'''

app_code = '''import os
import streamlit as st
import pandas as pd
from recovery_engine import analyze_chunk_integrity
from ai_reconstructor import analyze_and_reconstruct_evidence

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
        max-height: 380px;
        overflow-y: auto;
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
    return "\\n".join(lines)

st.markdown("""
<div class="top-header">
    <span style="font-size: 26px; font-weight: 800; color: #f9fafb;">⚡ PHOENIX<span style="color:#00f2fe">TRACE</span> <span style="font-size: 13px; color: #10b981; border: 1px solid #10b981; padding: 2px 8px; border-radius: 4px;">SYSTEM ACTIVE</span></span><br>
    <span style="color: #6b7280; font-size: 12px;">TACTICAL FORENSIC INGESTION • SEMANTIC SECTOR RECONSTRUCTION • THREAT TRIAGE</span>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 📥 Sector Ingestion")
    uploaded_files = st.file_uploader(
        "Ingest Raw Sectors / Dumps",
        type=["raw", "bin", "log", "json", "txt", "dat"],
        accept_multiple_files=True
    )
    st.markdown("---")
    st.markdown("#### **Target Disk Specs**")
    st.caption("Sector Size: 512 Bytes\\nCluster Alignment: 4096B\\nEngine: Gemini Flash 2.5")

if not uploaded_files:
    st.info("⚡ Ingest damaged sectors or dumps from the sidebar to activate the Tactical Forensic Workbench.")
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
        st.markdown(f'<div class="metric-card"><div class="metric-val" style="color:#10b981;">OPERATIONAL</div><div class="metric-lbl">Heuristic Engine</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    selected_name = st.selectbox(
        "SELECT FORENSIC TARGET FOR DEEP RECONSTRUCTION:",
        list(evidence_data.keys())
    )
    
    target = evidence_data[selected_name]
    raw_bytes = target["bytes"]
    meta = target["meta"]

    left_col, right_col = st.columns([1.1, 1.3], gap="medium")

    with left_col:
        st.markdown("#### 🔍 RAW ARTIFACT ANALYSIS")
        
        info_c1, info_c2, info_c3 = st.columns(3)
        info_c1.metric("FORMAT", meta["file_type"])
        info_c2.metric("SHANNON ENTROPY", f"{meta['entropy']} / 8.0")
        info_c3.metric("INTEGRITY", f"{meta['recoverability_score']}%")

        tab_hex, tab_text = st.tabs(["Hex Sector Stream", "Decoded ASCII"])
        
        with tab_hex:
            hex_view = format_hex_dump(raw_bytes)
            st.markdown(f'<div class="hex-box"><pre>{hex_view}</pre></div>', unsafe_allow_html=True)

        with tab_text:
            st.text_area("Surviving Characters", meta["preview"], height=320)

    with right_col:
        st.markdown("#### 🧠 AI EVIDENCE RECONSTRUCTION & TRIAGE")
        
        reconstruct_btn = st.button("EXECUTE NEURAL EVIDENCE RECONSTRUCTION", type="primary", use_container_width=True)

        if reconstruct_btn:
            with st.spinner("Decoding memory boundaries, assembling fragmented syntax, and triaging indicators..."):
                res = analyze_and_reconstruct_evidence(meta["preview"])
                
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

                st.markdown("##### 📄 SALVAGED & RESTORED EVIDENCE")
                st.code(res["restored_content"], language="yaml")

                os.makedirs("recovered_outputs", exist_ok=True)
                output_path = os.path.join("recovered_outputs", f"recovered_{selected_name}")
                with open(output_path, "w", encoding="utf-8") as out_f:
                    out_f.write(res["restored_content"])
                
                st.success(f"💾 File recovered and saved to: `{output_path}`")
                
                st.download_button(
                    label="📥 DOWNLOAD RECONSTRUCTED EVIDENCE",
                    data=res["restored_content"],
                    file_name=f"recovered_{selected_name}",
                    mime="text/plain",
                    use_container_width=True
                )
        else:
            st.info("Hit the button above to begin neural syntax reconstruction and timeline salvaging on this sector.")
'''

with open("recovery_engine.py", "w", encoding="utf-8") as f:
    f.write(recovery_engine_code)

with open("ai_reconstructor.py", "w", encoding="utf-8") as f:
    f.write(ai_reconstructor_code)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(app_code)

print("SUCCESS: All 3 files generated cleanly!")