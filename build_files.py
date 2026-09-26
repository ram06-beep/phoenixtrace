import os

files = {
    'recovery_engine.py': '''import math

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
''',
    'ai_reconstructor.py': '''import os
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

    prompt = f"""
    You are an AI Digital Forensics and Evidence Reconstruction expert.
    Analyze the following fragmented or partially corrupted data extracted from damaged disk sectors.
    
    Data Fragment:
    \"\"\"{fragment_text}\"\"\"

    Analyze the contents and respond strictly in this structured format:
    CATEGORY: [Credentials / Security Log / Source Code / Network Dump / General Document]
    PRIORITY: [CRITICAL / HIGH / MEDIUM / LOW]
    FORENSIC_NOTES: [A concise 1-2 sentence forensic interpretation of what happened or what this data proves]
    RECONSTRUCTED_CONTENT: [Repair broken syntax, format clean timeline or JSON, and salvage all surviving meaningful data]
    """

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        output = response.text

        category, priority, notes, restored = "Unknown Fragment", "Medium", "No notes generated.", ""

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
''',
    'app.py': '''import streamlit as st
import pandas as pd
from recovery_engine import analyze_chunk_integrity
from ai_reconstructor import analyze_and_reconstruct_evidence

st.set_page_config(page_title="PhoenixTrace | Forensics Recovery", layout="wide", page_icon="🛡️")

st.title("🛡️ PhoenixTrace: AI-Assisted Digital Evidence Reconstruction")
st.caption("Automated Sector Carving • Shannon Entropy • Semantic Syntax Reconstruction • Forensic Triage")

st.sidebar.header("📁 Evidence Ingestion")
uploaded_files = st.sidebar.file_uploader(
    "Upload Corrupted/Fragmented Dumps",
    type=["raw", "bin", "log", "txt", "dat"],
    accept_multiple_files=True
)

if not uploaded_files:
    st.info("👈 Upload sample corrupted disk sectors (.raw, .log, .bin) from the sidebar to begin carving.")
else:
    evidence_records = []
    chunk_cache = {}

    for file in uploaded_files:
        raw_bytes = file.read()
        meta = analyze_chunk_integrity(raw_bytes)
        chunk_cache[file.name] = (raw_bytes, meta)
        evidence_records.append({
            "File Name": file.name,
            "Detected Format": meta["file_type"],
            "Size (Bytes)": meta["size_bytes"],
            "Entropy": meta["entropy"],
            "Integrity Score": f"{meta['recoverability_score']}%"
        })

    st.subheader("1. Ingested Evidence Triage Matrix")
    st.dataframe(pd.DataFrame(evidence_records), use_container_width=True)
    st.markdown("---")

    st.subheader("2. Deep Fragment Reconstruction & Analysis")
    selected_filename = st.selectbox("Select Evidence Chunk to Reconstruct", [f["File Name"] for f in evidence_records])

    if selected_filename:
        _, meta = chunk_cache[selected_filename]
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### 🧩 Raw Carved Bytes")
            st.code(meta["preview"], language="text")
            st.metric("Local Heuristic Integrity", f"{meta['recoverability_score']}%")

        with col2:
            st.markdown("#### 🧠 AI Evidence Reconstruction")
            if st.button("Run AI Reconstruction & Triage", type="primary"):
                with st.spinner("AI parsing broken syntax, identifying secrets, and assessing impact..."):
                    ai_result = analyze_and_reconstruct_evidence(meta["preview"])

                    priority = ai_result["priority"].upper()
                    if "CRITICAL" in priority:
                        st.error(f"🚨 Triage Priority: {priority}")
                    elif "HIGH" in priority:
                        st.warning(f"⚠️ Triage Priority: {priority}")
                    else:
                        st.info(f"ℹ️ Triage Priority: {priority}")

                    st.markdown(f"**Evidence Category:** `{ai_result['category']}`")
                    st.info(f"**Forensic Note:** {ai_result['forensic_notes']}")
                    st.markdown("##### Salvaged & Structured Content:")
                    st.success(ai_result["restored_content"])
'''
}

for name, code in files.items():
    with open(name, 'w', encoding='utf-8') as f:
        f.write(code)

print("SUCCESS: All 3 files generated cleanly!")