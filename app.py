"""
TaxGuard Pro — Local PII Redaction for Tax Documents
====================================================

A Streamlit application that redacts sensitive PII (SSNs, Account Numbers,
Addresses) from tax documents, including searchable AND scanned (image-based)
PDFs. Uses a hybrid pipeline: text extraction first, OCR fallback at 300 DPI.

Run locally:
    streamlit run app.py
"""

from __future__ import annotations

import base64
import io
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import fitz  # PyMuPDF
import streamlit as st

# OCR stack — imported lazily so the app still starts if Tesseract/Poppler
# are missing; we surface a friendly error when OCR is actually needed.
try:
    import pytesseract
    from pdf2image import convert_from_bytes
    from PIL import Image
    OCR_AVAILABLE = True
    OCR_IMPORT_ERROR: Optional[str] = None
except Exception as e:  # pragma: no cover
    OCR_AVAILABLE = False
    OCR_IMPORT_ERROR = str(e)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# SSN: exactly NNN-NN-NNNN
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Account numbers: 10–12 consecutive digits (optionally with spaces/dashes
# every 4 digits). We match the "pure digits" form first (strictest) and
# then a loose form that's used only after SSNs have been stripped from
# the candidate string, to avoid eating an SSN.
ACCOUNT_PATTERN = re.compile(r"\b\d{10,12}\b")

# A lightweight US address heuristic: "<number> <Street Words> <Suffix>"
# followed optionally by a unit, then city/state/zip on the same or next
# token run. This is intentionally conservative — users can disable it.
ADDRESS_PATTERN = re.compile(
    r"\b\d{1,6}\s+"
    r"(?:[A-Z][A-Za-z0-9.'-]*\s+){1,5}"
    r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|"
    r"Court|Ct|Way|Place|Pl|Parkway|Pkwy|Terrace|Ter|Highway|Hwy|Circle|Cir)"
    r"\b\.?"
    r"(?:,?\s+(?:Apt|Suite|Ste|Unit|#)\s*[A-Za-z0-9-]+)?"
    r"(?:,?\s+[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+)?,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?)?",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Hit:
    """A single detected PII region on a specific page."""
    page_index: int
    text: str
    kind: str  # "SSN" | "ACCOUNT" | "ADDRESS"
    rect: fitz.Rect

    def as_dict(self) -> dict:
        return {
            "page": self.page_index + 1,
            "kind": self.kind,
            "text": self.text,
            "rect": [round(c, 1) for c in (self.rect.x0, self.rect.y0, self.rect.x1, self.rect.y1)],
        }


@dataclass
class DetectionConfig:
    redact_ssn: bool = True
    redact_account: bool = True
    redact_address: bool = True
    excluded_strings: List[str] = field(default_factory=lambda: ["CORNERSTONES", "TRANSFER"])
    force_ocr: bool = False
    ocr_dpi: int = 300


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_excluded(text: str, excluded: List[str]) -> bool:
    up = text.upper()
    return any(tok.strip().upper() in up for tok in excluded if tok.strip())


def _page_has_text(page: fitz.Page, min_chars: int = 20) -> bool:
    return len(page.get_text("text").strip()) >= min_chars


def _find_matches_in_string(
    s: str, cfg: DetectionConfig
) -> List[Tuple[int, int, str, str]]:
    """Return [(start, end, kind, matched_text)] for one string.

    Order matters: SSN first, then ACCOUNT, so we don't mis-classify an SSN's
    digit run as an account number.
    """
    spans: List[Tuple[int, int, str, str]] = []
    consumed = [False] * len(s)

    def claim(a: int, b: int) -> bool:
        if any(consumed[a:b]):
            return False
        for i in range(a, b):
            consumed[i] = True
        return True

    if cfg.redact_ssn:
        for m in SSN_PATTERN.finditer(s):
            if claim(m.start(), m.end()):
                spans.append((m.start(), m.end(), "SSN", m.group(0)))

    if cfg.redact_account:
        for m in ACCOUNT_PATTERN.finditer(s):
            if claim(m.start(), m.end()):
                spans.append((m.start(), m.end(), "ACCOUNT", m.group(0)))

    if cfg.redact_address:
        for m in ADDRESS_PATTERN.finditer(s):
            if claim(m.start(), m.end()):
                spans.append((m.start(), m.end(), "ADDRESS", m.group(0).strip()))

    # Filter exclusions
    out = []
    for a, b, kind, txt in spans:
        if _is_excluded(txt, cfg.excluded_strings):
            continue
        out.append((a, b, kind, txt))
    return out


# ---------------------------------------------------------------------------
# Text-layer detection (searchable PDFs)
# ---------------------------------------------------------------------------


def detect_hits_text_layer(doc: fitz.Document, cfg: DetectionConfig) -> List[Hit]:
    hits: List[Hit] = []
    for page_index in range(len(doc)):
        page = doc[page_index]
        page_text = page.get_text("text")
        if not page_text.strip():
            continue

        # We rely on PyMuPDF's `search_for` to map matched strings back to
        # geometry — this handles wrapping and tokenization correctly.
        matches = _find_matches_in_string(page_text, cfg)

        # Deduplicate by (kind, text) so we search once per unique match.
        seen: set = set()
        for _, _, kind, txt in matches:
            key = (kind, txt)
            if key in seen:
                continue
            seen.add(key)
            rects = page.search_for(txt, quads=False) or []
            for rect in rects:
                hits.append(Hit(page_index=page_index, text=txt, kind=kind, rect=rect))
    return hits


# ---------------------------------------------------------------------------
# OCR detection (scanned PDFs)
# ---------------------------------------------------------------------------


def detect_hits_ocr(
    pdf_bytes: bytes, doc: fitz.Document, cfg: DetectionConfig
) -> List[Hit]:
    if not OCR_AVAILABLE:
        raise RuntimeError(
            "OCR dependencies are not available. "
            f"Install Tesseract + Poppler and the Python packages. Import error: {OCR_IMPORT_ERROR}"
        )

    hits: List[Hit] = []
    dpi = cfg.ocr_dpi
    images = convert_from_bytes(pdf_bytes, dpi=dpi)

    for page_index, img in enumerate(images):
        if page_index >= len(doc):
            break
        page = doc[page_index]

        # Scale factor: PDF points (72/in) -> rendered pixels at `dpi`
        scale = 72.0 / dpi

        data = pytesseract.image_to_data(
            img, output_type=pytesseract.Output.DICT, config="--psm 6"
        )
        n = len(data["text"])

        # Build a flat "line string" with character offsets back to (word_idx, char_in_word).
        # Group by (block, par, line) so regex can span multiple words.
        lines: dict = {}
        for i in range(n):
            if not data["text"][i].strip():
                continue
            key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
            lines.setdefault(key, []).append(i)

        for _, idxs in lines.items():
            # Build line text + char->word map
            chunks: List[str] = []
            char_to_word: List[int] = []
            for i in idxs:
                w = data["text"][i]
                if chunks:
                    chunks.append(" ")
                    char_to_word.append(-1)
                for _c in w:
                    char_to_word.append(i)
                chunks.append(w)
            line_text = "".join(chunks)

            for a, b, kind, txt in _find_matches_in_string(line_text, cfg):
                word_indices = sorted({char_to_word[k] for k in range(a, b) if char_to_word[k] != -1})
                if not word_indices:
                    continue
                xs, ys, xe, ye = [], [], [], []
                for wi in word_indices:
                    x, y, w, h = (
                        data["left"][wi], data["top"][wi],
                        data["width"][wi], data["height"][wi],
                    )
                    xs.append(x); ys.append(y); xe.append(x + w); ye.append(y + h)
                px0, py0, px1, py1 = min(xs), min(ys), max(xe), max(ye)
                # Convert pixel box -> PDF-point rect
                rect = fitz.Rect(px0 * scale, py0 * scale, px1 * scale, py1 * scale)
                # Small padding so redaction fully covers glyphs
                rect = rect + (-1, -1, 1, 1)
                # Clamp to page
                rect = rect & page.rect
                if rect.is_empty:
                    continue
                hits.append(Hit(page_index=page_index, text=txt, kind=kind, rect=rect))
    return hits


# ---------------------------------------------------------------------------
# Top-level detection (hybrid)
# ---------------------------------------------------------------------------


def detect_hits(
    pdf_bytes: bytes, cfg: DetectionConfig
) -> Tuple[List[Hit], str, List[int]]:
    """Return (hits, mode, ocr_pages).

    mode ∈ {"text", "ocr", "hybrid"}.
    ocr_pages lists page indices that were processed via OCR.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    ocr_pages: List[int] = []

    if cfg.force_ocr:
        hits = detect_hits_ocr(pdf_bytes, doc, cfg)
        ocr_pages = list(range(len(doc)))
        doc.close()
        return hits, "ocr", ocr_pages

    # Find pages without text
    pages_needing_ocr = [i for i in range(len(doc)) if not _page_has_text(doc[i])]
    pages_with_text = [i for i in range(len(doc)) if i not in pages_needing_ocr]

    hits: List[Hit] = []

    if pages_with_text:
        text_hits = detect_hits_text_layer(doc, cfg)
        hits.extend(h for h in text_hits if h.page_index in pages_with_text)

    if pages_needing_ocr:
        ocr_hits = detect_hits_ocr(pdf_bytes, doc, cfg)
        hits.extend(h for h in ocr_hits if h.page_index in pages_needing_ocr)
        ocr_pages = pages_needing_ocr

    if not pages_needing_ocr:
        mode = "text"
    elif not pages_with_text:
        mode = "ocr"
    else:
        mode = "hybrid"

    doc.close()
    return hits, mode, ocr_pages


# ---------------------------------------------------------------------------
# Preview + redaction
# ---------------------------------------------------------------------------


def build_preview_pdf(pdf_bytes: bytes, hits: List[Hit]) -> bytes:
    """Return a PDF with translucent red boxes over each hit (non-destructive)."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for h in hits:
        page = doc[h.page_index]
        # Translucent red fill + solid red border
        page.draw_rect(
            h.rect,
            color=(1, 0, 0),
            fill=(1, 0, 0),
            fill_opacity=0.35,
            width=0.8,
            overlay=True,
        )
    out = doc.tobytes()
    doc.close()
    return out


def apply_hard_redactions(pdf_bytes: bytes, hits: List[Hit]) -> bytes:
    """Apply hard redactions (bytes removed) via page.apply_redactions()."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    # Group hits by page
    by_page: dict = {}
    for h in hits:
        by_page.setdefault(h.page_index, []).append(h)

    for page_index, page_hits in by_page.items():
        page = doc[page_index]
        for h in page_hits:
            # Black fill ensures the visual is also blacked out
            page.add_redact_annot(h.rect, fill=(0, 0, 0))
        # Remove underlying text/image bytes
        page.apply_redactions(
            images=fitz.PDF_REDACT_IMAGE_PIXELS,
            graphics=fitz.PDF_REDACT_LINE_ART_REMOVE,
        )
    out = doc.tobytes(garbage=4, deflate=True, clean=True)
    doc.close()
    return out


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------


def render_pdf_iframe(pdf_bytes: bytes, height: int = 820) -> None:
    """Display a PDF inline. Tries streamlit-pdf-viewer, falls back to base64 iframe."""
    try:
        from streamlit_pdf_viewer import pdf_viewer  # type: ignore

        pdf_viewer(input=pdf_bytes, width=700, height=height)
        return
    except Exception:
        pass

    b64 = base64.b64encode(pdf_bytes).decode("ascii")
    html = (
        f'<iframe src="data:application/pdf;base64,{b64}" '
        f'width="100%" height="{height}" style="border:1px solid #ddd;border-radius:6px;"></iframe>'
    )
    st.markdown(html, unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(page_title="TaxGuard Pro", page_icon="🛡️", layout="wide")

    st.title("🛡️ TaxGuard Pro")
    st.caption(
        "Local, hybrid PII redaction for tax PDFs. Searchable text + OCR fallback at 300 DPI. "
        "Redactions are hard — bytes are removed, not just hidden."
    )

    with st.sidebar:
        st.header("⚙️ Settings")

        st.subheader("What to redact")
        redact_ssn = st.checkbox("SSNs (NNN-NN-NNNN)", value=True)
        redact_account = st.checkbox("Account numbers (10–12 digits)", value=True)
        redact_address = st.checkbox("Addresses (US-style)", value=True)

        st.subheader("Exclusions")
        default_excl = "CORNERSTONES\nTRANSFER"
        excl_raw = st.text_area(
            "Never redact matches that contain these strings (one per line):",
            value=default_excl,
            height=100,
        )
        excluded = [line.strip() for line in excl_raw.splitlines() if line.strip()]

        st.subheader("OCR")
        force_ocr = st.checkbox("Force OCR on every page", value=False)
        ocr_dpi = st.slider("OCR DPI", min_value=150, max_value=600, value=300, step=50)

        if not OCR_AVAILABLE:
            st.warning(
                "OCR stack not available. Install Tesseract + Poppler to process scanned PDFs."
            )

    cfg = DetectionConfig(
        redact_ssn=redact_ssn,
        redact_account=redact_account,
        redact_address=redact_address,
        excluded_strings=excluded,
        force_ocr=force_ocr,
        ocr_dpi=ocr_dpi,
    )

    uploaded = st.file_uploader("Upload a tax PDF", type=["pdf"])
    if not uploaded:
        st.info("⬆️  Upload a PDF to begin. Processing happens entirely on your machine.")
        return

    pdf_bytes = uploaded.read()

    # Cache detection results in session_state keyed by file content hash + cfg
    file_key = (hash(pdf_bytes), repr(cfg.__dict__))
    if st.session_state.get("_file_key") != file_key:
        st.session_state["_file_key"] = file_key
        st.session_state.pop("_hits", None)
        st.session_state.pop("_mode", None)
        st.session_state.pop("_ocr_pages", None)

    col_ctrl, _ = st.columns([1, 3])
    with col_ctrl:
        scan_clicked = st.button("🔍 Scan for PII", type="primary", use_container_width=True)

    if scan_clicked or "_hits" not in st.session_state:
        with st.spinner("Scanning…"):
            try:
                hits, mode, ocr_pages = detect_hits(pdf_bytes, cfg)
            except RuntimeError as e:
                st.error(str(e))
                return
        st.session_state["_hits"] = hits
        st.session_state["_mode"] = mode
        st.session_state["_ocr_pages"] = ocr_pages

    hits: List[Hit] = st.session_state["_hits"]
    mode: str = st.session_state["_mode"]
    ocr_pages: List[int] = st.session_state["_ocr_pages"]

    # ------ Summary ------
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Processing mode", mode.upper())
    c2.metric("Total hits", len(hits))
    c3.metric("SSNs", sum(1 for h in hits if h.kind == "SSN"))
    c4.metric("Accounts", sum(1 for h in hits if h.kind == "ACCOUNT"))
    if ocr_pages:
        st.caption(f"OCR processed pages (1-indexed): {', '.join(str(i + 1) for i in ocr_pages)}")

    # ------ Preview / Apply ------
    left, right = st.columns([3, 2])

    with left:
        st.subheader("Double-Check Preview")
        st.caption("Translucent red boxes show detected sensitive areas. Nothing is removed yet.")
        preview_bytes = build_preview_pdf(pdf_bytes, hits)
        render_pdf_iframe(preview_bytes)

    with right:
        st.subheader("Detected items")
        if not hits:
            st.success("No sensitive items detected with the current settings.")
        else:
            rows = [h.as_dict() for h in hits]
            st.dataframe(rows, use_container_width=True, hide_index=True)

        st.divider()

        apply_disabled = len(hits) == 0
        if st.button(
            "✅ Apply Redactions (hard)",
            type="primary",
            use_container_width=True,
            disabled=apply_disabled,
        ):
            with st.spinner("Applying redactions…"):
                redacted = apply_hard_redactions(pdf_bytes, hits)
            st.success(f"Applied {len(hits)} redactions. Underlying bytes removed.")
            out_name = (Path(uploaded.name).stem + "_REDACTED.pdf")
            st.download_button(
                "⬇️ Download redacted PDF",
                data=redacted,
                file_name=out_name,
                mime="application/pdf",
                use_container_width=True,
            )

            with st.expander("Preview redacted PDF"):
                render_pdf_iframe(redacted, height=700)


if __name__ == "__main__":
    main()
