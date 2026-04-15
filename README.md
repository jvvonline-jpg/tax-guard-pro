# TaxGuard Pro

Local Streamlit application for redacting sensitive PII (SSNs, account numbers, and addresses) from tax documents. Handles both searchable and scanned (image-based) PDFs via a hybrid text-extraction + OCR pipeline.

All processing happens on your machine — nothing is uploaded anywhere.

## Features

- **Hybrid processing** — checks whether each page has a searchable text layer. If not, falls back automatically to OCR at 300 DPI (configurable).
- **Deterministic detection**:
  - SSNs via the regex `\d{3}-\d{2}-\d{4}`
  - Account numbers of 10–12 consecutive digits
  - US-style addresses
- **Exclusion list** — bank headers like `CORNERSTONES` or `TRANSFER` are never redacted (configurable in the sidebar).
- **Double-Check preview** — detected regions are overlaid with translucent red boxes on the PDF before anything is removed. Review first, then click **Apply Redactions**.
- **Surgical, hard redaction** — uses PyMuPDF's `page.apply_redactions()` so the underlying bytes are deleted, not just covered with a rectangle.
- **Download** the final redacted PDF directly from the browser.

## Setup

### 1. System dependencies (macOS — Homebrew)

TaxGuard Pro uses Tesseract for OCR and Poppler for rasterizing PDF pages.

```bash
brew install tesseract
brew install poppler
```

On Linux (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr poppler-utils
```

On Windows, install Tesseract from the UB Mannheim build and Poppler for Windows, then add both `bin/` directories to your `PATH`.

### 2. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run

```bash
streamlit run app.py
```

The app opens at <http://localhost:8501>.

## How to use

1. Upload a tax PDF (W-2, 1099, bank statement, etc.).
2. Click **Scan for PII**. The app reports the processing mode used (`TEXT`, `OCR`, or `HYBRID`) and which pages were OCR'd.
3. Review the **Double-Check Preview** — translucent red boxes show every region that will be redacted. Nothing has been removed yet.
4. Adjust settings in the sidebar if needed (toggle categories, edit the exclusion list, force OCR, change DPI). Re-scan.
5. Click **Apply Redactions (hard)**. The app removes the underlying content with `apply_redactions()` and offers the redacted PDF for download.

## How the redaction works

Redaction is performed with PyMuPDF's native redaction annotations:

```python
page.add_redact_annot(rect, fill=(0, 0, 0))
page.apply_redactions(
    images=fitz.PDF_REDACT_IMAGE_PIXELS,
    graphics=fitz.PDF_REDACT_LINE_ART_REMOVE,
)
```

`apply_redactions()` deletes the glyphs, image pixels, and vector graphics that fall inside each annotation — the data is gone from the PDF content stream, not merely painted over. Copy/paste, text search, and programmatic extraction will not recover it.

For scanned pages, bounding boxes come from Tesseract's `image_to_data` output. Pixel coordinates are mapped back into PDF points using the render DPI (`scale = 72 / dpi`) and clamped to the page rectangle.

## Files

- `app.py` — the Streamlit app (detection + preview + hard redaction).
- `requirements.txt` — Python dependencies.
- `README.md` — this file.

## Notes and caveats

- The address regex is intentionally conservative to minimize false positives on boilerplate text. Expect some addresses (especially international or unusual formats) to be missed — rely on the preview.
- If OCR misses an SSN or account number (blurry scans, unusual fonts), try raising the DPI slider to 450–600 in the sidebar before scanning.
- The exclusion list is matched case-insensitively against each candidate match's text, so `CORNERSTONES BANK` in a header will not be redacted as an address.
