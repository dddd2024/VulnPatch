"""
Enhanced PDF report generator for VulnPatch.

Generates PDF-format audit reports from AuditResult objects.
Uses the professional HTML report as intermediate format and converts via weasyprint or pdfkit.
Includes all sections from the HTML report with proper page breaks.

Conversion engines are tried in order:
1. weasyprint  -- pure-Python, no external binaries required (recommended)
2. pdfkit      -- wraps wkhtmltopdf; requires the binary on PATH
3. Plain-text fallback -- returns UTF-8 encoded Markdown if neither engine is available
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Optional

from audit_core.models import AuditResult
from report.html_report import build_html_report
from report.markdown_report import build_markdown_report

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PDF-optimized CSS overrides
# ---------------------------------------------------------------------------

_PDF_PRINT_CSS = """
/* --- PDF-specific overrides for weasyprint/pdfkit --- */
@page {
    size: A4;
    margin: 20mm 15mm 25mm 15mm;
    @bottom-center {
        content: "VulnPatch Security Audit Report  |  Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #888;
        font-family: 'Helvetica', sans-serif;
    }
}

/* Force white background for PDF */
*, *::before, *::after {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    color-adjust: exact !important;
}

body {
    background: #ffffff !important;
    color: #1a1a1a !important;
    font-size: 11px !important;
    line-height: 1.5 !important;
    max-width: 100% !important;
    padding: 0 !important;
}

/* Override dark theme for PDF */
:root {
    --bg-primary: #ffffff !important;
    --bg-secondary: #f8f9fa !important;
    --bg-tertiary: #f0f1f3 !important;
    --border-primary: #ddd !important;
    --border-secondary: #e5e5e5 !important;
    --text-primary: #1a1a1a !important;
    --text-secondary: #555 !important;
    --text-muted: #888 !important;
}

/* Remove shadows and rounded corners for print */
.report-header, .section, .toc, .report-footer,
.kpi-card, .finding-card, .evidence-card, .verification-card,
.chart-panel, .gauge-container, .code-block, .hypothesis-item,
.log-content, .call-step, .empty-state-box {
    box-shadow: none !important;
    border-radius: 2px !important;
}

/* Page break controls */
.report-header {
    page-break-after: avoid;
}

.toc {
    page-break-after: always;
}

.section {
    page-break-inside: avoid;
    margin: 12px 0 !important;
    padding: 16px 20px !important;
}

.section:first-of-type {
    page-break-before: avoid;
}

#executive-summary {
    page-break-after: avoid;
}

#kpi-dashboard {
    page-break-after: avoid;
}

#charts {
    page-break-after: avoid;
}

.finding-card, .evidence-card, .verification-card {
    page-break-inside: avoid;
    margin-bottom: 10px !important;
}

/* Ensure code blocks don't break awkwardly */
.code-block {
    page-break-inside: avoid;
}

/* KPI cards should stay together */
.kpi-grid {
    page-break-inside: avoid;
}

/* Charts side by side */
.charts-grid {
    grid-template-columns: 1fr 1fr !important;
    page-break-inside: avoid;
}

/* Links should show URL in print */
a[href]::after {
    content: none; /* Don't append URLs for CWE links to keep clean */
}

/* Footer handling */
.report-footer {
    page-break-before: avoid;
    margin-top: 20px !important;
}

/* Ensure SVG charts render properly */
svg {
    max-width: 100%;
    height: auto;
}

/* Table-like grid layouts */
.finding-details-grid {
    grid-template-columns: repeat(3, 1fr) !important;
}

.exec-summary-grid {
    grid-template-columns: 250px 1fr !important;
}

.verification-summary {
    page-break-inside: avoid;
}

/* Remove hover effects */
.kpi-card:hover {
    transform: none !important;
}
"""


def _build_pdf_html(result: AuditResult) -> str:
    """
    Build HTML optimized for PDF conversion.

    Injects PDF-specific CSS overrides into the HTML report
    to ensure proper rendering in weasyprint/pdfkit.
    """
    base_html = build_html_report(result)

    # Inject PDF overrides before </head>
    pdf_css_tag = f'<style>{_PDF_PRINT_CSS}</style>'
    if '</head>' in base_html:
        pdf_html = base_html.replace('</head>', f'{pdf_css_tag}\n</head>')
    else:
        pdf_html = base_html

    return pdf_html


def _try_weasyprint(html_content: str) -> bytes:
    """Convert HTML to PDF using weasyprint with enhanced settings."""
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("weasyprint is not installed, skipping")
        raise

    # Use enhanced settings for better PDF output
    pdf_bytes = HTML(string=html_content).write_pdf(
        presentational_hints=True,
    )
    logger.info("PDF generated successfully via weasyprint")
    return pdf_bytes


def _try_pdfkit(html_content: str) -> bytes:
    """Convert HTML to PDF using pdfkit with enhanced settings."""
    try:
        import pdfkit  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("pdfkit is not installed, skipping")
        raise

    # Enhanced options for professional PDF output
    options = {
        'page-size': 'A4',
        'margin-top': '20mm',
        'margin-right': '15mm',
        'margin-bottom': '25mm',
        'margin-left': '15mm',
        'encoding': 'UTF-8',
        'enable-local-file-access': None,
        'print-media-type': None,
        'no-outline': None,
        'footer-center': 'VulnPatch Security Audit Report  |  Page [page] of [topage]',
        'footer-font-size': '9',
        'footer-font-name': 'Helvetica',
        'footer-spacing': '5',
        'header-spacing': '5',
        'dpi': 300,
        'image-quality': 100,
    }

    pdf_bytes = pdfkit.from_string(html_content, False, options=options)
    logger.info("PDF generated successfully via pdfkit")
    return pdf_bytes


def _fallback_plain_text(result: AuditResult) -> bytes:
    """
    Fallback: return a plain-text representation when no PDF engine is available.

    This ensures the function always returns something usable.
    """
    logger.warning(
        "Neither weasyprint nor pdfkit is available; "
        "returning plain-text report as fallback"
    )
    text = build_markdown_report(result)
    return text.encode("utf-8")


def build_pdf_report(
    result: AuditResult,
    output_path: str | None = None,
) -> bytes:
    """
    Build a professional PDF report from an audit result.

    The function first generates a PDF-optimized HTML report (via
    ``_build_pdf_html``), then converts it to PDF.  Conversion engines
    are tried in order:

    1. **weasyprint** -- pure-Python, no external binaries required.
       Produces the best results with CSS custom properties and SVG support.
    2. **pdfkit** -- wraps wkhtmltopdf; requires the binary on ``PATH``.
       Good alternative with proper page break support.
    3. **Plain-text fallback** -- returns UTF-8 encoded Markdown if neither
       engine is available.

    The PDF includes all sections from the HTML report:
    - Executive Summary with risk gauge
    - KPI cards
    - Severity Distribution and Category charts
    - Detailed Findings with severity badges, CWE links, What-Why-How analysis
    - Verification Results
    - Evidence Chain with code snippets
    - Agent Analysis Log
    - Professional footer with page numbers

    Args:
        result: The audit result to convert.
        output_path: If provided, the PDF bytes are also written to this
            file path.  The bytes are always returned regardless.

    Returns:
        PDF file contents as ``bytes``.  If no PDF engine is available the
        return value is a UTF-8 plain-text report instead.
    """
    # Build PDF-optimized HTML
    html_content = _build_pdf_html(result)

    # --- Try weasyprint first (best SVG/CSS support) ---
    pdf_bytes: bytes | None = None
    try:
        pdf_bytes = _try_weasyprint(html_content)
    except Exception:
        logger.debug("weasyprint failed, trying pdfkit", exc_info=True)

    # --- Try pdfkit as second choice ---
    if pdf_bytes is None:
        try:
            pdf_bytes = _try_pdfkit(html_content)
        except Exception:
            logger.debug("pdfkit failed, falling back to plain text", exc_info=True)

    # --- Fallback to plain text ---
    if pdf_bytes is None:
        pdf_bytes = _fallback_plain_text(result)

    # --- Optionally write to disk ---
    if output_path is not None:
        try:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(pdf_bytes)
            logger.info("PDF report saved to %s", output_path)
        except Exception:
            logger.error("Failed to write PDF to %s", output_path, exc_info=True)
            raise

    return pdf_bytes
