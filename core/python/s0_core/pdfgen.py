"""Human-readable PDF certificate generation without external QR dependencies.

The PDF is a visual rendering of the signed JSON certificate. The canonical JSON
remains the cryptographic artifact of record.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

__all__ = ["generate_pdf"]

_STATUS_COLORS = {
    "success": colors.HexColor("#1b7f3b"),
    "reset_triggered": colors.HexColor("#1b5e9f"),
    "partial": colors.HexColor("#c08500"),
    "failure": colors.HexColor("#a32020"),
}


def generate_pdf(
    cert: dict,
    out_path: str | Path,
    **_kwargs,
) -> Path:
    """Render a SIGNED certificate dict to PDF. Raises if the cert has no signature."""
    if "signature" not in cert:
        raise ValueError("refusing to render an UNSIGNED certificate to PDF")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    status = cert["result"]["status"]
    device = cert.get("device", {})
    wipe = cert.get("wipe", {})
    result = cert.get("result", {})
    verif = result.get("verification") or {}
    sig = cert["signature"]

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        title=f"s0 Wipe Certificate {cert["cert_uuid"]}",
        author=cert["issuer"]["organization"],
    )
    styles = getSampleStyleSheet()
    mono = ParagraphStyle("mono", parent=styles["Code"], fontSize=7, leading=9)
    story = []

    story.append(Paragraph("<b>S0 — SECURE WIPE CERTIFICATE</b>", styles["Title"]))
    banner = Table(
        [[Paragraph(
            f"<para color='white'><b>{_xml_escape(status.upper())}</b> — NIST 800-88 category: "
            f"<b>{_xml_escape(str(wipe.get("nist_category", "?")))}</b></para>",
            styles["Normal"])]],
        colWidths=[170 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _STATUS_COLORS.get(status, colors.grey)),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(banner)

    from .crypto import DEMO_KEY_FINGERPRINT
    is_demo = (
        sig.get("public_key_fingerprint") == DEMO_KEY_FINGERPRINT
        or "demo" in cert.get("issuer", {}).get("organization", "").lower()
        or any("demo" in str(n).lower() for n in cert.get("notes", []))
    )
    if is_demo:
        demo_banner = Table(
            [[Paragraph(
                "<para color='#990000' align='center'><b>⚠️ DEMONSTRATION CERTIFICATE — SIGNED WITH PUBLIC DEMO KEY</b><br/>"
                "<font size='7.5'>This certificate was signed with an unaccredited public demonstration key. "
                "DO NOT use for legal chain-of-custody or regulatory compliance.</font></para>",
                styles["Normal"])]],
            colWidths=[170 * mm],
        )
        demo_banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff3cd")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#ffeeba")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Spacer(1, 3 * mm))
        story.append(demo_banner)

    story.append(Spacer(1, 6 * mm))

    def rows(pairs):
        out = []
        for k, v in pairs:
            if not isinstance(v, (Paragraph, Table)):
                v = Paragraph(_xml_escape(str(v)))
            out.append([Paragraph(f"<b>{_xml_escape(str(k))}</b>"), v])
        return out

    body_style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
    ]

    story.append(Paragraph("Device", styles["Heading3"]))
    t = Table(rows([
        ("Certificate UUID", cert["cert_uuid"]),
        ("Issued at", cert["issued_at"]),
        ("Issuer", f"{cert["issuer"]["organization"]} / operator {cert["issuer"]["operator_id"]}"),
        ("Tool", f"{cert["tool"]["name"]} {cert["tool"]["version"]} ({cert["tool"]["platform"]})"),
        ("Device ID", device.get("device_id", "?")),
        ("Type / storage", f"{device.get("device_type", "?")} / {device.get("storage_type", "?")}"),
        ("Model / serial", f"{device.get("model", "—")} / {device.get("serial_number", "—")}"),
        ("Capacity", f"{device.get("capacity_bytes", 0):,} bytes"),
    ]), colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle(body_style))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("Wipe performed", styles["Heading3"]))
    t = Table(rows([
        ("Method", wipe.get("method", "?")),
        ("NIST 800-88 tier", wipe.get("nist_category", "?")),
        ("Passes / pattern", f"{wipe.get("passes", "—")} / {wipe.get("pattern", "—")}"),
        ("Started / ended", f"{wipe.get("start_time")} → {wipe.get("end_time")}"),
        ("Bytes processed", f"{wipe.get("bytes_processed", 0):,}"),
        ("Result status", result.get("status", "?")),
    ] + ([("Errors", "; ".join(result.get("errors", [])))] if result.get("errors") else [])
      + ([("Post-wipe verification",
           f"{verif.get("method", "?")}: {verif.get("samples_checked", 0)} samples × "
           f"{verif.get("sample_bytes_each", 0)} B, all match: "
           f"{verif.get("all_samples_match_wipe_pattern")}")] if verif else [])),
        colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle(body_style))
    story.append(t)

    if cert.get("notes"):
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Notes", styles["Heading3"]))
        for n in cert["notes"]:
            story.append(Paragraph(f"• {_xml_escape(str(n))}", styles["Normal"]))

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Cryptographic signature", styles["Heading3"]))
    sig_rows = rows([
        ("Algorithm", sig.get("algorithm", "?")),
        ("Issuer key fingerprint", sig.get("public_key_fingerprint", "?")),
        ("Payload SHA-256", sig.get("signed_payload_hash", "(not recorded)")),
        ("Signature (base64url)", Paragraph(sig["signature_base64url"], mono)),
        ("Verify offline", "Verify with CLI: s0 verify cert.json --key issuer_public.pem"),
    ])
    t = Table(sig_rows, colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle(body_style))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    verif_info = Table([[Paragraph(
        "<font size='8'>This PDF document is a human-readable rendering of the signed JSON certificate.<br/>"
        "The canonical JSON file is the authoritative forensic artifact. The digital signature covers all fields above.<br/>"
        "Verify certificate integrity offline with <code>s0 verify</code> or online at "
        "<a href='https://s0-vp.vercel.app/' color='#1d4ed8'><u>https://s0-vp.vercel.app/</u></a>.</font>",
        styles["Normal"]
    )]], colWidths=[170 * mm])
    verif_info.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(verif_info)

    doc.build(story)
    return out_path
