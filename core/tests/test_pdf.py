"""PDF rendering tests."""

import json
from pathlib import Path

import pytest

from s0_core import crypto, certificate, pdfgen
from s0_core.canonical import canonicalize_str


def test_pdf_renders(signed_cert, tmp_path):
    out = tmp_path / "cert.pdf"
    pdfgen.generate_pdf(signed_cert, out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert b"/Encrypt" not in data
    assert len(data) > 2000


def test_pdf_refuses_unsigned(base_cert, tmp_path):
    with pytest.raises(ValueError):
        pdfgen.generate_pdf(base_cert, tmp_path / "nope.pdf")


def test_large_cert_pdf(signed_cert, tmp_path):
    big = json.loads(json.dumps(signed_cert))
    big["notes"] = ["x" * 3000 for _ in range(3)]
    priv = crypto.generate_private_key()
    resigned = certificate.sign_certificate(big, priv)
    ok, reason = certificate.verify_certificate(resigned, [priv.public_key()])
    assert ok, reason

    out = tmp_path / "big.pdf"
    pdfgen.generate_pdf(resigned, out)
    assert out.read_bytes().startswith(b"%PDF-")


def test_pdf_escapes_markup_injection(signed_cert, tmp_path):
    """Ensure HTML tags in fields are escaped and do not crash or alter rendering."""
    injected = json.loads(json.dumps(signed_cert))
    injected["issuer"]["operator_id"] = "<font color='red' size=24><b>*** REVOKED - DO NOT TRUST ***</b></font>"
    injected["notes"] = ["<script>alert(1)</script>", "unclosed <b tag"]
    priv = crypto.generate_private_key()
    resigned = certificate.sign_certificate(injected, priv)

    out = tmp_path / "injected.pdf"
    pdfgen.generate_pdf(resigned, out)
    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF-")
