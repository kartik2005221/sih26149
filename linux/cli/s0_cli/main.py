"""S0 (Sector Zero) — Unified Forensic Sanitization & Recovery CLI.

Core Modules:
  1. Drive Eraser:
     s0 list                       inventory of block devices
     s0 plan  --target PATH        dry-run: method, tier, warnings
     s0 wipe  --target PATH        sanitize drive, verify, issue certificate

  2. File & Folder Eraser:
     s0 erase --targets PATH...    secure deletion & metadata scrubbing

  3. Advanced File Carving & Recovery:
     s0 carve --target PATH --out-dir DIR   signature & structure recovery (FAT32)

  4. Blockchain Audit Ledger:
     s0 audit list                 display cryptographic audit blocks
     s0 audit verify               verify blockchain hash-chain integrity

  5. Offline Verification & Key Management:
     s0 verify CERT_JSON           verify signed certificate offline
     s0 keygen                     generate Ed25519 authority/operator keypair

  6. Web Forensics Dashboard:
     s0 web                        launch local browser dashboard
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from s0_core import certificate as cert_mod
from s0_core.crypto import is_demo_key
from s0_core.progress import ProgressBar

from . import __version__
from .audit import init_audit_db, list_audit_blocks, record_audit_event, verify_audit_ledger
from .carver import carve_image, signature_from_dict
from .devices import SafetyError, check_safety, get_block_device_size, image_target, list_block_targets
from .devices import Target as DevTarget
from .file_eraser import erase_batch
from .methods.ata import AtaSecureEraseMethod, hpa_dco_report
from .methods.base import Plan
from .methods.overwrite import OverwriteMethod, plant_patterns
from .wipe import (
    default_issuer_key,
    make_certificate,
    select_method,
    take_pre_samples,
    verify_wipe,
)

DEFAULT_OPERATOR = "op-forensic"
DEFAULT_ORGANIZATION = "Digital Forensics & Data Sanitization Lab"
DEFAULT_KEY_PATH = "core/keys/demo_issuer_private.pem"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _warn_if_demo_key(key_path: Path | None) -> None:
    if key_path is not None and is_demo_key(key_path):
        sys.stderr.write(
            "\n\033[33m[!] NOTICE: Operation signed with unaccredited demonstration key (demo_issuer_private.pem).\n"
            "    DO NOT use this certificate for legal chain-of-custody or regulatory compliance.\033[0m\n\n"
        )


_LEGAL_NOTICE = (
    "\n\033[1;33m⚖  LEGAL & RESPONSIBLE USE NOTICE:\033[0m\n"
    "\033[33m   Only operate on storage media you own or have explicit written authorization\n"
    "   to process. Unauthorized wiping, erasure, or forensic recovery may violate\n"
    "   computer crime legislation (e.g., CFAA 18 U.S.C. § 1030, Computer Misuse Act,\n"
    "   IT Act 2000 §§ 43/66). s0 is a certified forensic suite for authorized personnel.\033[0m\n\n"
)


def _print_legal_notice() -> None:
    if os.environ.get("S0_LEGAL_NOTICE_SHOWN"):
        return
    os.environ["S0_LEGAL_NOTICE_SHOWN"] = "1"
    sys.stderr.write(_LEGAL_NOTICE)


def _resolve_target(path: str) -> DevTarget:
    p = Path(path)
    is_blk = False
    try:
        is_blk = p.is_block_device()
    except Exception:
        pass
    if is_blk:
        for t in list_block_targets():
            if Path(t.path).resolve() == p.resolve():
                return t
        size = get_block_device_size(p)
        if size <= 0:
            raise SafetyError(f"Block device {p} has zero or unreadable capacity.")
        return DevTarget(path=str(p), kind="block", capacity_bytes=size)
    return image_target(path)


def _print_plan(
    target: DevTarget, candidate, alternatives, warnings: list[str], hpa_dco: dict | None
) -> None:
    m = candidate.method
    print(f"target          : {target.display}")
    if m is None:
        print("method          : NONE AVAILABLE")
        print(f"reason          : {candidate.reason}")
        return
    plan: Plan = m.plan(target)
    print(f"method          : {plan.method_id}")
    print(f"nist category   : {plan.nist_category}")
    print(f"summary         : {plan.summary}")
    if plan.commands:
        print("commands        :")
        for c in plan.commands:
            print(f"  - {c}")
    all_warnings = warnings + plan.warnings
    if all_warnings:
        print("warnings        :")
        for w in all_warnings:
            print(f"  ! {w}")
    if alternatives:
        print("alternatives    :")
        for a in alternatives:
            state = "available" if a.available else "unavailable"
            print(f"  - [{state}] {a.reason}")
    if hpa_dco and (
        hpa_dco.get("hpa_present") or hpa_dco.get("dco_present") or hpa_dco.get("note")
    ):
        print("hpa/dco         : " + json.dumps(hpa_dco))
        if hpa_dco.get("restore_command"):
            print(f"                  remove BEFORE wiping: {hpa_dco['restore_command']}")


# --------------------------------------------------------------------------- #
# Module 1: Drive Eraser Subcommands
# --------------------------------------------------------------------------- #


def cmd_list(args) -> int:
    targets = list_block_targets()
    mounted = set()
    try:
        with open("/proc/mounts") as f:
            mounted = {line.split()[0] for line in f}
    except OSError:
        pass

    if getattr(args, "output_format", "text") == "json":
        data = [
            {
                "path": t.path,
                "kind": t.kind,
                "storage_type": t.storage_type,
                "capacity_bytes": t.capacity_bytes,
                "model": t.model,
                "serial": t.serial,
                "mounted": any(m.startswith(t.path) for m in mounted),
            }
            for t in targets
        ]
        print(json.dumps(data, indent=2))
        return 0

    if not targets:
        print("(no block devices found)")
        return 0
    print(
        f"{'PATH':<14} {'TYPE':<7} {'STORAGE':<10} {'CAPACITY':>12}  "
        f"{'MODEL':<24} {'SERIAL':<16} MOUNTED?"
    )
    for t in targets:
        cap = f"{t.capacity_bytes / 2**30:.1f} GiB"
        is_mounted = "YES" if any(m.startswith(t.path) for m in mounted) else "-"
        print(
            f"{t.path:<14} {t.kind:<7} {t.storage_type:<10} {cap:>12}  "
            f"{(t.model or '—')[:24]:<24} {(t.serial or '—')[:16]:<16} {is_mounted}"
        )
    print("\nImage-file targets work too (no root needed): use --target /path/to/file.img")
    return 0


def cmd_plan(args) -> int:
    try:
        target = _resolve_target(args.target)
    except (FileNotFoundError, SafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if target.capacity_bytes <= 0:
        print(f"error: target {target.path} has zero or unreadable capacity.", file=sys.stderr)
        return 2

    try:
        warnings = check_safety(target, force=args.force)
    except SafetyError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    candidate, alternatives = select_method(
        target,
        passes=args.passes,
        pattern=args.pattern,
        prefer_firmware=not args.no_firmware,
        discard_justification=args.discard_purge_justification,
    )
    hpa_dco = None
    if target.kind == "block" and not target.path.startswith("/dev/nvme") and shutil.which("hdparm"):
        hpa_dco = hpa_dco_report(target)
    _print_plan(target, candidate, alternatives, warnings, hpa_dco)
    print("\nDRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
    return 0


def cmd_wipe(args) -> int:
    _print_legal_notice()
    t_start = time.monotonic()
    start_time = _now()
    try:
        target = _resolve_target(args.target)
    except (FileNotFoundError, SafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if target.capacity_bytes <= 0:
        print(f"error: target {target.path} has zero or unreadable capacity.", file=sys.stderr)
        return 2

    try:
        warnings = check_safety(target, force=args.force)
    except SafetyError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    candidate, alternatives = select_method(
        target,
        passes=args.passes,
        pattern=args.pattern,
        prefer_firmware=not args.no_firmware,
        discard_justification=args.discard_purge_justification,
    )
    if candidate.method is None:
        print(f"error: no applicable wipe method ({candidate.reason})", file=sys.stderr)
        return 2

    plan = candidate.method.plan(target)
    if not args.yes:
        _print_plan(target, candidate, alternatives, warnings, None)
        answer = input(
            f"\nType '{target.path}' to confirm permanent erasure ({plan.method_id}, NIST {plan.nist_category}): "
        )
        if answer.strip() != str(target.path):
            print("aborted — nothing was written", file=sys.stderr)
            return 2
    else:
        sys.stderr.write(f"[s0 wipe plan] target={target.path} method={plan.method_id} tier={plan.nist_category}\n")

    planted = None
    pre_samples = None
    offsets = None
    if args.plant_markers:
        marker = b"S0-DEMO-CONFIDENTIAL-" + secrets.token_hex(8).encode()
        count = max(8, target.capacity_bytes // (4 * 1024 * 1024))
        plant_patterns(
            target.path, [(i * (target.capacity_bytes // count), marker) for i in range(count)]
        )
        planted = [marker]
        print(f"planted {count} copies of a demo marker (will require 0 hits after)", file=sys.stderr)

    if args.pattern == "random":
        offsets, pre_samples = take_pre_samples(target)

    total_bytes = target.capacity_bytes * getattr(args, "passes", 1)
    bar = ProgressBar(total_bytes, operation="s0 wipe")

    def progress(msg: str) -> None:
        m_over = re.search(r"pass (\\d+)/(\d+):\s+([\d.]+)\s+(B|KiB|MiB|GiB|TiB)", msg)
        if m_over:
            p_idx = int(m_over.group(1)) - 1
            val = float(m_over.group(3))
            unit = m_over.group(4)
            mult = {"B": 1, "KiB": 1024, "MiB": 1048576, "GiB": 1073741824, "TiB": 1099511627776}.get(unit, 1)
            bytes_in_pass = int(val * mult)
            curr_total = (p_idx * target.capacity_bytes) + bytes_in_pass
            bar.update(curr_total)
            return

        m_disc = re.search(r"\\((\\d+)%\\)", msg)
        if m_disc:
            pct = int(m_disc.group(1))
            bar.update(int(target.capacity_bytes * (pct / 100.0)))
            return

        m_san = re.search(r"sanitize progress:\\s+(\\d+)%", msg)
        if m_san:
            pct = int(m_san.group(1))
            bar.update(int(target.capacity_bytes * (pct / 100.0)))
            return

        if not getattr(args, "json", False):
            print(f"[{time.monotonic() - t_start:8.1f}s] {msg}", file=sys.stderr)

    progress(f"wiping {target.display} with {plan.method_id} (NIST {plan.nist_category})")
    result = candidate.method.run(target, progress)
    bar.finish()
    end_time = _now()

    verif, _post = verify_wipe(
        target,
        args.pattern,
        samples=args.verify_samples,
        planted_needles=planted,
        pre_samples=pre_samples,
        offsets=offsets,
    )
    if not verif.get("all_samples_match_wipe_pattern", False):
        result.status = "failure"
        result.errors.append(
            "post-wipe verification FAILED — sampled sectors did not match expected pattern"
        )

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path)
    if key_path is None:
        print("error: no issuer signing key found.", file=sys.stderr)
        return 2

    cert = make_certificate(
        target,
        candidate.method,
        result,
        start_time,
        end_time,
        operator_id=args.operator,
        organization=args.organization,
        tool_version=__version__,
        key_path=key_path,
        verification=verif,
        extra_notes=warnings + [f"elapsed {time.monotonic() - t_start:.1f}s"],
    )

    try:
        blk = record_audit_event(cert, operation_type="DRIVE_ERASE", private_key=key_path)
        if not getattr(args, "json", False):
            print(f"audit ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
    except Exception as exc:
        print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
    cert_json.write_text(json.dumps(cert, indent=2) + "\n")

    pdf_path = None
    if not args.no_pdf:
        from s0_core import pdfgen
        pdf_path = out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf"
        pdfgen.generate_pdf(cert, pdf_path)

    ok = result.status == "success" and verif.get("all_samples_match_wipe_pattern") is True
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "status": cert["result"]["status"],
                    "verified": verif.get("all_samples_match_wipe_pattern"),
                    "certificate": str(cert_json),
                    "pdf": str(pdf_path) if pdf_path else None,
                    "cert_uuid": cert["cert_uuid"],
                },
                indent=2,
            )
        )
    else:
        print(f"\nresult        : {cert['result']['status']}")
        print(f"verification  : {json.dumps(verif)}")
        print(f"certificate   : {cert_json}" + (f"\nPDF           : {pdf_path}" if pdf_path else ""))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# Module 2: File & Folder Eraser Subcommand
# --------------------------------------------------------------------------- #


def cmd_erase_files(args) -> int:
    _print_legal_notice()
    print("==> S0 Module 2: Secure File & Folder Eraser")

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        print(
            "error: no issuer signing key found.\n"
            "S0 requires a valid Ed25519 signing key to issue compliance certificates and audit records.\n"
            "Specify --key <path> or pass --no-certificate to explicitly run without compliance certification.",
            file=sys.stderr,
        )
        return 2

    if getattr(args, "no_certificate", False):
        print("WARNING: --no-certificate specified. No compliance certificate or audit log will be generated.", file=sys.stderr)

    targets = [Path(t) for t in args.targets]
    print(f"==> Target items ({len(targets)}): {[str(t) for t in targets]}")

    total_est = sum(p.stat().st_size for p in targets if p.is_file()) * getattr(args, "passes", 1)
    bar = ProgressBar(max(total_est, 1024), operation="s0 erase") if total_est > 0 else None

    def erase_progress_cb(path_str: str, written: int, total_f: int) -> None:
        if bar:
            bar.update(written, extra=Path(path_str).name[:20])

    summary = erase_batch(
        targets,
        passes=args.passes,
        pattern=args.pattern,
        operator_id=args.operator,
        organization=args.organization,
        signing_key_path=key_path,
        progress_callback=erase_progress_cb,
        generate_certificate=not getattr(args, "no_certificate", False),
    )
    if bar:
        bar.finish()

    print(f"\nFiles Processed: {summary.total_files}")
    print(f"Successful     : {summary.successful_files}")
    print(f"Failed         : {summary.failed_files}")
    print(f"Bytes Sanitized: {summary.total_bytes_processed} bytes")

    if summary.certificate:
        try:
            blk = record_audit_event(summary.certificate, operation_type="FILE_ERASE", private_key=key_path)
            print(f"Audit Ledger   : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
        cert_p.write_text(json.dumps(summary.certificate, indent=2) + "\n")
        print(f"Certificate    : {cert_p}")

        pdf_p = None
        if not getattr(args, "no_pdf", False):
            try:
                from s0_core import pdfgen
                pdf_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.pdf"
                pdfgen.generate_pdf(summary.certificate, pdf_p)
                print(f"PDF Certificate: {pdf_p}")
            except Exception as e:
                print(f"WARNING: PDF generation failed: {e}", file=sys.stderr)

        if getattr(args, "json", False):
            print(json.dumps({
                "status": "success" if summary.failed_files == 0 else "failure",
                "successful_files": summary.successful_files,
                "failed_files": summary.failed_files,
                "bytes_overwritten": summary.bytes_overwritten,
                "certificate": str(cert_p) if summary.certificate else None,
                "pdf": str(pdf_p) if pdf_p else None,
                "cert_uuid": summary.certificate.get("cert_uuid") if summary.certificate else None
            }, indent=2))
    elif not getattr(args, "no_certificate", False):
        print("WARNING: Sanitization completed, but certificate generation failed (see warnings).", file=sys.stderr)

    return 0 if summary.failed_files == 0 else 1


# --------------------------------------------------------------------------- #
# Module 3: File Carving Subcommands
# --------------------------------------------------------------------------- #


def cmd_carve(args) -> int:
    _print_legal_notice()
    print("==> S0 Module 3: Advanced File Carving & Recovery (FAT32 & Signatures)")

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        print(
            "error: no issuer signing key found.\n"
            "S0 requires a valid Ed25519 signing key to issue forensic manifest certificates.\n"
            "Specify --key <path> or pass --no-certificate to explicitly run without compliance certification.",
            file=sys.stderr,
        )
        return 2

    if getattr(args, "no_certificate", False):
        print("WARNING: --no-certificate specified. No forensic recovery manifest will be issued.", file=sys.stderr)

    print(f"Target Media: {args.target}")
    print(f"Output Dir  : {args.out_dir}")

    target_path = Path(args.target)
    target_size = 0
    if target_path.is_block_device():
        try:
            target_size = get_block_device_size(target_path)
        except Exception:
            pass
    elif target_path.is_file():
        target_size = target_path.stat().st_size

    bar = ProgressBar(target_size, operation="s0 carve") if target_size > 0 else None

    def carve_progress_cb(scanned: int, total: int, found: int) -> None:
        if bar:
            bar.update(scanned, extra=f"Found: {found:,}")

    exts = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

    custom_sigs = None
    if getattr(args, "custom_sig", None):
        sig_arg = args.custom_sig.strip()
        sig_path = Path(sig_arg)
        try:
            if sig_path.exists():
                raw_data = json.loads(sig_path.read_text(encoding="utf-8"))
            else:
                raw_data = json.loads(sig_arg)
            if isinstance(raw_data, dict):
                raw_data = [raw_data]
            custom_sigs = [signature_from_dict(d) for d in raw_data]
            print(f"Loaded {len(custom_sigs)} custom forensic signature(s): {', '.join(s.name for s in custom_sigs)}")
        except Exception as err:
            print(f"error: failed to parse custom signatures from '{args.custom_sig}': {err}", file=sys.stderr)
            return 2

    summary = carve_image(
        args.target,
        args.out_dir,
        extensions=exts,
        custom_signatures=custom_sigs,
        min_confidence=args.min_confidence,
        operator_id=args.operator,
        organization=args.organization,
        signing_key_path=key_path,
        progress_callback=carve_progress_cb,
        generate_certificate=not getattr(args, "no_certificate", False),
    )
    if bar:
        bar.finish(extra=f"Found: {summary.files_recovered:,}")

    print(f"\nBytes Scanned  : {summary.total_bytes_scanned}")
    print(f"Candidates Found: {summary.total_candidates_found}")
    print(f"Files Recovered : {summary.files_recovered}")

    if summary.carved_files:
        print(f"\n{'ID':<14} {'EXT':<6} {'SIZE':>10}  {'CONF':>6}  {'SHA256 (PREFIX)':<20} FILENAME")
        for c in summary.carved_files[:20]:
            print(
                f"{c.file_id:<14} {c.extension:<6} {c.size_bytes:>10}  {c.confidence_score:>5}%  {c.sha256[:16]:<20} {c.filename}"
            )
        if len(summary.carved_files) > 20:
            print(f"... and {len(summary.carved_files) - 20} more files (see recovery_index.json).")

    idx_file = Path(args.out_dir) / "recovery_index.json"
    if idx_file.exists():
        print(f"Recovery Index File       : {idx_file}")

    if summary.manifest_certificate:
        try:
            blk = record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key_path)
            print(f"Audit Ledger              : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        cert_p = (
            out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
        )
        cert_p.write_text(json.dumps(summary.manifest_certificate, indent=2) + "\n")
        print(f"\nForensic Recovery Manifest: {cert_p}")

    return 0


# --------------------------------------------------------------------------- #
# Module 4: Blockchain Audit Ledger Subcommands
# --------------------------------------------------------------------------- #


def cmd_audit(args) -> int:
    if args.audit_action == "list":
        blocks = list_audit_blocks(limit=args.limit)
        print(f"==> S0 Blockchain Cryptographic Audit Ledger ({len(blocks)} blocks)")
        print(
            f"{'IDX':<5} {'TIMESTAMP':<20} {'OPERATION':<14} {'OPERATOR':<14} {'TARGET_ID':<20} {'BLOCK_HASH':<16}"
        )
        for b in blocks:
            print(
                f"{b.block_index:<5} {b.timestamp[:19]:<20} {b.operation_type:<14} {b.operator_id:<14} {b.target_id[:20]:<20} {b.block_hash[:16]}..."
            )
        return 0

    elif args.audit_action == "verify":
        print("==> Auditing Blockchain Cryptographic Hash Chain...")
        trusted_keys = None
        if getattr(args, "key", None):
            from s0_core.crypto import load_public_pem
            trusted_keys = [load_public_pem(args.key)]
        report = verify_audit_ledger(trusted_public_keys=trusted_keys)
        print(f"Chain Status : {'✅ VALID & CONTINUOUS' if report.is_valid else '❌ BROKEN / TAMPER DETECTED'}")
        print(f"Blocks Tested: {report.total_blocks_verified}")
        print(f"Details      : {report.reason}")
        return 0 if report.is_valid else 1

    return 0


# --------------------------------------------------------------------------- #
# Module 5: Offline Verification & Key Generation
# --------------------------------------------------------------------------- #


def cmd_verify(args) -> int:
    cert_path = Path(args.certificate)
    if not cert_path.is_file():
        print(f"error: certificate file {args.certificate} does not exist", file=sys.stderr)
        return 2

    try:
        cert_data = json.loads(cert_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"error: invalid certificate JSON: {exc}", file=sys.stderr)
        return 2

    pub_keys = []
    if args.key:
        p = Path(args.key)
        if not p.is_file():
            print(f"error: public key file {args.key} does not exist", file=sys.stderr)
            return 2
        from s0_core.crypto import load_public_pem
        pub_keys.append(load_public_pem(p))
    else:
        demo_pub = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem"
        if demo_pub.is_file():
            from s0_core.crypto import load_public_pem
            pub_keys.append(load_public_pem(demo_pub))

    from s0_core.certificate import verify_certificate
    ok, reason = verify_certificate(cert_data, pub_keys)
    if ok:
        print("✅ CERTIFICATE AUTHENTIC & VERIFIED")
        print(f"UUID         : {cert_data.get('cert_uuid')}")
        print(f"Status       : {cert_data.get('result', {}).get('status')}")
        print(f"NIST Tier    : {cert_data.get('wipe', {}).get('nist_category')}")
        print(f"Device       : {cert_data.get('device', {}).get('device_id')}")
        print(f"Issuer       : {cert_data.get('issuer', {}).get('organization')}")
        print(f"Fingerprint  : {cert_data.get('signature', {}).get('public_key_fingerprint')}")
        return 0
    else:
        print(f"❌ CERTIFICATE VERIFICATION FAILED: {reason}", file=sys.stderr)
        return 1


def cmd_keygen(args) -> int:
    from s0_core import crypto
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = crypto.generate_private_key()
    pub = priv.public_key()
    priv_p = out_dir / f"{args.name}_private.pem"
    pub_p = out_dir / f"{args.name}_public.pem"
    crypto.write_private_pem(priv, priv_p)
    crypto.write_public_pem(pub, pub_p)
    fp = crypto.public_key_fingerprint(pub)
    print("Generated Ed25519 Keypair:")
    print(f"  Private Key : {priv_p} (Keep secret & offline!)")
    print(f"  Public Key  : {pub_p}")
    print(f"  Fingerprint : {fp}")
    return 0


# --------------------------------------------------------------------------- #
# Module 6: Web Dashboard Launcher
# --------------------------------------------------------------------------- #


def cmd_web(args) -> int:
    """Launch the s0 local Web Dashboard in browser."""
    import webbrowser
    import threading

    port = getattr(args, "port", 8000)
    host = getattr(args, "host", "127.0.0.1")
    url = f"http://{host}:{port}"

    deps_missing = []
    try:
        import fastapi  # noqa: F401
    except ImportError:
        deps_missing.append("fastapi")
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        deps_missing.append("uvicorn")

    if deps_missing:
        print(f"\n[s0 web] Missing required web dashboard dependencies: {', '.join(deps_missing)}", file=sys.stderr)
        print(f"Please install via: pip install {' '.join(deps_missing)}", file=sys.stderr)
        return 1

    possible_roots = [
        Path(__file__).resolve().parents[3],
        Path.home() / ".s0",
    ]
    web_dir = None
    for root in possible_roots:
        cand_web = root / "web"
        if cand_web.is_dir() and (cand_web / "app.py").is_file():
            web_dir = cand_web
            break

    if not web_dir:
        print("❌ Error: Could not locate s0 Web Dashboard files (app.py).", file=sys.stderr)
        return 1

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║      S0 (Sector Zero) — Unified Web Forensics Dashboard         ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"[*] Address : {url}")
    print(f"[*] Binding : {host} (Strict loopback isolation)")
    print(f"[*] Status  : Live — Press CTRL+C to stop")
    print()

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app:app",
        "--host",
        host,
        "--port",
        str(port),
    ]

    proc = subprocess.Popen(cmd, cwd=str(web_dir))

    if not getattr(args, "no_browser", False):
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[s0 web] Stopping web dashboard...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[s0 web] Server terminated.")

    return 0


# --------------------------------------------------------------------------- #
# CLI Parser Setup
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="s0",
        description="S0 (Sector Zero) — Unified Forensic Sanitization & Recovery CLI",
        epilog="⚖ LEGAL: Only operate on storage media you own or have explicit written authorization to process.",
    )
    p.add_argument("--version", action="version", version=f"s0 {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # 1. Drive Eraser Subcommands
    lst = sub.add_parser("list", help="list block-device wipe targets")
    lst.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    lst.set_defaults(func=cmd_list)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--version", action="version", version=f"s0 {__version__}")
    common.add_argument("--target", required=True, help="block device path OR image file path")
    common.add_argument(
        "--passes",
        "-p",
        type=int,
        default=1,
        help="overwrite passes (default 1 — one pass IS Clear per NIST 800-88)",
    )
    common.add_argument(
        "--pattern",
        choices=["zero", "random"],
        default="zero",
        help="overwrite pattern: 'zero' (single/multi-pass zeros) or 'random' (CSPRNG bytes)",
    )
    common.add_argument(
        "--no-firmware",
        action="store_true",
        help="skip firmware methods (ATA SE/NVMe sanitize); overwrite only",
    )
    common.add_argument(
        "--discard-purge-justification",
        metavar="TEXT",
        help="record drive-spec deterministic-TRIM evidence to let BLKDISCARD claim Purge",
    )
    common.add_argument(
        "--force", action="store_true", help="override mounted/root safety refusals"
    )

    pln = sub.add_parser("plan", parents=[common], help="dry-run: show what would happen")
    pln.set_defaults(func=cmd_plan)

    wp = sub.add_parser("wipe", parents=[common], help="wipe target, verify, issue signed certificate")
    wp.add_argument("--yes", "-y", action="store_true", help="skip interactive WIPE prompt")
    wp.add_argument("--key", "--signing-key", help="issuer private key PEM (default: demo issuer key)")
    wp.add_argument("--out-dir", default=".", help="directory to store certificate and PDF assets (default: .)")
    wp.add_argument("--operator", "--operator-id", default=DEFAULT_OPERATOR, help="operator identifier for certificate")
    wp.add_argument("--organization", default=DEFAULT_ORGANIZATION, help="organization name for certificate")
    wp.add_argument("--no-pdf", action="store_true", help="skip generating human-readable PDF compliance certificate")
    wp.add_argument("--verify-samples", type=int, default=64, help="number of readback samples to verify (default: 64)")
    wp.add_argument(
        "--plant-markers",
        action="store_true",
        help="plant recoverable markers first, then require 0 grep hits afterwards",
    )
    wp.add_argument("--json", action="store_true", help="machine-readable stdout")
    wp.set_defaults(func=cmd_wipe)

    # 2. File & Folder Eraser Subcommand (erase & erase-files alias)
    for fe_cmd in ("erase", "erase-files"):
        fe = sub.add_parser(fe_cmd, help="securely erase files and folders with metadata cleansing")
        fe.add_argument("--targets", "-t", nargs="+", required=True, help="paths to files or directories to sanitize")
        fe.add_argument("--passes", "-p", type=int, default=1, help="number of overwrite passes")
        fe.add_argument("--pattern", choices=["zero", "random"], default="zero", help="overwrite pattern: 'zero' or 'random'")
        fe.add_argument("--out-dir", default=".", help="directory to store certificate and PDF assets (default: .)")
        fe.add_argument("--operator", "--operator-id", default=DEFAULT_OPERATOR, help="operator identifier for certificate")
        fe.add_argument("--organization", default=DEFAULT_ORGANIZATION, help="organization name for certificate")
        fe.add_argument("--key", "--signing-key", help="signing key path (default: demo issuer key)")
        fe.add_argument(
            "--no-certificate",
            action="store_true",
            help="explicitly run without generating an Ed25519 compliance certificate",
        )
        fe.add_argument("--no-pdf", action="store_true", help="skip rendering PDF certificate")
        fe.add_argument("--json", action="store_true", help="output result as machine-readable JSON")
        fe.add_argument(
            "--verify-samples",
            type=int,
            default=64,
            help="number of readback samples for verification (default: 64)",
        )
        fe.set_defaults(func=cmd_erase_files)

    # 3. File Carving & Recovery Subcommand
    crv = sub.add_parser("carve", help="advanced file carving and recovery from raw images / media (FAT32 & Signatures)")
    crv.add_argument("--target", required=True, help="raw disk image or block device to scan")
    crv.add_argument("--out-dir", required=True, help="directory to store carved files")
    crv.add_argument("--extensions", help="comma-separated file extensions to carve (e.g. jpg,png,pdf,zip)")
    crv.add_argument(
        "--custom-sig",
        help="path to JSON file (or inline JSON) defining custom file signature(s) with header/footer hex magic bytes",
    )
    crv.add_argument("--min-confidence", type=int, default=50, help="minimum confidence score (0-100)")
    crv.add_argument("--operator", "--operator-id", default=DEFAULT_OPERATOR, help="operator identifier for manifest")
    crv.add_argument("--organization", default=DEFAULT_ORGANIZATION, help="organization name for manifest")
    crv.add_argument("--key", "--signing-key", help="signing key path (default: demo issuer key)")
    crv.add_argument(
        "--no-certificate",
        action="store_true",
        help="explicitly run without generating an Ed25519 forensic manifest certificate",
    )
    crv.set_defaults(func=cmd_carve)

    # 4. Blockchain Audit Ledger Subcommand
    aud = sub.add_parser("audit", help="cryptographic audit ledger and blockchain continuity management")
    aud.add_argument("audit_action", choices=["list", "verify"], help="list audit blocks or verify hash chain")
    aud.add_argument("--limit", type=int, default=50, help="limit number of records displayed")
    aud.add_argument("--key", help="path to trusted public key PEM for strict signature verification")
    aud.set_defaults(func=cmd_audit)

    # 5. Offline Verification Subcommand
    vr = sub.add_parser("verify", help="verify a signed certificate offline against trusted public keys")
    vr.add_argument("certificate", help="path to certificate JSON")
    vr.add_argument("--key", help="path to trusted public key PEM")
    vr.set_defaults(func=cmd_verify)

    # 6. Key Generation Subcommand
    kg = sub.add_parser("keygen", help="generate Ed25519 signing keypair for an authority or operator")
    kg.add_argument("--out-dir", default=".", help="directory to store private and public keys")
    kg.add_argument("--name", default="operator_key", help="key filename prefix")
    kg.set_defaults(func=cmd_keygen)

    # 7. Web Dashboard Subcommand
    wb = sub.add_parser("web", help="launch local s0 Web Dashboard in browser (FastAPI loopback)")
    wb.add_argument("--port", type=int, default=8000, help="port to bind (default: 8000)")
    wb.add_argument("--host", default="127.0.0.1", help="host to bind (default: 127.0.0.1 loopback)")
    wb.add_argument("--no-browser", action="store_true", help="start web server without opening browser")
    wb.set_defaults(func=cmd_web)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
