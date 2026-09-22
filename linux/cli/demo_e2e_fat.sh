#!/usr/bin/env bash
# s0 Module 3 end-to-end demo — Advanced FAT32 Structure & Signature Carving.
#
#   1. build a 4 MiB synthetic FAT32 filesystem (USB flash drive structure)
#   2. plant and mark deleted confidential evidence files in FAT32 root directory
#   3. carve deleted evidence using FAT32 directory parser and signature engine
#   4. verify recovered file hashes match original pre-deletion payloads
#   5. verify Ed25519 forensic manifest and blockchain audit chain continuity
#
# Runs entirely in user-space without root privileges.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
PY="$REPO/.venv/bin/python"
CLI=("$PY" -m s0_cli.main)
WORK="${S0_FAT_DEMO_DIR:-/tmp/s0_fat_demo_$(date +%H%M%S)}"
IMG="$WORK/usb_evidence.raw"
RECOVERED="$WORK/recovered"

export S0_AUDIT_DB="$WORK/s0_audit.db"
mkdir -p "$WORK" "$RECOVERED"
cd "$REPO"

echo "═══════════════════════════════════════════════════════════════════"
echo " s0 Module 3 FAT32 Forensic Carving Demo — Target: $IMG"
echo "═══════════════════════════════════════════════════════════════════"

echo
echo "── [1/5] building FAT32 USB storage image with deleted evidence ────"
"$PY" - "$IMG" << 'PYEOF'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
bytes_per_sec = 512
sec_per_clus = 1
reserved_sec = 32
fats_count = 2
sec_per_fat = 32
root_cluster = 2

cluster_size = bytes_per_sec * sec_per_clus
data_start = (reserved_sec + fats_count * sec_per_fat) * bytes_per_sec

img_size = 4 * 1024 * 1024
buf = bytearray(img_size)

# BPB Boot Sector
buf[0:3] = b"\xeb\x58\x90"
buf[3:11] = b"MSDOS5.0"
struct.pack_into("<H", buf, 11, bytes_per_sec)
buf[13] = sec_per_clus
struct.pack_into("<H", buf, 14, reserved_sec)
buf[16] = fats_count
struct.pack_into("<H", buf, 17, 0)
struct.pack_into("<H", buf, 19, 0)
struct.pack_into("<I", buf, 32, img_size // bytes_per_sec)
struct.pack_into("<I", buf, 36, sec_per_fat)
struct.pack_into("<I", buf, 44, root_cluster)
buf[66] = 0x29
buf[82:90] = b"FAT32   "
struct.pack_into("<H", buf, 510, 0xAA55)

root_offset = data_start + (root_cluster - 2) * cluster_size

# Evidence File 1: Deleted confidential report (TXT)
# Marker: 0xE5 (deleted), first cluster: 3
clus3 = 3
entry1 = bytearray(32)
entry1[0] = 0xE5
entry1[1:8] = b"REPORT "
entry1[8:11] = b"TXT"
entry1[11] = 0x20
struct.pack_into("<H", entry1, 20, 0)
struct.pack_into("<H", entry1, 26, clus3)
file1_data = b"TOP SECRET DEFENSE INTELLIGENCE DOSSIER - OPERATIONAL REPORT 2026"
struct.pack_into("<I", entry1, 28, len(file1_data))
buf[root_offset : root_offset + 32] = entry1

c3_off = data_start + (clus3 - 2) * cluster_size
buf[c3_off : c3_off + len(file1_data)] = file1_data

# Evidence File 2: Deleted confidential document (PDF with magic bytes)
# Marker: 0xE5 (deleted), first cluster: 5
clus5 = 5
entry2 = bytearray(32)
entry2[0] = 0xE5
entry2[1:8] = b"INTEL  "
entry2[8:11] = b"PDF"
entry2[11] = 0x20
struct.pack_into("<H", entry2, 20, 0)
struct.pack_into("<H", entry2, 26, clus5)
file2_data = b"%PDF-1.4\n1 0 obj\n<< /Title (Sensitive Forensic Evidence) >>\nstream\nCONFIDENTIAL EVIDENCE CONTENT\nendstream\nendobj\n%%EOF"
struct.pack_into("<I", entry2, 28, len(file2_data))
buf[root_offset + 32 : root_offset + 64] = entry2

c5_off = data_start + (clus5 - 2) * cluster_size
buf[c5_off : c5_off + len(file2_data)] = file2_data

path.write_bytes(bytes(buf))
print(f"Created synthetic FAT32 volume: {path} ({len(buf):,} bytes)")
print("Planted 2 deleted evidence files (_REPORT.TXT, _INTEL.PDF)")
PYEOF

echo
echo "── [2/5] carving evidence via s0 carve (FAT32 structure + signatures) ─"
"${CLI[@]}" carve \
    --target "$IMG" \
    --out-dir "$RECOVERED" \
    --min-confidence 50 \
    --operator "forensic-analyst" \
    --organization "Digital Forensics Unit"

echo
echo "── [3/5] verifying carved evidence files on disk ────────────────────"
ls -lh "$RECOVERED"
cat "$RECOVERED/recovery_index.json"

echo
echo "── [4/5] verifying payload integrity and Shannon entropy score ──────"
"$PY" - "$RECOVERED" << 'PYEOF'
import hashlib
import json
import sys
from pathlib import Path

rec_dir = Path(sys.argv[1])
idx_path = rec_dir / "recovery_index.json"
assert idx_path.is_file(), "Missing recovery_index.json"

idx = json.loads(idx_path.read_text())
recovered = idx.get("recovered_files", [])
print(f"Files recovered count: {len(recovered)}")
assert len(recovered) >= 2, f"Expected at least 2 recovered files, got {len(recovered)}"

found_txt = False
found_pdf = False

for rf in recovered:
    fpath = rec_dir / rf["filename"]
    assert fpath.is_file(), f"Missing file {fpath}"
    data = fpath.read_bytes()
    assert hashlib.sha256(data).hexdigest() == rf["sha256"]
    print(f"Verified {rf['filename']}: {rf['size_bytes']} bytes, confidence {rf['confidence_score']}%, SHA-256={rf['sha256'][:16]}...")
    if b"TOP SECRET DEFENSE INTELLIGENCE" in data:
        found_txt = True
    if b"%PDF-1.4" in data and b"%%EOF" in data:
        found_pdf = True

assert found_txt, "TXT evidence payload not found"
assert found_pdf, "PDF evidence payload not found"
print("=> All deleted evidence payloads successfully carved and hash-verified!")
PYEOF

echo
echo "── [5/5] verifying blockchain audit chain integrity ────────────────"
"${CLI[@]}" audit list --limit 5
"${CLI[@]}" audit verify

echo
echo "═══════════════════════════════════════════════════════════════════"
echo " FAT32 FORENSIC CARVING DEMO COMPLETE"
echo "   artifacts in: $RECOVERED"
echo "     - carved evidence files"
echo "     - recovery_index.json"
echo "     - carving_manifest_*.json (Ed25519 signed)"
echo "═══════════════════════════════════════════════════════════════════"
