# User & Operator Guide

Step-by-step instructions for installing, configuring, and running the s0 forensic data sanitization and file recovery workstation.

---

## 1. System Requirements

- **Operating System**: Linux (Ubuntu 22.04+, Debian 12+, Fedora 38+, or Arch Linux)
- **Python**: Python 3.10 or higher
- **System Tools (Optional, for block device operations)**:
  - `hdparm` (for ATA Secure Erase inspection)
  - `nvme-cli` (for NVMe sanitize operations)
  - `util-linux` (`lsblk`, `losetup`, `fdisk`)

---

## 2. Installation

Clone the repository and install dependencies inside a virtual environment:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and local modules in editable mode
pip install -r requirements.txt
pip install -e core/python
pip install -e linux/cli
```

Verify that the CLI is accessible:
```bash
s0 --version
```

---

## 3. Creating a Safe Test Target (Loop Device)

To test sanitization or carving safely without touching physical hard drives:

```bash
# Create a 256 MiB sparse loop block device for testing
sudo bash scripts/make_loop_target.sh 256
```

Alternatively, you can test directly on raw disk image files without `sudo`.

---

## 4. Module 1: Drive Sanitizer (`s0 wipe`)

### 4.1 Device Inventory
Inspect available block devices and partition tables:
```bash
s0 list
```

### 4.2 Dry-Run Planning
Preview the proposed sanitization method, NIST category, and safety checks without writing anything:
```bash
s0 plan --target /dev/loop0
# Or using a file target:
s0 plan --target /path/to/test.img
```

### 4.3 Drive Sanitization
Sanitize a target drive with post-wipe verification and Ed25519 compliance certification:
```bash
s0 wipe \
  --target /dev/loop0 \
  --pattern zero \
  --passes 1 \
  --operator "op-forensic-01" \
  --organization "Central Forensics Lab" \
  --out-dir ./output
```

**Artifacts Generated**:
- `output/certificate_<uuid>.json` — Cryptographically signed Canonical JSON certificate.
- `output/certificate_<uuid>.pdf` — Human-readable compliance report.

---

## 5. Module 2: File & Folder Eraser (`s0 erase`)

Securely overwrite targeted files or recursive directories with POSIX cache flushing and metadata scrubbing:

```bash
# Erase specific sensitive evidence files
s0 erase --targets confidential_record.docx /tmp/sensitive_dir/ --passes 1 --out-dir ./output

# Overwrite with random bytes
s0 erase --targets evidence.dat --pattern random --passes 3 --out-dir ./output
```

---

## 6. Module 3: Advanced File Carver (`s0 carve`)

Recover deleted files from raw disk images or media using FAT32 directory structure parsing and signature carving:

```bash
# Carve all supported file formats from a FAT32 image or raw drive
s0 carve --target /path/to/evidence.raw --out-dir ./recovered_files

# Filter by file extension
s0 carve --target /dev/sdb1 --extensions pdf,jpg,png --out-dir ./recovered_files

# Adjust minimum confidence threshold (0-100)
s0 carve --target evidence.img --out-dir ./recovered_files --min-confidence 75
```

**Carved Output**:
- `recovered_files/` — Carved files named with file ID, recovery method, and confidence score.
- `recovered_files/recovery_index.json` — Forensic manifest listing all recovered files, offsets, sizes, and SHA-256 hashes.
- `recovered_files/carving_manifest_<uuid>.json` — Ed25519 signed manifest.

---

## 7. Module 4: Blockchain Audit Ledger (`s0 audit`)

Review and cryptographically verify the continuous SHA-256 audit hash chain:

```bash
# List recent audit ledger blocks
s0 audit list --limit 10

# Verify hash chain continuity and Ed25519 signature validity across all blocks
s0 audit verify
```

---

## 8. Module 5: Offline Verification & Key Management

### 8.1 Offline Certificate Verification
Verify any signed wipe or carving certificate against trusted public keys:
```bash
s0 verify output/certificate_0b7f409c.json --key core/keys/demo_issuer_public.pem
```

### 8.2 Operator Key Generation
Generate a dedicated Ed25519 keypair for an authorized operator or lab:
```bash
s0 keygen --out-dir ./my_keys --name lab_authority
```

---

## 9. Web Forensics Dashboard (`s0 web`)

Launch the local web console:

```bash
s0 web --port 8000
```
Then navigate to `http://127.0.0.1:8000` in your web browser.

---

## 10. Automated End-to-End Demonstrations

Run the complete, automated test verification scripts:

```bash
# Module 1 (Sanitization + Verification + Tamper Detection demo)
bash linux/cli/demo_e2e.sh

# Module 3 (FAT32 Deleted Evidence Carving + Hash Check + Audit demo)
bash linux/cli/demo_e2e_fat.sh
```
