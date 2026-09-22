# Prototype Limitations & Scope

This document details the deliberate engineering constraints, boundaries, and limitations of this prototype workstation.

---

## 1. Operating System & Platform Boundary
- **Linux Only**: The prototype is built and tested exclusively on Linux (kernel 5.15+ on Ubuntu/Debian).
- Native Windows (`win32`) and macOS (`darwin`) device access layers, volume locking, and OS-specific filesystems (such as APFS, ReFS, or Windows Volume Shadow Copies) are not implemented in this prototype.

## 2. Storage Media & Sanitization Methods
- **Host Overwrite (NIST Clear)**: Single-pass and multi-pass cryptographic zero/random overwriting with POSIX `fsync` flush guarantees.
- **Firmware Commands (NIST Purge)**: Direct ATA Secure Erase (`hdparm`) and NVMe Format/Sanitize (`nvme-cli`) dispatch are supported on Linux block devices when appropriate hardware and kernel capabilities are present. Remapped, damaged, or inaccessible spare blocks cannot be verified via user-space readback if the drive controller firmware does not implement standardized Purge feedback.
- **TRIM / Deallocate**: `blkdiscard` is supported on SSD targets; it claims Purge only if deterministic readback behavior is verified.

## 3. Forensic File Carving & Recovery
- **Target Filesystem**: Structure-aware parsing is implemented specifically for **FAT32** (the predominant filesystem for USB flash drives, memory cards, and portable media). Filesystem-specific parsing for NTFS (MFT records), ext4 (extent trees), and exFAT is omitted in this prototype.
- **File Types**: Signature-based raw carving supports 8 common evidence file formats:
  - Documents: PDF (`%PDF-`), ZIP / DOCX / Office Open XML (`PK\x03\x04`)
  - Images: JPEG (`\xFF\xD8\xFF`), PNG (`\x89PNG`), GIF (`GIF87a`/`GIF89a`), BMP (`BM`)
  - Media: MP4 (`ftyp`), WAV (`RIFF....WAVE`)
- **Fragmentation**: Reassembly handles contiguous files, multi-cluster FAT directory runs, and bifragment cluster-gap heuristic reassembly. Complex multi-fragment interleaving across heavily fragmented disks is outside the scope of this prototype.

## 4. Cryptographic Certification & Auditing
- **Ed25519 Signing**: All sanitization operations and carving sessions generate deterministic certificates adhering to s0 Canonical JSON (RFC 8785) signed with pure Ed25519 (RFC 8032).
- **Certificate Formats**: Outputs include Canonical JSON and human-readable PDF reports. QR-code optical barcode generation is omitted in favor of direct digital JSON verification.
- **Audit Ledger**: Implemented via a local SQLite-backed cryptographic hash chain with continuous SHA-256 block linking. Distributed consensus (multi-node P2P validation) is not included.

## 5. Web Interface & Deployment
- **Local Workstation**: The FastAPI web dashboard runs strictly in localhost loopback mode (`127.0.0.1:8000`).
- **No Multi-User Authentication**: Prototype web dashboard does not implement multi-tenant role-based access control (RBAC) or persistent session databases.
- **Bootable Media**: Live ISO generator and USB flashing utilities are not included in this repository.
