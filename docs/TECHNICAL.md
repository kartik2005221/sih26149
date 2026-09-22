# Technical Specification & Architecture

In-depth technical reference for the s0 forensic data sanitization and file recovery engine.

---

## 1. System Architecture

The workstation is partitioned into modular, decoupled layers:

```
┌────────────────────────────────────────────────────────┐
│                   s0 Web Dashboard                     │
│               (FastAPI / HTML5 Console)                │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                    s0 Linux CLI                        │
│   (Wipe / Erase / Carve / Audit / Keygen / Verify)     │
└─────────────┬───────────────────────────┬──────────────┘
              │                           │
┌─────────────▼─────────────┐ ┌───────────▼──────────────┐
│       Core Cryptography   │ │    Forensic Engines      │
│  - Ed25519 Signing        │ │  - NIST 800-88 Wiper     │
│  - Canonical JSON RFC8785 │ │  - POSIX File Eraser     │
│  - SHA-256 Audit Chain    │ │  - FAT32 Parser          │
│  - ReportLab PDF Engine   │ │  - Signature Carver      │
└───────────────────────────┘ └──────────────────────────┘
```

---

## 2. Cryptographic Integrity & Canonical JSON

To guarantee that certificates are byte-level deterministic across different platforms, architectures, and programming languages, s0 implements **Canonical JSON v1** (`core/CANONICAL_JSON.md`, conforming to RFC 8785 principles):

1. **UTF-8 Encoding**: Deterministic byte stream without BOM.
2. **Key Ordering**: Dictionary keys are sorted lexicographically by Unicode code point values.
3. **Whitespace**: Minimal separators (`,` and `:`) without spaces, indentation, or newlines.
4. **Number Formatting**: Strictly integer-only representations. Floating-point numbers are rejected to eliminate cross-architecture float serialization ambiguities.
5. **Signing Payload**: The signature covers all certificate fields excluding the `signature` object itself:
   $$\text{Payload} = \text{Canonicalize}(\text{Certificate} \setminus \{\text{"signature"}\})$$
   $$\text{Signature} = \text{Ed25519\_Sign}(\text{PrivateKey}, \text{Payload})$$

---

## 3. NIST SP 800-88 Rev. 1 Sanitization Compliance

s0 maps sanitization actions directly to NIST SP 800-88 Rev. 1 categories:

| Method ID | NIST Category | Technique | Applicability |
|---|---|---|---|
| `OVERWRITE_ZERO_1PASS` | **Clear** | 1-pass zero overwrite with POSIX `fsync` | HDDs, Virtual Images, Raw partitions |
| `SHRED_RANDOM_NPASS` | **Clear** | N-pass CSPRNG random overwrite | HDDs, Flash devices |
| `BLKDISCARD` | **Clear / Purge** | Kernel ATA/SCSI discard / TRIM | Solid State Drives (with deterministic TRIM) |
| `ATA_SECURE_ERASE` | **Purge** | Firmware controller ATA SECURITY ERASE | SATA HDDs / SSDs |
| `ATA_SECURE_ERASE_ENHANCED` | **Purge** | Firmware controller Enhanced Erase | SATA HDDs / SSDs |
| `NVME_FORMAT_USER_DATA_ERASE`| **Purge** | NVMe low-level user data erase | NVMe SSDs |
| `NVME_SANITIZE_BLOCK_ERASE` | **Purge** | NVMe controller block erase sanitize | NVMe SSDs |
| `NVME_SANITIZE_CRYPTO_ERASE` | **Purge** | NVMe internal media encryption key destruction | NVMe SSDs (Self-Encrypting) |

### Post-Wipe Verification
Every sanitization operation runs sampled readback verification across uniformly distributed sector offsets:
- Verifies that sampled blocks match the expected pattern (e.g., all zeroes).
- If markers were planted prior to wiping (`--plant-markers`), asserts zero instances remain.

---

## 4. FAT32 Structure-Aware Carving Engine

Unlike pure blind byte carving, s0's filesystem-aware recovery inspects disk structures:

1. **BPB Boot Sector Parsing**: Reads sector size, sectors per cluster, reserved sectors, number of FATs, and root cluster index.
2. **Root Directory Traversal**: Scans 32-byte directory entries for deleted entries marked with `0xE5` in the first byte.
3. **Cluster Allocation Extraction**:
   - Reconstructs the first cluster from directory entry bytes 20-21 (high 16 bits) and 26-27 (low 16 bits).
   - Reads exact file size from entry bytes 28-31.
4. **Data Stream Acquisition**: Traverses contiguous and fragmented cluster allocations to extract the unallocated payload.

---

## 5. Shannon Entropy Confidence Scoring

Raw signature carving candidates are evaluated with Shannon entropy ($H$):

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the frequency of byte value $x_i \in [0, 255]$.
- **Zero/Sparse Padding**: $H \approx 0.0$ (Penalized, false-positive rejection).
- **Text & Uncompressed Documents**: $H \approx 3.5 - 5.5$ (Expected for code, text, XML).
- **Compressed & Encrypted Media (JPEG, PNG, ZIP)**: $H \approx 7.0 - 7.9$ (Expected for valid payloads).
- Candidates matching signature headers with valid trailing footers and expected entropy receive high confidence scores ($\ge 75\%$).

---

## 6. Blockchain Audit Ledger Specification

Every sanitization and carving operation is committed to an append-only cryptographic ledger:

```
[Genesis Block #0]
       │
       ▼ (Hash: 1222963588ac...)
[Block #1: DRIVE_ERASE] ─── PrevHash: 1222963588ac...
       │
       ▼ (Hash: 3fade298e449...)
[Block #2: FILE_CARVE]   ─── PrevHash: 3fade298e449...
```

Each block records:
- `block_index`: Sequential integer index.
- `timestamp`: ISO 8601 UTC timestamp.
- `operation_type`: `DRIVE_ERASE`, `FILE_ERASE`, or `FILE_CARVE`.
- `target_id`: Hardware identifier or canonical file path hash.
- `operator_id`: Operator badge / ID.
- `organization`: Issuing authority.
- `cert_uuid`: Unique certificate identifier.
- `payload_hash`: SHA-256 of the sanitized/carved payload.
- `prev_hash`: SHA-256 hash of previous block.
- `block_hash`: SHA-256 computed over all block fields.
