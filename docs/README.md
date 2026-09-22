# Documentation Index

> **Smart India Hackathon (SIH) — Problem Statement 26149**  
> **Title:** Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization

---

Welcome to the documentation for the s0 (Sector Zero) forensic data erasure and file recovery workstation prototype.

## Documentation Index

1. **[User & Operator Guide](USER_GUIDE.md)**
   - Step-by-step CLI usage, arguments, and workflow instructions.
   - Loop device setup, drive wiping, file erasing, and file carving guides.
   - Web dashboard launch and navigation.

2. **[Technical Architecture & Specification](TECHNICAL.md)**
   - System component diagrams and inter-module communication.
   - Cryptographic specification (Ed25519, Canonical JSON RFC 8785).
   - NIST SP 800-88 Rev. 1 sanitization category mapping.
   - FAT32 directory structure parsing and Shannon entropy scoring algorithms.
   - Blockchain audit ledger hash-chain specification.

3. **[Prototype Scope & Limitations](LIMITATIONS.md)**
   - Transparent engineering boundaries, hardware requirements, and filesystem support scope.
   - Honest evaluation of prototype capabilities versus future production expansion.

---

## Online Verification
Issued certificates can be verified independently using the live web verifier:
- **Verification Portal**: [https://s0-vp.vercel.app/](https://s0-vp.vercel.app/)
- **Offline CLI Verification**: `s0 verify <cert.json> --key core/keys/demo_issuer_public.pem`
