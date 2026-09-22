"""s0 Module 3: Advanced File Carving and Forensic Recovery (FAT32 & Signatures)."""

from .engine import CarvedFile, CarvingSessionSummary, carve_image, detect_filesystem
from .fat_carver import (
    Fat32BootSector,
    FatRecoveredFile,
    parse_fat32_boot_sector,
    scan_fat32_deleted_files,
)
from .fragmentation import reconstruct_bifragment_stream
from .scoring import calculate_shannon_entropy, score_carved_candidate
from .signatures import SIGNATURES, FileSignature, get_signature_by_ext, parse_hex_bytes, signature_from_dict

__all__ = [
    "CarvedFile",
    "CarvingSessionSummary",
    "carve_image",
    "detect_filesystem",
    "calculate_shannon_entropy",
    "score_carved_candidate",
    "SIGNATURES",
    "FileSignature",
    "get_signature_by_ext",
    "parse_hex_bytes",
    "signature_from_dict",
    "Fat32BootSector",
    "FatRecoveredFile",
    "parse_fat32_boot_sector",
    "scan_fat32_deleted_files",
    "reconstruct_bifragment_stream",
]
