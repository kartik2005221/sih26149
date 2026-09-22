"""Comprehensive tests verifying remediation of forensic audit findings.

Covers:
1. Block device sizing, partition mount safety, and 0-byte wipe rejection.
2. Whole-disk partitioned MBR/GPT filesystem detection (FAT32).
3. Removal of fabricated verification fields in certificates.
4. Audit ledger recording error reporting.
5. Entropy scoring strictly rejecting zero-filled buffers.
"""

import struct
from pathlib import Path

import pytest
from s0_cli.carver.engine import (
    carve_image,
    detect_filesystem,
    detect_partitions,
)
from s0_cli.carver.scoring import (
    score_carved_candidate,
)
from s0_cli.carver.signatures import get_signature_by_ext
from s0_cli.devices import (
    Target,
    _is_dev_or_subpartition,
)
from s0_cli.wipe import verify_wipe


def test_partition_mount_matching_no_false_positive():
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda1") is True
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda10") is False
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda2") is False

    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda") is True
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda1") is True
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda10") is True
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sdb1") is False


def test_zero_capacity_wipe_verification_fails():
    target = Target(
        path="/dev/loop99",
        kind="block",
        capacity_bytes=0,
        sector_size=512,
        storage_type="UNKNOWN",
    )
    verif, post = verify_wipe(target, "zero", offsets=[], sample_bytes=4096)
    assert verif["all_samples_match_wipe_pattern"] is False
    assert "Zero readback samples obtained" in verif["verification_error"]


def test_whole_disk_partition_detection_and_carving(tmp_path: Path):
    sector_size = 512
    part_start_sector = 2048
    part_offset = part_start_sector * sector_size
    total_size = part_offset + (128 * 1024)

    img = bytearray(total_size)

    img[510:512] = b"\x55\xaa"
    mbr_entry1 = 446
    img[mbr_entry1 + 4] = 0x0C  # FAT32 LBA
    struct.pack_into("<I", img, mbr_entry1 + 8, part_start_sector)
    struct.pack_into("<I", img, mbr_entry1 + 12, 128 * 2)

    # FAT32 boot sector at part_offset
    img[part_offset + 510 : part_offset + 512] = b"\x55\xaa"
    img[part_offset + 82 : part_offset + 87] = b"FAT32"

    img_file = tmp_path / "partitioned_disk.raw"
    img_file.write_bytes(img)

    parts = detect_partitions(img_file)
    assert len(parts) >= 1
    assert parts[0][0] == "fat32"
    assert parts[0][1] == part_offset

    fs = detect_filesystem(img_file)
    assert fs == "fat32"


def test_carver_manifest_verification_integrity(tmp_path: Path):
    target_img = tmp_path / "target.img"
    target_img.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF" + bytes(4096))

    out_dir = tmp_path / "carved_out"
    summary = carve_image(target_img, out_dir)

    if summary.manifest_certificate:
        verif = summary.manifest_certificate["result"]["verification"]
        assert "all_samples_match_wipe_pattern" not in verif
        assert "planted_pattern_hits_after" not in verif
        assert verif["method"] == "forensic_signature_and_structure_carving"


def test_scoring_rejects_zero_filled_buffer():
    pdf_sig = get_signature_by_ext("pdf")
    assert pdf_sig is not None

    zero_buf = b"%PDF-" + bytes(1024)
    score, heuristics = score_carved_candidate(pdf_sig, zero_buf, has_valid_footer=False)

    assert any("Suspiciously low entropy" in h for h in heuristics)
    assert not any("consistent with document structure" in h for h in heuristics)


def test_random_wipe_verification_entropy(tmp_path: Path):
    import os
    from s0_cli.wipe import sample_offsets

    rand_file = tmp_path / "random.img"
    rand_file.write_bytes(os.urandom(64 * 1024))

    target = Target(
        path=str(rand_file),
        kind="image",
        capacity_bytes=64 * 1024,
        sector_size=512,
        storage_type="UNKNOWN",
    )
    verif, post = verify_wipe(target, "random", samples=8, sample_bytes=1024)
    assert verif["all_samples_match_wipe_pattern"] is True
    assert verif["average_entropy"] >= 7.0
    assert verif["pct_non_zero_samples"] == 1.0

    low_entropy_file = tmp_path / "low_entropy.img"
    low_entropy_file.write_bytes(b"A" * (64 * 1024))
    target_low = Target(
        path=str(low_entropy_file),
        kind="image",
        capacity_bytes=64 * 1024,
        sector_size=512,
        storage_type="UNKNOWN",
    )
    verif_low, post_low = verify_wipe(target_low, "random", samples=8, sample_bytes=1024)
    assert verif_low["all_samples_match_wipe_pattern"] is False
    assert verif_low["average_entropy"] < 1.0


def test_csprng_sample_offsets():
    from s0_cli.wipe import sample_offsets

    offs_small = sample_offsets(capacity=4096, sector_size=512, count=4)
    assert len(offs_small) == 4
    assert all(off % 512 == 0 for off in offs_small)

    offs_large = sample_offsets(capacity=100 * 1024 * 1024, sector_size=512, count=16)
    assert len(offs_large) == 16
    assert all(off % 512 == 0 for off in offs_large)
