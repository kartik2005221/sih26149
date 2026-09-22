"""Tests for s0 Fragmented File Reconstruction Engine.

Covers:
1. Multi-run cluster reassembly across discontiguous cluster runs.
2. Bifragment / cluster-gap heuristic stream reassembly.
"""

import io
from pathlib import Path

import pytest
from s0_cli.carver.fragmentation import (
    reassemble_cluster_runs,
    reconstruct_bifragment_stream,
)


def test_discontiguous_cluster_run_reconstruction(tmp_path: Path):
    """Test reconstructing a fragmented file across discontiguous cluster runs."""
    cluster_size = 4096
    disk_data = bytearray(64 * cluster_size)

    # 3 fragments across clusters:
    # Run 1: Cluster 5, length 1 cluster (4096 B) -> part1
    # Run 2: Cluster 12, length 1 cluster (4096 B) -> part2
    # Run 3: Cluster 9, length 1 cluster (100 B used) -> part3
    part1 = b"FRAGMENT_PART_1_" * (4096 // 16)
    part2 = b"FRAGMENT_PART_2_" * (4096 // 16)
    part3 = b"FRAGMENT_PART_3_REMAINDER_DATA_100_BYTES"
    expected_full = part1 + part2 + part3

    disk_data[5 * cluster_size : 5 * cluster_size + len(part1)] = part1
    disk_data[12 * cluster_size : 12 * cluster_size + len(part2)] = part2
    disk_data[9 * cluster_size : 9 * cluster_size + len(part3)] = part3

    img_file = tmp_path / "fragmented.raw"
    img_file.write_bytes(disk_data)

    runs = [(5, 1), (12, 1), (9, 1)]
    with open(img_file, "rb") as f:
        stream = reassemble_cluster_runs(runs, disk_file=f, cluster_size=cluster_size, target_size=len(expected_full))

    assert stream.is_fragmented is True
    assert len(stream.fragments) == 3
    assert stream.data == expected_full


def test_bifragment_heuristic_reconstruction(tmp_path: Path):
    """Test heuristic bifragment reconstruction across a cluster gap."""
    head = b"%PDF-1.4\n1 0 obj\n<< /Title (Sensitive Document) >>\nstream\n" + b"A" * 1024
    footer = b"%%EOF"
    tail = b"endstream\nendobj\nxref\n0 2\ntrailer\n<<>>\nstartxref\n1234\n" + footer

    gap = b"\x00" * 8192
    disk = bytearray(head + gap + tail + b"\x00" * 4096)

    img_path = tmp_path / "bifragment.raw"
    img_path.write_bytes(disk)

    with open(img_path, "rb") as f:
        reconstructed = reconstruct_bifragment_stream(
            head_data=head,
            disk_file=f,
            search_start_offset=len(head),
            footer_pattern=footer,
            max_search_bytes=32 * 1024,
        )

    assert reconstructed is not None
    assert reconstructed.is_fragmented is True
    assert len(reconstructed.fragments) == 2
    assert footer in reconstructed.data
