# Changelog

All notable changes to Forensis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

_Nothing yet._

## [0.2.0] - 2026-09-12

### Added

- **Full FAT32 support**: boot sector (BPB) parsing, FAT location, data
  clusters and directory parsing (8.3 entries + **LFN** with full long names
  in UTF-16).
- **Forensic inspection**: `ForensicModel` for FAT32 — live files, deleted
  files (marked `0xE5`), the volume label as a system entry and names
  reconstructed from residual LFN.
- **Deleted file recovery**: rebuilds the **residual FAT chain** from erased
  clusters, with physical runs mapped sector by sector — even when the
  volume's original FAT has already been zeroed.
- Full integration with the **detector, inspection, CLI and TUI**, following
  the same pattern already in place for NTFS and ext4.

### Fixed

- **Critical FAT32 BPB offset bug**: the boot sector was read 4 bytes off
  (FAT size, root cluster and filesystem type), causing the geometry to
  diverge from reality. It now uses the official spec offsets.
- **CLI `recover deleted --output`**: the `--output` directory was printed but
  ignored — files were written to a fixed directory. The parameter is now
  honored.

### Validated against a real image

- `disk-fat32.img` fixture (64 MiB) created with `mkfs.fat` + mtools; residual
  FAT chain rebuilt to simulate the real forensic scenario.
- `disk-mbr.img` variant with an FAT32 partition (`0x0C`, LBA 2048).
- Recovery validated against the originals by SHA-256 (identical), via the CLI
  and integration tests.

### Testing and quality

- +30 FAT32 unit tests; 3 integration tests against real images (full FAT32,
  MBR partition and NTFS).
- Baseline: 48 green suites, `clippy -D warnings` clean, `fmt` and man page ok.

### Documentation

- Updated man page (.TH 0.2.0), filesystem roadmap, validation fixture
  procedure and architecture (extension pattern: detector → separate crates
  per fs → CLI/TUI).

### CI/CD

- GitHub Actions workflows: **CI** (fmt, clippy, tests) and **Release**
  (linux/macOS/windows builds + `.tar.gz`/`.zip` packages + auto-release).

## [0.1.0] - 2026-09-12

### Added

- **ext4 support**: superblock, block groups and descriptor table, inode
  location, inode table, bitmaps, extents, directories and journal — wired
  into the investigation pipeline and emitting the `ForensicModel`.
- **NTFS support** (first version): forensic analysis via the MFT (records
  investigated, entries discovered, physical allocation).
- **Forensic model**: a filesystem-independent representation expressed as a
  tree (objects, status, physical allocation).
- **Recovery engine**: recovery of deleted objects with SHA-256 integrity
  comparison between the original and the recovered file.
- **CLI and TUI interfaces** sharing a common application layer.
- Automatic discovery of evidence sources (block devices, partitions, disk
  images) with an interactive picker.
- Technical documentation (architecture, forensic model, recovery, NTFS
  study), man page and integration tests against real images.

## [0.0.1] - 2026-08-30

### Added

- Initial release: workspace structure (core, app, CLI and TUI crates), raw
  access to block devices/partitions/images and a filesystem signature
  detector (NTFS, ext4, FAT32, exFAT, XFS, btrfs, HFS+ and APFS).
