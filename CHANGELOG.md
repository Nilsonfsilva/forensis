# Changelog

All notable changes to Forensis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Recovery by status scope**: `RecoveryFilter` (`Deleted`/`Normal`/`All`)
  plus the shared, filter-aware candidate collector
  `collect_recoverable_entries` in `forensis-app`, used by both CLI and TUI.
- **Normal-file recovery**: `recover_normal_files` /
  `recover_normal_files_from_result` and `recover_objects` (by Object ID);
  `recover_all_from_result`. `recover all` now covers Deleted **and** Normal
  objects.
- **CLI `recover` filter surface**: `recover deleted`, `recover normal` and
  `recover all`, each accepting `--object <ID>...` to skip the interactive
  selection and recover specific objects. All subcommands use the same
  `forensis-app` API as the TUI.
- **TUI recovery filter**: press `F` in the recovery view to cycle
  Deleted → Normal → All, re-collecting candidates from the current scope;
  the active filter is shown in the recovery workspace.
- **Progress reporting across the investigation and recovery**
  (the two moments): `ProgressPhase::Recovering` and
  `ProgressUnit::Objects` added to the progress contract.
- **ext4 progress**: root-directory walk reports inodes (indeterminate),
  inode-table scan reports a determinate percentage per block group.
- **exFAT progress**: directory walk reports directory clusters
  (indeterminate).
- **Recovery without re-investigation**: new `recover_deleted_files_from_result`,
  `recover_object_from_result` and `recover_objects_from_result` reuse an
  already-built `InspectionResult`, so recovery is a separate moment from the
  investigation. Recovery progress is reported per object ("i de N").
- **CLI**: `inspect`, `recover deleted` and `recover all` now show live
  investigation progress, and recovery shows per-object progress.
- **TUI**: investigation inside the interactive source/browse selection runs
  in a background thread with shared progress state, shown live in the
  evidence panel; recovery reuses the loaded model (no re-investigation).

### Changed

- FAT32 and exFAT no longer emit a final artificial `current == total` event;
  percentages are only shown when a real denominator exists.

### Fixed

- CLI and TUI recovered each selected object by re-reading the filesystem.
  Both now recover from the already-built forensic model.
- FAT32 reads the whole FAT into a cache (`fat_cache`, capped at 256 MB) in a
  single bulk read instead of issuing one 4-byte syscall per FAT entry; a FAT
  large enough to exceed the cap falls back to per-entry reads. This removes
  the dominant syscall overhead verified on a real 29 GB pendrive during a
  strace run.
- FAT32 directory parsing no longer loops forever when a recycled directory
  cluster carries binary slot data: the 32-byte slot offset is advanced at the
  top of the parse loop before plausibility checks can bail out early.
- FAT32 only follows the recorded chain of a directory after the plausibility
  gate accepts its first cluster (the `.`/`..` self entries that every real
  FAT32 subdirectory carries, live or deleted). Without the gate, one recycled
  cluster whose slot attribute exposed the directory bit made the walk read
  megabytes of leftover file payload. The FAT32 root cluster is exempt because
  it has no `.`/`..` entries.

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
