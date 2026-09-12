# Filesystem Roadmap

Forensis is designed so that each filesystem is an additive producer of
the same [forensic model](forensic-model.md). This page states what
is supported today and what comes next.

## Detector support

`FileSystemDetector` recognizes the signatures of eight filesystems,
but `is_supported()` gates which ones can actually be investigated:

| Filesystem | Detected | Investigated |
| --- | --- | --- |
| NTFS | yes | **yes (today)** |
| EXT4 | yes | no — parsers exist, not wired |
| FAT32 | yes | no — empty module |
| exFAT | yes | no — empty module |
| XFS | yes | no |
| BTRFS | yes | no |
| HFS+ | yes | no |
| APFS | yes | no |
| EXT3 | not detected yet | no |

## NTFS — done

Investigation and recovery are implemented and validated against real
(also fragmented and reused) forensic images. See the
[NTFS implementation notes](ntfs/implementation.md) for the exact scope,
including known gaps (MFT mirror, timestamps in the model, large
directories, `$Bitmap` cross-checking).

## Next: EXT4

The `crates/forensis-core/src/filesystem/ext4/` tree already contains
substantial parser scaffolding that is not yet reachable:

- superblock;
- block groups, block group descriptor/table;
- inode, inode table, inode locator, inode bitmap, block bitmap;
- extents;
- directories;
- journal.

The work is to connect these parsers to the investigation pipeline and
emit the forensic model: inode numbers become `object_id`es, directory
entries provide `parent_id`, extents provide physical locations, and
the block bitmap gives the same allocated-vs-free signal used to detect
deleted objects. This is the natural second filesystem because it answers
the same six questions as NTFS with different structures.

## Later: FAT32, exFAT, EXT3

- `fat32/mod.rs` and `exfat/mod.rs` are currently near-empty modules.
- EXT3 detection and parsing inherit most of the EXT4 machinery and can
  reuse its inode/journal code as a starting point.

## The six questions

Every filesystem implementation must answer the same questions that
[the NTFS study](ntfs/guide.md) answers:

| Question | NTFS | EXT4 | FAT32 | exFAT |
| --- | --- | --- | --- | --- |
| Where is the metadata? | MFT | inode tables per block group | reserved FAT region / directory entries | FAT + directory entry chains |
| How is a file identified? | MFT record | inode number | first cluster + directory entry | directory entry |
| How does the system find its data? | data runs | extents / block maps | cluster chain | cluster chain |
| How are directories organized? | B-tree indexes (`INDEX_ROOT`/`INDEX_ALLOCATION`) | directory inode + htree | linked directory entries | linked directory entries |
| How is space controlled? | `$Bitmap` | block and inode bitmaps | FAT table | FAT table |
| How do modification/recovery work? | `$LogFile` | journal | no journal | no journal |

## Non-filesystem roadmap items

These architectural items affect all filesystems and are tracked
alongside the per-filesystem work:

- honor the sector size from the device/partition instead of assuming
  512 bytes;
- surface NTFS (and future) timestamps into `ForensicMetadata`;
- wire the existing metadata parsers (`$Bitmap`, `$UpCase`, `$Secure`,
  `$BadClus`, `$LogFile`, `$AttrDef`, `INDEX_ALLOCATION`) into the
  investigation pipeline;
- read and cross-validate the MFT mirror;
- make `recover all` richer than an alias of `recover deleted`
  (carving, hash/entropy-based carving);
- stream recovery instead of accumulating in memory;
- clean up superseded abstractions (`DiskReader`, `Disk`/`DiskKind`).