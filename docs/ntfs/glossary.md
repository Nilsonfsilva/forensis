# NTFS Glossary

Terms and abbreviations used throughout the NTFS study.

## Allocation

**Cluster** — the filesystem's unit of allocation, one or more sectors.
An allocation map of clusters is how NTFS tracks free and used space.

**Bitmap** — a bit-per-unit map. A set bit means *allocated*, a clear
bit means *free*. NTFS uses `$BITMAP` for cluster allocation and for
large indexes and extended MFT records.

**Run / Data run** — one contiguous physical piece of a non-resident
attribute: a cluster count and a starting LCN (relative to the previous
run). Sparse runs have a count but no location.

**Sparse** — logical content with no physical allocation; reads as
zeroes. Used for partial cluster allocation and holes.

## Structures

**MFT** — *Master File Table*; the central table of records, one per
filesystem object.

**MFT record** — one slot of the MFT. A header plus attributes,
terminated by `0xFFFFFFFF`.

**USA / Update Sequence Array** — the integrity mechanism of records and
`INDX` blocks: the last two bytes of each 512-byte sector store a
sequence number, checked and restored ("fixed up") during parsing.

**INDX** — an index block; the non-resident unit of `$INDEX_ALLOCATION`,
each block carrying its own signature and USA fixup.

**Attribute** — a typed value slot attached to a record (e.g.
`$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`).

**Resident / Non-resident** — resident values are stored inside the
record; non-resident values point to clusters outside it through a
runlist.

**Journal ($LogFile)** — NTFS' transactional log, used to replay or roll
back interrupted metadata operations.

**Security descriptor** — the structure expressing ownership and access
rules (owner, group, DACL/SACL), deduplicated in `$Secure`.

## Units

**Sector** — the device's base unit of storage (assumed 512 bytes
throughout Forensis today).

**LCN** — *logical cluster number*; an absolute cluster position on the
volume, used by runlists.

**FILETIME** — Windows timestamp format: 100-nanosecond ticks since
1601-01-01 UTC.

**UTF-16LE** — the character encoding used for NTFS names; `$UpCase`
serves Unicode-aware case folding.

## Forensic statuses

- **Normal** — live, allocated filesystem object.
- **System** — NTFS metadata file (e.g. `$MFT`, `$Bitmap`).
- **Deleted** — record no longer marked in use, but its attributes are
  still physically present and recoverable.
- **Carved / Inconsistent / Unknown** — reserved for future work
  (carving, validation and partial parsing).