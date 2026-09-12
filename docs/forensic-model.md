# The Forensic Model

The forensic model is Forensis' filesystem-independent representation of
an investigated volume. Filesystem parsers (today, NTFS) translate their
internal structures into this model; recovery, the CLI and the TUI
consume it without any knowledge of the filesystem that produced it.

```text
               NTFS
                 |
                 v
         Investigation
                 |
                 v
        +------------------+
        |  ForensicModel   |
        |------------------|
        |  source          |
        |  records_...     |
        |  entries: [...]  |
        +------------------+
              |
              +--> ForensicEntry
              +--> ForensicTree
```

## `ForensicModel`

The result of an investigation:

- `source: ForensicSource` — the image path and the detected filesystem.
- `records_investigated: u64` — how many records the parser processed
  (for NTFS, the number of MFT records actually read).
- `entries: Vec<ForensicEntry>` — every discovered object.

The model answers identity questions: *"which objects exist?"*, *"which
files were present?"* and *"where were their data located?"*.

## `ForensicEntry`

Each entry is one forensic finding grouped by meaning rather than by
parser internals. The groups mirror the questions a forensic analysis
asks:

| Component | Answers |
| --- | --- |
| `identity` | Name, path, kind, status, `object_id`. |
| `hierarchy` | `parent_id` — the parent directory's `object_id`. |
| `metadata` | Real size and allocated size. |
| `filesystem` | Which filesystem and the native object id (NTFS MFT record). |
| `allocation` | Allocated? Cluster count. |
| `physical_location` | The raw disk regions where the object's data lives. |
| `content_layout` | The object's content in logical order, including sparse and inline parts. |

The `object_id` is how interfaces reference an object: the NTFS module
uses the MFT record number as the `object_id`, and the parent
relationship is expressed through `parent_id`.

### `ForensicStatus`

```text
Normal  System  Deleted  Carved  Inconsistent  Unknown
```

The NTFS module currently emits only three of them:

- `Normal` — allocated filesystem object (record in use, not a system
  file);
- `System` — NTFS metadata files (record flagged
  `FILE_ATTRIBUTE_SYSTEM`);
- `Deleted` — the MFT record is no longer marked in use, but its
  `FILE_NAME` and `$DATA` attributes are still physically present.

`Carved`, `Inconsistent` and `Unknown` are reserved for future use
(carving, validation and partial parsing).

### `ForensicEntryKind`

```text
File  Directory  Symlink  Other
```

The NTFS module produces `File` and `Directory`. Symlinks/other kinds
are future work.

### `ForensicAllocation`

- `allocated` — the object is allocated on the filesystem (for NTFS,
  the MFT `record in use` flag);
- `cluster_count` — number of clusters gathered from the data runs;
- `bitmap_allocated` — reserved for cross-checking against the volume
  bitmap (currently always `None` for NTFS).

### `ForensicPhysicalLocation`

A list of `ForensicPhysicalRegion`:

```text
cluster_start  sector_start  offset
cluster_end    sector_end
```

Each region is the physical footprint of one contiguous data run:
logical cluster numbers mapped to absolute disk sectors. Sparse runs are
deliberately excluded. This is the information an investigator needs to
answer *"where on disk did this object live?"*.

### `ForensicContentLayout`

The recovery-oriented view of the same object. It keeps `bytes_per_cluster`
and a list of `ForensicContentSegment` in **logical order**:

- `Inline(Vec<u8>)` — resident file content embedded in the metadata
  record (e.g. a small file stored inside its NTFS MFT record);
- `Physical(ForensicPhysicalRegion)` — non-resident data mapped to disk
  regions;
- `Sparse` — a logical run with no physical backing (a hole that reads
  as zeroes).

Because the layout is logical, recovery can reconstruct a fragmented,
sparse or partially-resident object exactly: read each `Physical`
segment from the image, zero-fill `Sparse` segments, and use `Inline`
bytes verbatim. See [recovery.md](recovery.md).

## `ForensicTree`

`ForensicTree` turns the flat list of entries into a navigable
hierarchy built purely from `parent_id`/`object_id`. A node is a root
when it has no parent, is its own parent, or its parent was not
discovered — a situation that genuinely occurs in partial
investigations. Only directory entries are expanded with children.

## Filesystem-independence

Every parser that wants to feed the model must produce `ForensicEntry`
data and nothing else. This boundary is what makes a future ext4,
FAT32 or exFAT implementation a purely additive change: write a parser,
emit the same model, and recovery plus both interfaces work unchanged.

Source files:

- `crates/forensis-core/src/forensic/model.rs`
- `crates/forensis-core/src/forensic/tree.rs`
- `crates/forensis-core/src/forensic/mod.rs`