# How Forensis Reads an NTFS Volume

This page documents the real, end-to-end implementation of NTFS in
`crates/forensis-core/src/filesystem/ntfs/`. The [guide](guide.md)
explains the concepts; this page explains which concepts are actually
connected to the investigation pipeline, in what order, and what is
still missing.

## The pipeline

```text
read partition bytes
        |
        v
FileSystemDetector::detect_at           "NTFS" signature at bytes [3..7]
        |
        v
NtfsFileSystem::parse(reader, offset)   Boot Sector decode
        |
        v
NtfsFileSystem::investigate(reader)
        |
        +--> NtfsMftReader        (geometry from boot sector)
        +--> read MFT record 0    ($MFT)
        +--> parse record 0       (locate the $MFT $DATA attribute)
        +--> must be NON-RESIDENT
        +--> reconstruct the whole MFT stream via data runs
        +--> for each record slot:
        |       skip if all-zero
        |       MftRecord::new       ("FILE" signature + USA fixup)
        |       Investigation::process_mft_record
        |
        v
Investigation
        |
        v
to_forensic_model(image)        -> ForensicModel
```

## Step by step

### 1. Detection

`FileSystemDetector::detect_at` reads 512 bytes at the partition's byte
offset and checks that bytes `[3..7]` equal `"NTFS"`. NTFS is currently
the only filesystem for which `is_supported()` returns `true`; every
other signature is detected but rejected at the support gate.

### 2. Boot sector decode

`NtfsFileSystem::parse` (`boot_sector.rs`) decodes fixed offsets:
bytes-per-sector, sectors-per-cluster, total sectors, the MFT cluster
(LCN), the MFT mirror cluster, and the MFT and index record sizes. The
MFT record size is a signed field: positive means "that many clusters",
negative means "1 << -value" bytes. The cluster size is `bytes_per_sector
* sectors_per_cluster`.

### 3. Reading the MFT

The `NtfsMftReader` computes the MFT's byte offset as
`partition_offset + mft_cluster * bytes_per_cluster`.

**Crucially, the MFT is not read linearly from the disk.** Forensis:

1. reads record 0 (the `$MFT` file itself);
2. parses it twice to locate its `$DATA` attribute (the first parse is
   currently discarded);
3. requires that `$DATA` be **non-resident** (a resident `$MFT` is
   rejected);
4. reads the MFT geometry — the MFT's real size gives the record
   count;
5. reconstructs the **entire MFT stream** by walking the `$DATA`
   runlist and reading each run physically.

This is why an MFT that is fragmented works: the runlist
(`data_run.rs`, `data_run_reader.rs`) re-assembles it regardless of
physical layout.

### 4. Record validation — USA fixup

Every MFT record starts with the `"FILE"` signature. `MftRecord::new`
validates the signature and applies the **Update Sequence Array (USA)**
fixup: the last two bytes of each 512-byte sector inside the record
store a sequence number, which is replaced by the original bytes taken
from the USA, and the sequence numbers are checked for consistency.
Sector alignment (records aligned to 512 bytes) is validated as well.

### 5. Attribute walking

`MftParser::parse` reads the record header (sequence number, link
count, first-attribute offset, flags, used/allocated sizes, base
record) and then walks attributes from the first-attribute offset until
the `0xFFFFFFFF` terminator. Traversal advances by the *declared*
attribute length — it never trusts parsed content sizes.

For each attribute the parser dispatches on type:

| Attribute | Parsed with | Notes |
| --- | --- | --- |
| `$STANDARD_INFORMATION` | `standard_information.rs` | resident, always |
| `$FILE_NAME` | `file_name.rs` | resident, always |
| `$DATA` | `data_attribute.rs` | resident or non-resident |
| `$INDEX_ROOT` | `index_root.rs` | resident, always |
| everything else | — | ignored, so parsing can continue safely |

The resident flag lives in the attribute header's byte 8. Resident
values are copied into the attribute; non-resident values are
interpreted later by `DataAttribute`.

### 6. Data runs and content

- `DataAttribute::parse` reads the runlist offset, the allocated size,
  the real size, and the runlist.
- `DataRun::parse` decodes each run's header byte: the high nibble is
  the number of bytes used for the LCN delta, the low nibble the bytes
  of the cluster count. A zero-length LCN field means a **sparse** run.
  LCN deltas are sign-extended and accumulated against the previous
  LCN; negative absolute LCNs are rejected; the runlist must end with a
  `0x00` terminator.
- `DataRunReader::read_runs` walks the runs, reads each one physically
  at `partition_offset + lcn * bytes_per_cluster`, zero-fills sparse
  runs, and stops once `real_size` bytes have been collected.
- `FileContentReader` is the thin facade used for reading file content.

### 7. Directories

Directories are resolved through their **resident** `INDEX_ROOT`
attribute. `IndexRoot::parse` reads the fixed header and walks the
`IndexEntry` chain until the *last-entry* flag. Each `IndexEntry`'s key
is interpreted as a `FILE_NAME` (`index_entry.rs` → `file_name.rs`).

***Important limitation:*** the non-resident `INDEX_ALLOCATION`
(`INDX` blocks) parser exists in `index_allocation.rs` and validates
the `"INDX"` signature, applies the USA fixup, and parses the entry
chain — but it is **not wired into the investigation pipeline**.
Directories whose index overflows the root are therefore only partially
enumerated. Large directories are a known gap.

### 8. Investigation and the forensic model

`Investigation::process_mft_record` visits every MFT record and, for
every `$FILE_NAME`, produces an `InvestigationEntry`
(`investigation_entry.rs`), which `to_forensic_model` then converts to
a `ForensicEntry`.

The mapping from NTFS to the [forensic model](../forensic-model.md):

| NTFS | Forensic model |
| --- | --- |
| MFT record number | `object_id` |
| parent MFT record from `$FILE_NAME` | `parent_id` |
| `$DATA` / `$FILE_NAME` sizes | `real_size`, `allocated_size` |
| record flags | `status` and `allocation.allocated` |
| `$FILE_NAME` directory flag | `kind = Directory` vs `File` |
| non-sparse data runs | `physical_location.regions` (cluster + sector ranges) |
| resident data, runs, sparse runs | `content_layout` segments (`Inline`, `Physical`, `Sparse`) |

### Deleted-file detection

Deletion detection is entirely **MFT-record-flag-based**:

1. Windows clears the *record in use* bit (`0x0001`) in the record
   header when it frees the record.
2. The record's `$FILE_NAME` and `$DATA` attributes are usually left
   physically in the record.
3. Because `process_mft_record` still parses and emits every remaining
   `$FILE_NAME` even for unallocated records, these entries are found
   with `mft_flags` missing bit `0x0001`.
4. That missing bit maps the entry to `ForensicStatus::Deleted` and
   `allocation.allocated = false`.

Note that NTFS normally *removes* the deleted file's name from the
parent directory's index — which is exactly why a full MFT scan is the
reliable way to find deleted objects. The directory index is not
cross-checked for deletions. Completely zero-filled MFT slots are
skipped entirely and produce no entries.

### Path resolution

After enumeration, each entry's absolute path is resolved by walking
the parent chain (`resolve_path` in `investigation.rs`). Roots are
identified by the self-parenting convention (record 5, the root
directory `$`). A visit map protects against parent cycles, and records
whose ancestors are gone get a partial path.

## What is implemented but not wired in

These parsers compile and work standalone, but no code path calls them
during `investigate()`:

| Module | Parses | Status |
| --- | --- | --- |
| `$Bitmap` | cluster allocation map | never read; `allocation.bitmap_allocated` is always `None` |
| `$UpCase` | Unicode uppercase table | not loaded; name comparison uses the raw name bytes |
| `$Secure` | security descriptor stream | wrapper only; descriptors not decoded |
| `$BadClus` | bad-cluster stream | not read |
| `$LogFile` | journal restart area / records | placeholder; validates non-empty only |
| `$AttrDef` | attribute definitions | not read |
| `$VolumeInformation` | volume flags | parsed for the record but not surfaced |
| `INDEX_ALLOCATION` | non-resident `INDX` blocks | parsed but not connected |

## Current limitations

- **MFT mirror is never read.** The boot sector field is stored and
  echoed in metadata, but there is no fallback or cross-validation
  against `$MFTMirr` when `$MFT` is truncated or corrupt.
- **Timestamps do not reach the forensic model.** `$STANDARD_INFORMATION`
  parses the four FILETIME values internally, but `ForensicMetadata`
  carries only sizes. There is no FILETIME→Unix conversion anywhere in
  the crate yet.
- **512-byte sector assumption.** Partition offsets and NTFS sector
  math assume 512-byte logical sectors (`NTFS_BYTES_PER_SECTOR = 512`
  in `investigation_entry.rs`).
- **Resident-only directory roots and no reparse/ea handling.**
  Attribute list, reparse points, EA and alternate data streams are
  skipped (parsing continues safely past them).
- **A stale debug-era residue** exists in the parser (*an empty
  `if record.index == 65 {}` block*) that has no effect.

## What works well

- Fragmented MFTs and files are handled correctly through runlists.
- USA fixups validate record and `INDX` integrity.
- The mapping to the forensic model is complete for status, allocation,
  physical location and content layout — the data recovery needs to
  work against fragmented, sparse and resident content
  (see [recovery.md](../recovery.md)).
- Zeroed slots are skipped; sparse runs are represented, not fabricated.

## Source map

| Concern | Files |
| --- | --- |
| Volume parse + investigation driver | `boot_sector.rs` |
| MFT reading | `mft_reader.rs` |
| MFT record + USA | `mft_record.rs` |
| Attribute walk | `mft_parser.rs`, `mft_attribute.rs`, `parsed_record.rs` |
| Content | `data_attribute.rs`, `data_run.rs`, `data_run_reader.rs`, `file_content.rs` |
| Directories | `index_root.rs`, `index_entry.rs`, `index_allocation.rs`, `directory.rs`, `directory_entry.rs` |
| Metadata files | `bitmap.rs`, `upcase.rs`, `secure.rs`, `badclus.rs`, `log_file.rs`, `attr_def.rs`, `volume.rs`, `volume_information.rs` |
| Investigation | `investigation.rs`, `investigation_entry.rs` |
| Module wiring | `mod.rs` |