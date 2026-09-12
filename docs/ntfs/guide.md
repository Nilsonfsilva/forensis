# NTFS Guide

A conceptual deep-dive into the New Technology File System (NTFS). The
guide is written against Forensis' real implementation, so each concept
points to the source file that implements it in
`crates/forensis-core/src/filesystem/ntfs/`.

> How to read this guide: each chapter covers one structure. For every
> concept we ask three questions — *what it is*, *what it does*, and
> *why it exists* — because each NTFS structure exists to solve one
> specific problem, and no structure can be understood without its
> problem.

---

## 1. What is NTFS?

NTFS is the **New Technology File System**, the native filesystem of
modern Windows systems.

A storage device, by itself, is only a long sequence of bytes. It has
no native concept of *file*, *directory*, *name*, *permission*,
*timestamp*, or *deleted file*. Those concepts are imposed by the
filesystem.

```text
Physical device
        |
        v
+---------------------------+
| byte sequence             |
+---------------------------+
        |
        v
       NTFS
        |
        +-- files
        +-- directories
        +-- metadata
        +-- permissions
        +-- free space
        +-- indexes
        +-- journal
```

> **NTFS is a structure that turns a sequence of bytes into an
> organized volume of files and metadata.**

---

## 2. How to think about a filesystem

A useful analogy is a library.

| Library | NTFS |
| --- | --- |
| The building | The disk |
| The books | The files |
| The shelves | The directories |
| The catalog | The MFT |
| Indexes | Directory indexes |
| Access rules | Security descriptors |
| The operations log | The journal ($LogFile) |

The point is not the analogy itself but the principle behind it: NTFS
imposes organization and bookkeeping on a flat medium, in binary form,
byte by byte.

---

## 3. How NTFS is divided

At a high level NTFS is a set of structures that cooperate:

```text
NTFS
│
├── Boot Sector            initial volume parameters
├── MFT                    the central file table
├── Attributes             standardized per-file data slots
├── Index                  directory organization
│   ├── Index Root
│   ├── Index Entry
│   └── Index Allocation
├── $UpCase                Unicode name comparison table
├── $Volume Information    volume state
├── Security               security descriptors
├── $LogFile               transactional journal
└── $BadClus               registry of defective clusters
```

These are *logical* roles. On disk they are not laid out one after
another; they are scattered across the volume and linked to each other.

> **Each component solves one specific problem of the filesystem.**

---

## 4. Boot Sector

Source: `boot_sector.rs`

The boot sector is the first structure any NTFS reader must interpret.
It contains every parameter needed to interpret the rest of the volume.

### What it provides

- bytes per sector;
- sectors per cluster;
- total sector count;
- location of the MFT (in clusters);
- location of the MFT mirror;
- MFT record size;
- index record size.

### Why it exists

Without its geometry, the reader cannot even compute the cluster size,
and every later offset would be wrong. The boot sector answers the
first question of any read: *how are the following bytes organized?*

```text
Image
  |
  v
Boot Sector
  |
  +-- bytes per sector
  +-- sectors per cluster
  +-- MFT location
  |
  v
 MFT
```

---

## 5. The MFT — Master File Table

Sources: `mft_reader.rs`, `mft_record.rs`, `mft_parser.rs`

The MFT is the central metadata structure of NTFS. It is a table of
fixed-size records, one record per filesystem object:

```text
MFT
│
├── Record 0   $MFT
├── Record 1   $MFTMirr
├── Record 2   $LogFile
├── Record 3   $Volume
├── Record 4   $AttrDef
├── Record 5   $
├── Record 6   $Bitmap
├── ...
└── Record N
```

### What it does

The MFT is the source of truth for what exists on the volume:

- which objects exist;
- which attributes each object carries;
- where each object's data lives;
- the object's name;
- the object's parent directory;
- the object's metadata.

### Why it exists

NTFS needs one authoritative structure to describe every object. A
central table makes enumeration simple and traversal fast.

> **In NTFS, a file is not "its bytes". A file is a record carrying
> attributes.**

---

## 6. MFT Record

Source: `mft_record.rs`

Each MFT slot is a *record*. A record has a header followed by a
sequence of attributes:

```text
MFT Record
│
├── Header          signature, flags, link count, first attribute offset
├── Attribute
├── Attribute
├── Attribute
│
└── End Marker      0xFFFFFFFF
```

- The header's signature is `"FILE"`.
- The record is protected by an **Update Sequence Array (USA)**: the
  last two bytes of every 512-byte sector of the record store a
  sequence number, and any corruption is detected by comparing the
  trailer bytes against the array. Fixing (undoing the fixup) restores
  the original bytes.
- The header flags (in particular the "record in use" bit) are forensic
  gold — they are what let Forensis identify *deleted* records.

### Why it exists

The record is the unit that represents one file or directory. NTFS can
grow and shrink a record's content through its attributes.

---

## 7. Attributes

Source: `mft_attribute.rs`

The attribute is the most important idea of NTFS. A record is little
more than a container for attributes, and attributes are typed slots:

| Type | Attribute |
| --- | --- |
| 0x10 | `$STANDARD_INFORMATION` |
| 0x20 | `$ATTRIBUTE_LIST` |
| 0x30 | `$FILE_NAME` |
| 0x40 | `$OBJECT_ID` |
| 0x50 | `$SECURITY_DESCRIPTOR` |
| 0x60 | `$VOLUME_NAME` |
| 0x70 | `$VOLUME_INFORMATION` |
| 0x80 | `$DATA` |
| 0x90 | `$INDEX_ROOT` |
| 0xA0 | `$INDEX_ALLOCATION` |
| 0xB0 | `$BITMAP` |
| 0xC0 | `$REPARSE_POINT` |
| 0xD0 | `$EA_INFORMATION` |
| 0xE0 | `$EA` |
| 0x100 | `$LOGGED_UTILITY_STREAM` |

Each attribute has a common header (type, length, the resident flag,
id) followed by a value. A **resident** attribute stores its value
inside the record; a **non-resident** attribute points to clusters
outside it.

### Why it exists

This architecture lets one record represent very different objects
without a bespoke structure for each: a file is a record with a
`$FILE_NAME`, a `$STANDARD_INFORMATION` and a `$DATA`; a directory adds
an `$INDEX_ROOT`; the volume itself is a record with volume attributes.

---

## 8. Standard Information

Source: `standard_information.rs`

`$STANDARD_INFORMATION` is the basic per-file state. It contains the
four FILETIME timestamps:

- creation time;
- last modification time;
- MFT record modification time;
- last access time.

plus file attribute flags. Windows stores these timestamps as FILETIME
(100-nanosecond ticks since 1601-01-01).

### Forensic importance

Timestamps are among the most asked questions in an investigation. They
must never be interpreted in isolation — a serious analysis cross-checks
them against other sources and context.

---

## 9. File Name

Source: `file_name.rs`

`$FILE_NAME` is a named reference to the object:

- the name itself;
- a reference to the parent directory's MFT record;
- allocated and real sizes (as seen from the directory entry);
- per-entry timestamps;
- file attribute flags (including the *directory* flag).

This attribute is what makes path reconstruction possible: walking the
parent references of each record rebuilds the full path such as
`C:\Users\Nilson\Documents\report.txt`.

---

## 10. The Data Attribute

Source: `data_attribute.rs`

`$DATA` is the attribute that carries file content. It is where the
concepts of **resident** and **non-resident** live.

### Resident

Small content stored directly inside the MFT record:

```text
MFT Record
│
└── $DATA
    └── the file's bytes
```

### Non-resident

Content described by a runlist that maps logical offsets to physical
clusters:

```text
MFT Record
│
└── $DATA
    └── runlist (data runs)
             |
             +-- Cluster 100
             +-- Cluster 101
             +-- Cluster 102
```

### Why it exists

Storing large files inside the record would be wasteful; storing every
file's indirection would be wasteful too. NTFS keeps small contents
inline and uses references only when content grows.

---

## 11. Resident and non-resident attributes

| | Resident | Non-resident |
| --- | --- | --- |
| Value location | inside the record | outside the record |
| Extra bookkeeping | none | runlist, allocated/real sizes, compression flag |
| Access | immediate | read clusters through the runlist |
| Use case | small values (`$STANDARD_INFORMATION`, `$FILE_NAME`, `INDEX_ROOT`, tiny `$DATA`) | large values (`$DATA`, `$INDEX_ALLOCATION`, `$BITMAP`) |

---

## 12. Data Runs

Sources: `data_run.rs`, `data_run_reader.rs`, `file_content.rs`

A **data run** describes one contiguous physical piece of a
non-resident attribute: how many clusters it covers and where it starts
(relative to the previous run). Sparse runs — logical content with no
physical allocation — have a length but no location, and read as zeroes.

The runlist is a sequence of runs; following it in order and accumulating
the LCN deltas yields every physical region of the attribute.

```text
Runlist:
  run 1  length=10, lcn stub          -> LCN 100
  run 2  length=8,  lcn delta +50     -> LCN 150
  run 3  length=4,  sparse            -> zeroes
```

This is the mechanism behind fragmentation: a single logical file can
live in many disjoint regions, and the runlist preserves their logical
order.

---

## 13. Bitmap

Source: `bitmap.rs`

A bitmap is a bit-per-unit allocation map: each bit states whether a
unit is in use. NTFS uses `$BITMAP` for the cluster allocation map, and
bitmaps also back large indexes and MFT extension records.

```text
bit:   7 6 5 4 3 2 1 0
value: 0 1 1 0 0 1 0 1
      (1 = allocated, 0 = free)
```

### Forensic importance

Space that is not currently allocated may contain old data — this is
exactly the territory of deleted-file recovery and (future) carving.
Understanding allocation is therefore essential to understanding
recovery.

---

## 14. Directories and Indexes

Sources: `index_root.rs`, `index_entry.rs`, `index_allocation.rs`,
`directory.rs`, `directory_entry.rs`

A directory must answer one query efficiently: given a name, which
record does it refer to? NTFS answers with per-directory **indexes**
organized as B-tree structures.

```text
Directory
   |
   +-- index
        |
        +-- "a.txt"   -> Record 42
        +-- "b.txt"   -> Record 77
        +-- "c.txt"   -> Record 90
```

The index tree has three levels, exactly matching where the data lives:

| Level | Structure | Resident? |
| --- | --- | --- |
| Root | `INDEX_ROOT` + its entries | resident in the record |
| Leaf | `INDEX_ALLOCATION` (`INDX` blocks) | non-resident |
| Leaf | `IndexEntry`s inside the blocks | |

### Index Root

Source: `index_root.rs`

The resident part of the index: a header describing the indexed
attribute and the first entries themselves. Small directories fit
entirely here.

### Index Entry

Source: `index_entry.rs`

One entry in the index: a reference to an MFT record (48-bit record
number + sequence number), the entry's length, a flags word, and a
*key*. For directories the key is a `FILE_NAME` value. The flags say
whether the entry is the last in the block and whether it has a
sub-node pointer.

### Index Allocation

Source: `index_allocation.rs`

When a directory outgrows the root, the overflow is stored in
non-resident `INDX` blocks. Each `INDX` block carries the same
`"INDX"` signature, its own USA fixup, and another chain of index
entries. This is how NTFS handles directories with tens of thousands of
entries.

---

## 15. UpCase

Source: `upcase.rs`

`$UpCase` is a 65,536-entry table mapping each UTF-16 code unit to its
uppercase form. NTFS uses it for Unicode-aware, case-insensitive name
comparison:

```text
report.txt
Report.txt
REPORT.TXT
```

The same comparison works regardless of script rules because NTFS does
not rely on a naive byte comparison.

---

## 16. Volume Information

Source: `volume_information.rs`

`$VOLUME_INFORMATION` describes the volume itself: NTFS version and
flags such as the *dirty* bit (the volume was not cleanly dismounted).
A dirty flag is a strong indicator of a system that was interrupted,
which matters for both consistency analysis and recovery.

---

## 17. Security

Source: `secure.rs`

Security is expressed through **security descriptors** stored in the
`$Secure` metadata stream. A descriptor can carry the owner, the
primary group, DACLs (discretionary access control lists) and SACLs
(system access control lists). NTFS deduplicates descriptors in
`$Secure`, and records reference them by index.

Forensis' `secure.rs` is currently a raw wrapper of the `$Secure`
stream: the descriptors are not yet decoded.

---

## 18. Journal — $LogFile

Source: `log_file.rs`

`$LogFile` is NTFS' transactional journal. Before mutating critical
structures, NTFS logs the intended change; if an operation is
interrupted (e.g. power loss), the journal lets the filesystem replay
or roll back the transaction to restore consistency.

```text
Beginning of an operation
       |
       v
Updating structures
       |
       X
   power loss
```

### Forensic importance

The journal records recent metadata operations. It is not a complete
history of everything on the volume — NTFS periodically truncates it —
but it can corroborate or contradict other evidence. Forensis'
`log_file.rs` runs the container; the records are not yet decoded.

---

## 19. Bad Clusters

Source: `badclus.rs`

`$BadClus` is the metadata file that maps defective clusters. NTFS uses
it to avoid placing important data on media regions known to be
physically damaged.

The concept matters forensically too: a cluster listed in `$BadClus`
might indicate deliberate tampering that copies data into the bad-cluster
stream to hide it.

---

## 20. How a file is represented

Consider `report.txt`. NTFS does *not* think `report.txt = bytes`. It
thinks:

```text
MFT Record (object)
│
├── $STANDARD_INFORMATION
│     ├── timestamps
│     └── flags
│
├── $FILE_NAME
│     ├── name
│     └── parent directory reference
│
└── $DATA
      ├── content (if resident)
      └── runlist -> clusters (if non-resident)
```

This decomposition is the single most important concept of this guide.

---

## 21. What happens when a file is deleted?

The simplification "the file is gone, so the data disappeared" is
dangerous and usually wrong.

Deleting a file is a change to the filesystem bookkeeping, not
necessarily a wipe of content:

1. NTFS clears the **"record in use"** bit in the MFT record header.
2. The record's attributes usually remain physically in the record — a
   `FILE_NAME` and a `$DATA` may be fully intact.
3. The file's name is generally removed from the parent directory's
   index.
4. The clusters are marked free in the cluster bitmap.

```text
Before deletion                        After deletion
-------------                          -------------
MFT Record                             MFT Record
   |  in use: yes                         |  in use: no   <-- flag cleared
   +-- $FILE_NAME                         +-- $FILE_NAME  <-- still present
   +-- $DATA                              +-- $DATA       <-- still present
   +-- clusters allocated                 +-- clusters now "free"
```

Whether recovery is possible depends on factors such as:

- whether the clusters have been reallocated and overwritten;
- fragmentation;
- file size (resident content survives fully inside the record);
- whether the record itself was reused;
- subsequent writes by the OS.

This is why forensic recovery must not be confused with simply
"searching for deleted files". Forensis identifies deleted objects by
the cleared in-use flag and recovers them from the bytes still on the
medium. See [implementation.md](implementation.md) and
[recovery.md](../recovery.md).

---

## 22. The forensic view

A forensic tool is not the OS: it must not "mount" the filesystem so
much as *interview* it, preserving as much original information as
possible. The questions are:

- Which files exist?
- Which files existed?
- What were the names are original paths?
- What metadata was present?
- Where were the data located on disk?
- Is the content still allocated?
- Is the content recoverable?
- Are there signs of recent activity (journal, dirty flag, reallocated
  clusters)?

These questions map directly onto Forensis' [forensic model](../forensic-model.md).

---

## 23. The complete mental model

```text
                 NTFS
                   |
                   v
             Boot Sector
                   |
                   v
                  MFT
                   |
                   v
             MFT Record
                   |
          +--------+--------+
          |        |        |
          v        v        v
        Name    Metadata   Data
          |        |        |
          v        v        v
     Directory   Time    Content
                   |
                   v
              other structures
                   |
       +----------+----------+
       |          |          |
       v          v          v
     Bitmap    Security   Journal
```

And for Forensis:

```text
             DISK / IMAGE
                   |
                   v
             DISK LAYER
                   |
                   v
          PARTITION LAYER
                   |
                   v
            FILESYSTEM
                   |
                   v
                 NTFS
                   |
          +--------+--------+
          |        |        |
          v        v        v
       Boot      MFT      Volume
                   |
                   v
               Record
                   |
                   v
            Attributes
                   |
        +----------+----------+
        |          |          |
        v          v          v
      Name     Metadata    Data
                   |
                   v
           Investigation
                   |
                   v
            FORENSIC MODEL
```

> **Forensis takes raw bytes and, layer by layer, turns them into
> knowledge about the filesystem.** That is why the code is split into
> modules: no single module understands all of NTFS; each understands a
> piece, and the layers above combine the pieces.

---

## 24. NTFS concepts and Forensis modules

| NTFS concept | Forensis module |
| --- | --- |
| Boot sector | `boot_sector.rs` |
| MFT access | `mft_reader.rs` |
| MFT record | `mft_record.rs` |
| Record parsing | `mft_parser.rs` |
| Logical record | `parsed_record.rs` |
| Attribute header | `mft_attribute.rs` |
| Metadata timestamps/flags | `standard_information.rs` |
| File name / parent | `file_name.rs` |
| Content | `data_attribute.rs` |
| Runlist | `data_run.rs`, `data_run_reader.rs`, `file_content.rs` |
| Index root | `index_root.rs` |
| Index entry | `index_entry.rs` |
| Index allocation | `index_allocation.rs` |
| Directories | `directory.rs`, `directory_entry.rs` |
| Allocation bitmap | `bitmap.rs` |
| Unicode comparison | `upcase.rs` |
| Volume state | `volume_information.rs` |
| Journal | `log_file.rs` |
| Security | `secure.rs` |
| Bad clusters | `badclus.rs` |
| Investigation | `investigation.rs`, `investigation_entry.rs` |

A concept marked by a module does not always mean it is wired into the
investigation pipeline — see the [implementation notes](implementation.md)
for exactly what is connected today.

---

## 25. Why Forensis started with NTFS

NTFS is an excellent first filesystem because it concentrates nearly
every idea that later filesystems reuse, in different forms:

- binary structures and records;
- attributes;
- indexes and B-trees;
- allocation and bitmaps;
- metadata and timestamps;
- Unicode;
- security;
- journaling.

When the next filesystem starts (ext4, then FAT32/exFAT), the
structures will be different but the questions will be the same:

> Where is the metadata?
> How is a file identified?
> How does the system find its data?
> How are directories organized?
> How is space controlled?
> How do modification and recovery work?

If you can answer these six questions for NTFS, you have a foundation
for every other filesystem. The [roadmap](../filesystem-roadmap.md)
tracks that work.

---

## Conclusion

NTFS looks complex because it has many structures. But when every
structure has a single responsibility, the system becomes tractable:

```text
Volume
  ↓
Boot Sector
  ↓
MFT
  ↓
MFT Record
  ↓
Attributes
  ↓
File / Directory
  ↓
Data
```

Around that spine sit the supporting mechanisms:

```text
Bitmap      -> controls allocation
Index       -> organizes directories
UpCase      -> Unicode name comparison
Security    -> access control
Journal     -> consistency and recovery
Bad Clusters-> avoids defective regions
Volume Info -> describes the volume
```

It is this decomposition that lets Forensis grow in an organized way
and that lets you stop memorizing structures and start reasoning about
problems.