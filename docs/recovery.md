# Recovery

Forensis recovers forensic objects by re-reading the evidence bytes
directly from the disk image or device. Nothing is copied from the
operating system's filesystem layer: the bytes are located through the
forensic model and read back from raw storage.

```text
            ForensicEntry
                 |
                 v
         PhysicalRecoveryEngine
                 |
                 |  re-reads from Readable source
                 v
            RecoveryResult
                 |
                 +-- recovered data
                 +-- original_sha256 (reference digest)
```

## The engine

`RecoveryEngine` is a trait in `forensis-core` with one obligation:
produce a `RecoveryResult` for a `ForensicEntry`, given a `Readable`
byte source. It has no filesystem knowledge. `PhysicalRecoveryEngine`
implements it with `partition_offset` and `bytes_per_sector`
(currently `512`).

Every read is bounds-checked: the requested size must fit the region,
the byte offset must not overflow, and the region must not extend past
the end of the image. Short reads are treated as failures, not silent
truncation.

### Reconstructing the content

The authoritative path reconstructs the object's **logical content
layout** in order:

1. `Inline` segments — the resident bytes are used verbatim;
2. `Physical` segments — the region is read from the image at its disk
   byte offset;
3. `Sparse` segments — zero-filled (unallocated runs read as zeroes).

The last physical segment is truncated so that the total length matches
the object's real size. If fewer bytes are read than `real_size`, the
result is reported as failed, never as a partial success.

A legacy path iterating `physical_location.regions` directly remains
for entries that carry no content layout.

### `RecoveryResult`

- `recovered` — whether reconstruction succeeded;
- `data` — the reconstructed bytes (for small objects; recovery is
  currently in-memory);
- `original_sha256` — SHA-256 of the content read straight from the
  image, **before** any file is written. This is the reference digest
  used to verify the written file;
- `physical_location` — the regions that were read;
- `reason` — a human explanation when recovery failed.

## Application-layer coordination

The application layer (`forensis-app/src/recovery.rs`) coordinates the
whole operation:

- `next_recovery_ticket()` — a monotonic, zero-padded ticket stored in
  `forensis-recovery/.ticket`, used to name working directories and
  avoid clobbering previous work.
- `recover_object(image, object_id, output)` — inspects the image,
  locates the object in any model, recovers it and writes the file.
- `recover_deleted_files(image, output)` — recovers every entry whose
  status is `Deleted`.
- `recover_all(image, output)` — currently a straight alias of
  `recover_deleted_files`; carving is future work.

### `RecoveredFile` and integrity

Once a file is written, Forensis computes its hash and compares it with
the reference digest captured from the raw image:

| `HashComparison` | Meaning |
| --- | --- |
| `Identical` | The written file matches the bytes read from the image. |
| `Different` | The hashes differ — something is wrong. |
| `ReferenceUnavailable` | No reference digest (the reference was not produced). |

A recovered file is named after the object; on a name collision the
`object_id` is appended so no evidence is silently overwritten.

## Workflow

The CLI drives recovery through a ticket-based working directory:

```text
forensis-recovery/
  .ticket                         transport-protocol counter
  .working-000042                 scratch directory
  forensis-recovery-cli-000042    finalized CLI recovery
  forensis-recovery-tui-000042    finalized TUI recovery
```

## Limitations

- Recovery is in-memory (`Vec<u8>`); very large objects are not
  streamed.
- Sector math assumes 512-byte sectors.
- The hash comparison happens after the file is written; a misleading
  write is not preventable, only detectable.
- `recover all` does not yet be a distinct strategy from
  `recover deleted`.

Source files:

- `crates/forensis-core/src/recovery/engine.rs`
- `crates/forensis-core/src/recovery/result.rs`
- `crates/forensis-app/src/recovery.rs`
- `crates/forensis-core/src/forensic/model.rs` (content layout)