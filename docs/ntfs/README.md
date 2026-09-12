# NTFS Study

A deep dive into the New Technology File System, written against
Forensis' actual NTFS implementation.

- [NTFS guide](guide.md) — the conceptual deep-dive: boot sector, MFT,
  records, attributes, indexes, resident and non-resident data, deleted
  files, and the forensic view.
- [Implementation](implementation.md) — how Forensis reads an NTFS
  volume end to end, and what the implementation does not do yet.
- [Glossary](glossary.md) — abbreviations and terms.

## Suggested reading order

1. Start with the [guide](guide.md) to build the mental model.
2. Read [implementation.md](implementation.md) to see how that model
   maps to code.
3. Use the [glossary](glossary.md) as reference while studying.

## Related

- [Forensic model](../forensic-model.md) — how NTFS data is translated
  into the filesystem-independent representation.
- [Recovery](../recovery.md) — how deleted NTFS objects are recovered
  from raw bytes.
- [Filesystem roadmap](../filesystem-roadmap.md) — what comes after NTFS
  (ext4, FAT32, exFAT).