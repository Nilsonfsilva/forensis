# Forensis Documentation

Technical documentation for the Forensis forensic framework:
analysis and recovery of digital evidence directly from disk bytes.

## Project

- [Architecture](architecture.md) — crates, layers and data flow.
- [Forensic model](forensic-model.md) — the filesystem-independent
  representation that parsers produce and recovery consumes.
- [Recovery](recovery.md) — the physical recovery engine and its
  integrity guarantees.
- [Filesystem roadmap](filesystem-roadmap.md) — NTFS today; ext4,
  ext3, FAT32 and exFAT next.

## NTFS study

- [Study index](ntfs/)
- [NTFS guide](ntfs/guide.md) — conceptual deep-dive.
- [Implementation](ntfs/implementation.md) — how Forensis actually reads
  an NTFS volume, and its current limitations.
- [Glossary](ntfs/glossary.md)

## Contributing

- [Contributing guide](../CONTRIBUTING.md) — building, testing and
  adding a filesystem.

## Index

| Document | Audience |
| --- | --- |
| [architecture.md](architecture.md) | Developers, reviewers, architects |
| [forensic-model.md](forensic-model.md) | Developers, forensic analysts |
| [recovery.md](recovery.md) | Developers, forensic analysts |
| [ntfs/guide.md](ntfs/guide.md) | Anyone learning NTFS |
| [ntfs/implementation.md](ntfs/implementation.md) | Contributors to the NTFS module |
| [filesystem-roadmap.md](filesystem-roadmap.md) | Maintainers, contributors |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | New contributors |