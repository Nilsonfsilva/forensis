# Forensis

Forensic analysis and recovery directly from disk bytes.

Forensis works at the raw byte level of block devices and disk images,
building a forensic model without relying on the operating system's
filesystem layer. It identifies hardware evidence sources, inspects
disk images, filesystems and partitions, and recovers deleted objects
through a physical recovery engine.

## Demo

### TUI

The TUI in action: loading a fragmented NTFS image, recovering a deleted
fragmented file, and verifying it against the media reference by SHA-256.

![Forensis TUI demo](docs/demo/forensis-tui-demo.gif)

### CLI

The CLI walking through the same workflow: the forensic tree, the deleted
objects inspection, the interactive recovery with SHA-256 verification,
and a checksum of the recovered file.

![Forensis CLI demo](docs/demo/forensis-cli-demo.gif)

## Features

- Raw access to block devices, device partitions and disk images.
- Automatic discovery of evidence sources with an interactive picker.
- Filesystem-independent forensic model expressed as a tree.
- NTFS forensic analysis (records investigated, entries discovered,
  physical allocation).
- Recovery of deleted filesystem objects, including SHA-256-based
  integrity comparison between the original and the recovered file.
- CLI and TUI interfaces sharing a common application layer.

## Documentation

- [Architecture](docs/architecture.md) — the byte-flow map: crates, layers,
  vertical/horizontal transitions and how bytes enter and leave each layer.
- [Forensic model](docs/forensic-model.md) — the filesystem-independent
  representation.
- [Recovery](docs/recovery.md) — the physical recovery engine.
- [NTFS study](docs/ntfs/) — a full deep-dive into NTFS, from the
  concepts to the implementation.
- [Filesystem roadmap](docs/filesystem-roadmap.md) — NTFS today; ext4,
  FAT32 and exFAT next.
- [Contributing](CONTRIBUTING.md) — building, testing and adding a
  filesystem.

## Status

The filesystem detector recognizes NTFS, ext4, FAT32, exFAT, XFS,
btrfs, HFS+ and APFS signatures. Forensic investigation and recovery
are currently implemented for **NTFS**; the other filesystems are
detected but not yet analyzed.

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `forensis-core` | Bytes, disk, partition and filesystem layers; forensic model; recovery engine. |
| `forensis-app` | Application use cases shared by the user interfaces. |
| `forensis-cli` | Command line interface (binary `forensis`). |
| `forensis-tui` | Terminal user interface (binary `forensis-tui`). |

## Installation

No `.deb` package is available yet. On Debian/Ubuntu, install from
source with the Rust toolchain. If you do not have it yet:

```sh
sudo apt update
sudo apt install -y rustc cargo
```

Install the binaries to `/usr/local/bin`:

```sh
cargo build --release
sudo install -Dm755 target/release/forensis target/release/forensis-tui /usr/local/bin/
```

Verify the installation:

```sh
forensis --help
```

To remove Forensis from the system:

```sh
sudo rm /usr/local/bin/forensis /usr/local/bin/forensis-tui
```

Alternatively, install only the CLI into a personal directory
(without `/usr/local/bin`):

```sh
cargo install --path crates/forensis-cli --root ~/.local
# then add ~/.local/bin to PATH
```

## Building

```sh
cargo build --release
```

The CLI binary is produced as `target/release/forensis` and the TUI
binary as `target/release/forensis-tui`.

## Usage

### Inspect a disk image

```sh
forensis inspect disk.img
```

Show an object's detail by ID (workspace the ID of an object from the
listing; `64` below is only an example value):

```sh
forensis inspect disk.img --detail <OBJECT_ID>
# exemplo: forensis inspect disk.img --detail 64
```

Filter objects by status (`normal`, `system`, `deleted`, `carved`,
`inconsistent`, `unknown`):

```sh
forensis inspect disk.img --status deleted
```

### Display the forensic tree

```sh
forensis tree disk.img
forensis tree disk.img /path/inside/filesystem
```

### Recover forensic objects

```sh
forensis recover disk.img                        # asks category, then output
forensis recover disk.img --category deleted
forensis recover disk.img --category file --output /dest
forensis recover disk.img --category all --output /dest
```

When inspecting a raw device, Forensis lists the block device, its
partitions and any disk images found, and prompts you to choose a
source interactively.

## Supported platforms

Works on Linux. Use on block devices requires appropriate privileges.
Always operate on a forensic copy of the evidence, never on the
original device.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).