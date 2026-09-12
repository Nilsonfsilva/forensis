# Contributing to Forensis

Thank you for contributing. This guide explains the workspace, the
build/test commands and the conventions used in the project.

## Workspace layout

```
Cargo.toml                     workspace + shared package metadata
crates/
  forensis-core/               byte access, disk/partition/filesystem,
                               forensic model, recovery engine
  forensis-app/                application use cases
  forensis-cli/                command line interface (binary: forensis)
  forensis-tui/                terminal interface (binary: forensis-tui)
docs/                          technical documentation
lab/                           local test images (git-ignored)
```

## Building

```sh
cargo build --workspace
```

To compile the tests as well:

```sh
cargo build --workspace --tests
```

Run the test suite:

```sh
cargo test --workspace
```

The binaries are produced as `target/debug/forensis` (CLI) and
`target/debug/forensis-tui` (TUI).

## Code conventions

- Follow the layout of the layers: parsers live in
  `forensis-core/src/filesystem/<fs>/`, application logic in
  `forensis-app`, and presentation in the interfaces.
- Use the strongly typed newtypes (`ByteOffset`, `ByteSize`, `Sector`,
  `Cluster`) instead of bare integers for on-disk quantities.
- Use checked arithmetic (`checked_add`, `checked_mul`, ...) for any
  computation derived from untrusted on-disk values.
- Never panic on malformed input: return `Result` (`ForensisError` in
  `forensis-core`, `anyhow` in `forensis-app`/interfaces).
- Do not add comments that merely restate the code.
- Keep the [forensic model](docs/forensic-model.md) free of parser
  internals: a filesystem implementation must emit `ForensicEntry`
  data and nothing else.

## Adding a filesystem

1. Create `crates/forensis-core/src/filesystem/<fs>/`.
2. Implement the `FileSystem` trait (`parse` + `investigate`).
3. Translate the filesystem's structures into `ForensicEntry` data:
   - `object_id` ↔ native object id (inode, MFT record, ...);
   - `parent_id` from directory entries;
   - `kind` (file/directory/...);
   - `status` (Normal/System/Deleted at minimum);
   - `metadata` sizes;
   - `physical_location` and `content_layout` for recovery;
4. Give the volume blueprint to the forensic model so recovery works.
5. Register the filesystem in `FileSystemType` and `is_supported()`.

A parser that is not yet wired in must not claim support
(`is_supported()` stays `false` until the pipeline works end to end).

## Testing

- Unit tests live next to the code, or under `crates/<crate>/tests/`.
- Forensic images for local validation live under `lab/` and are
  git-ignored; do not commit disk images.
- Every pipeline change should keep `cargo build --workspace --tests`
  warning-clean (the only tolerated warning today is the pre-existing
  unused `is_known_mbr_partition_type` helper).

## Documentation

- User-facing docs live in `docs/`; update the relevant page when a
  behavior described there changes (especially
  `docs/ntfs/implementation.md` and `docs/filesystem-roadmap.md`).
- Keep code refs in docs pointing at real files; a concept described as
  implemented must actually be wired into the pipeline.

## License

By contributing you agree that your work is licensed under the
project's GPL-3.0-or-later license. See [LICENSE](LICENSE).