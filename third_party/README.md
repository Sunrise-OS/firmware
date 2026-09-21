# Third-party sources

## `patina`

`patina` is a git submodule of [OpenDevicePartnership/patina][patina], pinned to
the commit that published the crates this firmware uses ("Chore: Update crate
versions to 23.2.1", `0abda1c`). Every Patina crate the platform depends on is
taken from that tree by path rather than from crates.io, so the framework is one
consistent set of sources at one commit instead of a set of independently
published versions. `platform/Cargo.toml` carries the mapping in
`[patch.crates-io]`.

One patch sits on top of the submodule:

- `patches/dxe-core-loaded-image-system-table.patch`: the DXE core's own
  `EFI_LOADED_IMAGE_PROTOCOL` recorded a pointer to Patina's Rust
  `EfiSystemTable` wrapper in `SystemTable` instead of the `EFI_SYSTEM_TABLE`
  it wraps. Images Patina loads later get the right pointer; the core's own
  record is what a platform component reaches the system table through (to
  publish the console in `ConOut`, for one), and it read a table whose
  "signature" was the wrapped pointer and whose `BootServices` was null.

`scripts/prepare-patina.sh` applies it, idempotently, and says so when it does.
It is safe to run before every build; `git -C third_party/patina checkout .`
removes it again.

[patina]: https://github.com/OpenDevicePartnership/patina
