# linux-memory-mapper
A kernel module that maps the VMAs of a target process into the calling process, enabling cross-process memory inspection/modification.

## Interface
The module exposes a root-only device at `/dev/map` (mode `0600`). A userspace process opens `/dev/map` and writes a PID (ASCII decimal + newline). The target process is then mapped into the *calling process* (the process that performed the write).

Important: mappings are tracked per open file descriptor. When the `/dev/map` fd is closed, the module unmaps anything it created and releases pinned pages. If you want “live” mappings, your process must keep the fd open while inspecting.

## Build / Load
- Build: `make LLVM=1`
- Load: `sudo insmod main.ko`
- Unload: `sudo rmmod main`

## Usage
- Programmatic use (recommended): open `/dev/map`, write `<pid>\n`, keep the fd open during inspection.
- `dump` example: a simple interactive hexdump tool in this repo opens `/dev/map`, writes the PID, keeps the fd open, and then lets you dump addresses.

## Notes / Caveats
- This module is intentionally invasive and unsafe: it uses `MAP_FIXED` and can overwrite existing mappings in the calling process, potentially crashing it.
- File-backed VMAs are recreated via file mappings; “liveness” follows normal `MAP_SHARED`/`MAP_PRIVATE` semantics.
- Anonymous VMAs are mapped “live” by pinning the target’s pages and remapping PFNs. This is dangerous and can fail for some regions (guard pages, special kernel mappings, address collisions).

## Module parameters
- `log_failures=0/1` (default `1`): emit a kernel log line explaining each failed VMA mapping step.
- `live_anon=0/1` (default `1`): enable live mapping of anonymous VMAs via PFN remapping.
