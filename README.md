# linux-memory-mapper
A kernel module that maps the VMAs of a target process into the calling process, enabling cross-process memory inspection/modification.

## Interface
The module exposes a root-only device at `/dev/map` (mode `0600`). A userspace process opens `/dev/map` and writes a PID (plus a newline). The target process is then mapped into the *calling process* (the process that performed the write).

Important: mappings are tracked per open file descriptor. When the `/dev/map` fd is closed, the module unmaps anything it created and releases pinned pages. If you want “live” mappings, your process must keep the fd open.

## Loading
- `insmod main.ko`

## Usage
- open `/dev/map`, write `<pid>\n`, and keep the fd open during use. Close the fd once done.

## Some Caveats
- This module is intentionally unsafe; it uses `MAP_FIXED` and can overwrite existing mappings in the calling process, potentially crashing it. It is recommended that the calling process binary is built statically to keep the amount of potential VMA collisions to a minimum
- File-backed VMAs are recreated via mappings;
- Anonymous VMAs are mapped “live” by pinning the target’s pages and remapping PFNs. This is dangerous and can fail for some regions, specifically vdso and vvar. These regions aren't particularly important so it should be fine

## parameters
- `log_failures=0/1` (default `1`): print a kernel log line explaining each failed VMA mapping step.
- `live_anon=0/1` (default `1`): enable live mapping of anonymous VMAs via PFN remapping.
