# linux-memory-mapper
A kernel module that maps the VMAs of a target process into the calling process, enabling cross-process memory inspection/modification.

## Interface
The module exposes `/dev/map` and enforces access in `open`/`write` (root or the configured allowlisted UID). A userspace process opens `/dev/map` and writes a mapping request. The target process is then mapped into the *calling process* (the process that performed the write).

Important: mappings are tracked per open file descriptor. When the `/dev/map` fd is closed, the module unmaps anything it created and releases pinned pages. If you want “live” mappings, your process must keep the fd open.

## Loading
- `insmod main.ko`

## Usage
- open `/dev/map`, write one of the following request formats, and keep the fd open during use:
- `<pid>` maps all VMAs with lazy anonymous-page population by default (`ondemand=1` implicit).
- `<pid> addr=<start>-<end>` where start/end are numeric (hex `0x...` or decimal), mapping only VMAs that overlap that address range.
- `<pid> vma=<list>` where list is comma-separated VMA indices/ranges (1-based), for example `vma=1,3,6-10`.
- `<pid> ondemand=1` explicitly enables lazy anonymous-page remapping via VMA page faults (default).
- `<pid> ondemand=0` force-populates anonymous pages immediately (eager mode).
- options can be combined, for example `<pid> ondemand=1 vma=8-12` or `<pid> ondemand=1 addr=0x7000-0x8000`.
- bind-then-map mode (single VMA at a time):
  - `bind=<pid>` binds the target process to this open `/dev/map` fd.
  - `map_addr=<addr>` maps only the single target VMA that contains `addr` from the bound target; lazy page population is default.
  - `map_addr=<addr> ondemand=1` does the same single-VMA map with lazy anonymous page remapping.
  - `map_addr=<addr> ondemand=0` force-populates anonymous pages for that selected VMA immediately.
  - `bind=<pid> map_addr=<addr>` binds and maps the containing VMA in one write.
- examples:
  - `echo "21780" > /dev/map`
  - `echo "21780 ondemand=0" > /dev/map`
  - `echo "21780 addr=0x700000000000-0x700000100000" > /dev/map`
- `echo "21780 vma=1,4,8-13" > /dev/map`
- `echo "21780 ondemand=1 vma=8-12" > /dev/map`
- `echo "bind=21780" > /dev/map`
- `echo "map_addr=0x700000000123" > /dev/map`
- `echo "bind=21780 map_addr=0x700000000123 ondemand=1" > /dev/map`

## Some Caveats
- This module is intentionally unsafe; it uses `MAP_FIXED` and can overwrite existing mappings in the calling process, potentially crashing it. It is recommended that the calling process binary is built statically to keep the amount of potential VMA collisions to a minimum
- File-backed VMAs are recreated via mappings;
- Anonymous VMAs preserve the target mapping type (`MAP_PRIVATE` vs `MAP_SHARED`) and are mapped “live” via page pinning/remap logic.
- Some special regions (for example `vvar`/`vdso`) can still fail to map depending on kernel restrictions.

## parameters
- `log_failures=0/1` (default `1`): print a kernel log line explaining each failed VMA mapping step.
- `live_anon=0/1` (default `1`): enable live mapping of anonymous VMAs via PFN remapping.
