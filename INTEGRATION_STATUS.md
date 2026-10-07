# Momentarius integration status

## A13, iOS 16.6 (20G75)

The Ghidra project `kernelcache.release.iPhone12,1` is the 20G75 kernelcache
(SHA-256 `0eaa1fa1ef14f5ff5cd8b9e9ee76fe9c5c4adfd8fd2da588cc0b0a022e56b7ea`).
Disassembly/decompilation confirms these `vm_map` fields used by Momentarius:

| Field | Offset | Evidence |
| --- | ---: | --- |
| `vm_map.pmap` | `0x40` | `0xfffffff007e7d408` loads this field from a map and passes it to `pmap_require`. |
| `vm_map.min` | `0x20` | `0xfffffff007e7d654` reads the lower map bound here. |
| `vm_map.max` | `0x28` | `0xfffffff007e7d654` reads the upper map bound here. |

Lara’s kernelcache report independently lists `task.map=0x28`,
`proc.fd=0xd0`, `filedesc.fd_ofiles=0x28`, `fileproc.fp_glob=0x10`, and
`fileglob.fg_data=0x38` for this image. `momentarius_a13_20g75_offsets_verified()`
therefore restricts the known profile to exactly `20G75` + `iPhone12,1` and
rejects altered Lara allocator offsets. This does not approve 20G81 (16.6.1),
other A13 devices, or A12.

Ghidra also confirms the pipe allocator's buffer-pointer offset for this image.
In `FUN_fffffff00820810c` (pipe read path), code loads the fileglob from
`fileproc + 0x10`, obtains the pipe object from `fileglob + 0x38`, and loads
its buffer pointer at `pipe + 0x10` (`*(long *)(puVar8 + 4)`). The same path
uses pipe fields at `+0x04`, `+0x08`, and `+0x0c` as the buffer size and
read/write positions; `FUN_fffffff00820806c` checks the pointer and those
indices. `momentarius/src/utils.c:kalloc_page()` now checks `pipe()`, allocation,
and exact 0x4000-byte `write()`/`read()` results, then rejects null/non-kernel
pointers in the fd-to-buffer lookup chain and closes the pipe on those failures.
This is source-level failure checking; it is not device validation of the
allocator layout or its behavior.

The A13 preflight now rejects failed/zero level-aware translations, unexpected
leaf levels, and a failed physical translation of the recovered PTE address.
This also fixes a guard that previously checked `l3_table_pte` a second time
instead of checking the newly computed `l3_table_pte_pa`. These checks run
before the graphics writer starts; they do not bound or recover a failure
after writer start.

The A13 source now also fails before writer start if the second graphics page
mapping fails, the detected patch sites fall outside the kernel text or cross
the mapped 16 KB page boundary, or creation of the PTE-waiter thread fails.
These checks prevent known pre-writer faults. They do not address the endless
writer/poller once it starts.

The 20G75 IOSurface initializer `FUN_fffffff009dafa78` handles the
`IOSurfaceAddressRanges` property by storing the ranges pointer at
`IOSurface + 0x3f8` and the range count at `IOSurface + 0x400`. These are
Ghidra-confirmed field offsets for this kernelcache. The IOSurface
`memoryDescriptor` pointer is supported at `+0x38` by the backing-object
allocation path described below. The descriptor's flags, memory reference,
size, ranges, range count, task, and wire-count offsets are also confirmed in
target disassembly; this establishes layout, not mapper safety.
The `IOSurfaceRootUserClient +0x118` assumption is contradicted by the
20G75 lookup trace below. The meanings of `IOSurfaceClient +0x40` and
`IOSurfaceSendRight +0x18` as the surface reference still need confirmation;
the latter is known to be an owned-object slot, but its referent is unknown.

The initializer was rechecked as a methodology cross-check: it reads the
`IOSurfaceAddressRanges` property and writes the resulting allocation/count at
`+0x3f8`/`+0x400`. It does not by itself verify the mapper's descriptor fields;
those were established through separate virtual-method analysis below.
Dopamine clears descriptor-relative slots `+0x70`, `+0x18`, and `+0x90`.
Ghidra identifies `+0x70` as the descriptor task pointer and `+0x18`/`+0x90`
as owned-reference slots. This does not establish that clearing them is safe
in the mapper's particular descriptor state.

A further Ghidra pass on 20G75 followed the `IOSurfaceAddressRanges` string
reference into `FUN_fffffff009db4ae0`, within the same large IOSurface
initializer. It confirms this is property parsing in the ranges/plane setup
path; it does not establish descriptor fields.

The IOSurface allocation path provides separate evidence for the descriptor
pointer slot. In `FUN_fffffff009db537c`, the default backing allocation calls
`FUN_fffffff0083c031c` with size/options/alignment arguments; it allocates and
initializes the registered `IOBufferMemoryDescriptor` class (instance size
`0xe8`). Its result is handed to `FUN_fffffff009db8890`, which stores the
retained object through the holder at `IOSurface + 0x38`. The IOSurface
constructor `FUN_fffffff009daf5f4` also initializes the corresponding holder.
This confirms the backing memory-descriptor pointer slot at `+0x38` for this
20G75 allocation path. Lara records it as
`LARA_MOMENTARIUS_20G75_IOSURFACE_MEMORY_DESCRIPTOR`. It does not establish
that the separate send-right field references the same IOSurface object.

A follow-up inspection of `FUN_fffffff009db70e4`, called after the address-range
initializer, found property-container and creation-property handling but no
`memoryDescriptor` assignment or descriptor-field access. The kernelcache has
no named IOSurface functions to use as direct search anchors, so this routine
does not close the remaining mapper-offset questions.

Ghidra class-registration code reports `IOSurfaceRootUserClient` size `0x138`
and `IOSurfaceSendRight` size `0x28`. Those allocation sizes alone do not
identify field meanings and do not confirm `IOSurfaceSendRight +0x18`.

The `IOSurfaceRootUserClient` lookup path gives stronger field evidence.
`FUN_fffffff009dd0728` calls `FUN_fffffff009dd05fc` with the root user client
as its first argument. That function bounds the surface ID against the count
at `rootUserClient + 0x108`, loads the pointer-array base from
`rootUserClient + 0x100`, and indexes the array by `surfaceId * 8`. This
confirms the lookup array/count pair at `+0x100`/`+0x108` for 20G75 and means
Dopamine's `rootUserClient + 0x118` lookup assumption must not be used for this
profile. The constructor `FUN_fffffff009dcb114` also zeros the `+0x100` pointer
and `+0x108` count. The separate field at `+0x118` remains unidentified.
Lara exposes the confirmed pair as
`LARA_MOMENTARIUS_20G75_IOSURFACE_ROOT_CLIENTS` and
`LARA_MOMENTARIUS_20G75_IOSURFACE_ROOT_CLIENT_COUNT` in `offsets.h`.

The same lookup validates that `IOSurfaceClient` is a `0x98`-byte class and
dereferences a pointer at `IOSurfaceClient +0x40`, but its subsequent `+0x28`
check does not by itself prove that this pointer is the IOSurface object
returned by Dopamine's helper. Keep that semantic mapping unconfirmed. The
`IOSurfaceSendRight` constructor initializes a pointer-sized field at `+0x18`
to null and its destructor releases/clears that field; this confirms an owned
object reference there, but not which object it references.

The 20G75 IOKit class-registration routine at `FUN_fffffff0083d42b8` registers
`IOMemoryDescriptor` with instance size `0x60`, `IOGeneralMemoryDescriptor` with
size `0xb0`, and `IOBufferMemoryDescriptor` with size `0xe8`. Class sizes are
only a sanity check; field meanings below are established by virtual-method
accesses in the target kernelcache.

Follow-up constructor/destructor inspection shows the IOGeneral constructor
initializes `+0x18` and `+0x90` to null and the destructor releases/clears them.
These are owned-reference slots; their exact source names and whether forcibly
clearing them is safe in the mapper's descriptor state are not established.

### `IOGeneralMemoryDescriptor` mapper fields

The 20G75 constructor `FUN_fffffff0083d3120` installs the object vtable at
`PTR_FUN_fffffff007957568`. Its virtual method `FUN_fffffff0083d26d8` reads
flags at `object +0x20`, ranges at `+0x60`, and range count at `+0x68`.
Additional virtual methods establish size at `+0x50` (`FUN_fffffff0083cc328`),
task at `+0x70` and a conditional memory-reference path at `+0x28`
(`FUN_fffffff0083d1944`), and wire count at `+0x88` (`FUN_fffffff0083d2368`
waits on this count during descriptor teardown). Lara records these offsets
as `LARA_MOMENTARIUS_20G75_IOMD_*` constants in `offsets.h`. The `+0x28`
field is identified as `_memRef` by matching its use to the memory-reference
branch and member order in Apple's nearby `xnu-8796.141.3` header. The device
kernel is `xnu-8796.142.1`; that source is semantic corroboration only, while
the byte offsets are from target disassembly. Confirming offsets does not
establish that Dopamine's direct field mutations are safe for Lara's mapper.

The public Apple XNU tag `xnu-8796.141.3` has matching
`IOGeneralMemoryDescriptor` and `IOBufferMemoryDescriptor` definitions and
member order, and is useful for interpreting the Ghidra accesses. The device
kernel identifies as `xnu-8796.142.1`, so that nearby source tag is semantic
cross-reference only; the byte offsets above come from 20G75 disassembly.
Whether the direct field mutations are safe in the mapper's required object
state remains unresolved.

### `pmap` layout evidence

In 20G75 `FUN_fffffff0084b4b34` (`pmap_remove_options_internal`), the first
word of the pmap is dereferenced as the software page-table walk root. The
same function reads pmap-relative lower and upper bounds at `+0x10` and
`+0x18`; it takes the pmap lock at `+0x28`. This establishes the surrounding
layout for this kernelcache:

| Offset | Current interpretation | Evidence |
| ---: | --- | --- |
| `+0x0` | Software page-table walk root (KVA) | Used as the root for indexed table-entry loads in `FUN_fffffff0084b4b34`. |
| `+0x8` | `ttep` | Loaded by `pmap_switch_internal` and written to `TTBR0_EL1` after ASID bits are added. |
| `+0x10` | Lower pmap bound | Read in `FUN_fffffff0084b4b34`. |
| `+0x18` | Upper pmap bound | Read in `FUN_fffffff0084b4b34`. |
| `+0x28` | Pmap lock | Passed to the lock operation in `FUN_fffffff0084b4b34`. |

The same 20G75 `pmap_remove_options_internal` decompilation confirms the
kernel's 16 KB table-walk indices: L1 uses `(va >> 36) & 7`, L2 uses
`(va >> 25) & 0x7ff`, and L3 uses `(va >> 14) & 0x7ff`. It converts table
descriptor physical addresses with `FUN_fffffff007ee0f34` before dereferencing
the next level. This verifies the index layout for a software walk, but is not
runtime validation of a Lara implementation.

The `+0x8` field is confirmed as the TTEP for 20G75. In
`FUN_fffffff0084b4684` (`pmap_switch_internal`), Ghidra shows `param_1` is the
pmap argument and the function eventually enters `FUN_fffffff0084b489c`.
That function loads `[param_1 + 0x8]`, combines the ASID bits from
`param_1 + 0xb4`, and passes the result to `FUN_fffffff0084a9884`, whose
disassembly writes its argument to `TTBR0_EL1`. This directly identifies the
pmap field consumed as the translation-table base on this kernelcache.
Lara exposes this verified value as
`LARA_MOMENTARIUS_20G75_PMAP_TTEP` in `lara/kexploit/offsets.h`; this is only
an offset fact and does not enable or call the Momentarius walker.

A search of the 20G75 instruction stream found a `TTBR1_EL1` write at
`0xfffffff007d88480`. Its source is `x0`, calculated immediately beforehand
from `x25 + 0x4000` and masked; this is an early translation setup path and
does not load `pmap + 0x8`; it is unrelated to this pmap-field confirmation.

## Experimental Lara test wiring and remaining blockers

Lara now has an experimental Tools entry, `Run Momentarius A13 test`, gated to
the exact iPhone12,1 / 20G75 profile and DarkSword readiness. The Momentarius
sources are included through the Xcode filesystem-synchronized group, with the
adapter and IOSurface framework linked. The action runs the A13 init routine;
it is not a production toggle and must not set `momentariusready`.

The adapter provides ABI wrappers for the Lara read/write helpers and the
translation functions, plus an IOSurface mapper using the 20G75 field table.
That mapper is source-level only. The IOSurface send-right-to-object lookup
(`send_right + 0x18`) and descriptor mutation/lifetime assumptions have not
been independently runtime-verified. Normal-return cleanup checks its writes
back before releasing tracked ports/surfaces; if restoration cannot be
verified, it retains those references and reports cleanup failure. This is
not proof of recovery from a crash or a stalled writer.

The A13 init still has an unbounded graphics-cacheline writer and PTE poll.
If it stalls, force-restart the device. No timeout or reliable mid-init
rollback has been implemented. The current Lara kernel-write wrappers are not
an independent verification of Momentarius' physical PPL-write primitive, so
the Tools action reports only that init returned; it does not report a probe
pass and leaves `momentariusready` false. Reboot before another attempt.

The pipe allocator has source-level checks for syscall results and pointer
chains, and the read-only translation diagnostic passed one kernel-image
round-trip on the user's iPhone12,1 / 20G75. The allocator has not been
runtime-validated, and the translation PA has no independent oracle. The
offsets in this report remain static analysis, not general device validation.
Do not enable any user-facing Momentarius capability until independent
physical-write verification, allocator validation, and a recoverable failure
path are established.

### Read-only device diagnostic

Lara now exposes `lara_momentarius_20g75_translation_diagnostic()` in Tools
when DarkSword reports ready. It uses the verified `kernproc -> task -> map ->
pmap` chain, walks the kernel image VA with the new software walker, translates
the resulting PA back to a KVA, and reports the root, VA, PA, PTE KVA, and
round-trip result. This path only calls kernel reads; it never calls Momentarius
init or writes kernel memory. A round-trip pass is a smoke check, not independent
validation of the PA. The first run failed at stage 5 because the raw integer
reader retained PAC bits in `task.map`; the helper was corrected to use
`ds_kreadptr()`, then passed on the iPhone12,1 / 20G75 device. Do not use that
smoke check as a Momentarius readiness signal.

The first device screenshot confirms the Tools entry is reachable on
iPhone12,1 / 20G75 with DarkSword reporting kernel R/W ready, but the diagnostic
returned its generic fail-closed message. The report now includes a numbered
failure stage, the observed offsets, and any addresses reached before failure
so the next run can identify whether the profile gate, proc chain, page walk,
or reverse mapping failed. No Momentarius init or kernel write was performed.
The captured run failed at stage 5 because `task.map` was read with the raw
integer reader and retained PAC bits (`0xfdea...`), so it was rejected as a
noncanonical pointer. The diagnostic now uses Lara's `ds_kreadptr()` to strip
PAC from `task.map`, `vm_map.pmap`, and the software-walk root before using
them. Rebuild and rerun the diagnostic to continue the read-only check.

The next iPhone12,1 / 20G75 run passed the read-only round-trip diagnostic:
kernel image VA `0xfffffff0225cc000` walked to PA `0x8045cc000` at L3, with
PTE KVA `0xfffffff022e90b98`; Lara's PA-to-KVA helper returned the original
VA. This is runtime evidence that the proc/map/pmap chain, L3 walk, and reverse
map work together for this kernel image address on this device. It is not an
independent physical-address oracle, does not validate other virtual addresses
or profiles, and is not a Momentarius readiness probe.

The vendored common init rejects every profile except iPhone12,1 / 20G75 before
doing any mapping, no longer dispatches to the A12 implementation, and fixes
two preflight checks that previously rechecked the proc/map pointer instead of
the task/pmap pointer. Its IOSurface mapping helpers reject a failed mapping
result or null address. Lara now has experimental source wiring for this path,
but no Xcode build or new device run has verified it.

The pipe allocator now caps the number of retained allocator pipes and records
their file descriptors after a successful buffer lookup; init failure cleanup
closes those tracked descriptors. This fixes an unbounded fd leak across failed
preflight attempts while preserving successful pipe buffers for their required
lifetime. It remains unvalidated on-device and does not change the exploit's
graphics writer or failure-recovery behavior.

## Upstream reference

Dopamine integrates Momentarius through its exploit `init`/`deinit` interface
and supplies the kernel primitive/runtime dependencies that this standalone
snapshot lacks. Useful pinned references are:

- [Dopamine `momentarius cleanup` commit `3d8dd72`](https://github.com/opa334/Dopamine/commit/3d8dd72), including its Momentarius changes.
- [Dopamine A13 implementation on the 3.x branch](https://github.com/opa334/Dopamine/blob/3.x/Application/Dopamine/Exploits/momentarius/momentarius_a13.c).
- [Dopamine common init/deinit implementation](https://github.com/opa334/Dopamine/blob/3.x/Application/Dopamine/Exploits/momentarius/momentarius.c).
- [Original Momentarius repository](https://github.com/staturnzz/momentarius).

The referenced Dopamine A13 code retains the same unbounded `wait_for_pte()`
and repeated graphics-cacheline writer. On the successful path,
`wait_for_pte()` writes the original `cmp x1, #0` instruction back to the hook
location through that writer, waits 100 ms, and only then sets `stop_write`.
Thus, the hook instruction is restored during successful init; it is not
restored by `momentarius_deinit()`. The latter restores `target_rw_pte` and
frees host buffers, but does not restore the remaining graphics-side code/data
written by the init path.

Dopamine calls exploit cleanup in the same boot after building its physical
RW primitive, and also on a post-exploitation failure path. This shows that
the deinit path is used without requiring a reboot. It does not establish that
all graphics modifications are reverted or explain how to unwind if the PTE
poll never reaches its success branch. Because that branch performs the hook
instruction restoration, a timeout cannot simply stop the writer and return;
the timeout path would need a verified restoration sequence of its own.

The A13 writer copies these lengths on every iteration:

| Mode | Shellcode area | TTBR1-load area | Hook area |
| --- | ---: | ---: | ---: |
| v1 | `0x48` bytes | `0x8` bytes | `0x4` bytes |
| v2 | `0x28` bytes | `0x10` bytes | `0x4` bytes |

The hook area is initialized from the branch shellcode and then changed back to
the matched `cmp x1, #0` instruction on success. The source does not snapshot
the pre-init contents of the shellcode or TTBR1-load areas. The fixed shellcode
location (`0x2000`) is described as "seems like 0x2000 is always usable" rather
than checked against an original-data/unused-region invariant. So an unwind
design must first establish what state at those ranges is safe to preserve and
restore; copying the current generated buffers back would reapply the patch,
not undo it.

## Timeout constraint

The desired PTE condition is checked by `wait_for_pte()` while the graphics
cacheline writer is running; the writer is what applies the TTBR/shellcode/hook
changes that can make that condition true. Therefore a timeout cannot detect
failure *before* those writes. A preflight can reject known-bad builds, invalid
translations, failed allocations, and missing patchfinder signatures before
starting the writer, but it cannot guarantee the graphics/PTE transition will
succeed. Any deadline after writer start must be treated as a fatal,
reboot-required outcome unless a separately verified recovery mechanism is
found. It must never set `momentariusready` or allow continued use of the
current session as though initialization failed cleanly.

The common init now records `CLOCK_MONOTONIC` immediately around the A13 init
call and emits elapsed milliseconds only after a successful return. This is
instrumentation only: it does not change the poll or writer control flow, does
not bound init, and cannot produce a measurement while init remains blocked.
Collect several successful 20G75 runs before selecting a timeout and margin.

## Lara build/adapter gap

The Xcode project has a filesystem-synchronized source root for `lara/` and now
includes `momentarius/` as a synchronized source group with the vendor include
path. `lara/kexploit/momentarius_adapter.m` supplies the expected mapper and
translation ABI wrappers. This is experimental wiring only: no Xcode build or
device run has verified source membership, link success, mapper behavior, or
the full init path. The init timer is now reachable through the Tools test
button if the app builds, but produces a duration only after successful
return; a stalled init remains unbounded.

The Lara translation helper declarations are intentionally not ABI-compatible
drop-in replacements for `momentarius/include/utils.h`: Lara returns `bool`
and writes outputs through pointers, while Momentarius expects direct integer
returns; Lara's `kvtophys` also requires an explicit software-walk root, while
Momentarius calls it with only a VA. The source adapter wraps those interfaces
and fails closed on translation failure. It has not yet been validated by an
Xcode build or on-device test.
The root mismatch was corrected in the vendored source: common init reads
the PAC-stripped software-walk root from `pmap + 0x0` into `kern_tte`, and both
A13 `vtophys_lvl` calls pass that KVA root. `kern_ttep` remains the physical
TTBR value at `pmap + 0x8`. The adapter converts Lara's PTE KVA output to the
PTE PA Momentarius expects, then lets the existing `phystokv` call map it back.
The conversion is source-level only and needs build/runtime validation.

The local `reference (dopamine)` copy provides
`BaseBin/libjailbreak/src/primitives_IOSurface.m` and `translation.c`; its
`BaseBin/XPF` submodule directory is empty. Lara already implements
`task_get_ipc_port_kobject()` in `lara/kexploit/utils.m`, so that lookup helper
does not need a new port. The remaining mapper dependency is the physical
surface setup and verified object layout: Dopamine reads and mutates
`IOMemoryDescriptor` fields at fixed offsets and assumes exact
IOSurface/IOMachPort layouts.
Dopamine's `info.c` initializes `IOSurface.memoryDescriptor` to `+0x38` for
iOS 16, then changes it to `+0x40` for iOS 17 and `+0x30` for iOS 17.4+.
The 20G75 allocation path independently confirms the `+0x38` pointer slot;
Ghidra also confirms descriptor flags at `+0x20`, memory reference at `+0x28`,
size at `+0x50`, ranges/count at `+0x60`/`+0x68`, task at `+0x70`, and wire
count at `+0x88`. These findings confirm structure offsets only; they do not
verify the mapper's object lookup chain or mutations.

The mapper's translation call site is narrower than a general physical-memory
API: when `krwMinSafeReadSize > 0x10`, it converts the userspace `fakeRanges`
buffer VA to a PA and then to a kernel VA so it can point the descriptor at
that buffer. With a primitive that can directly write the two range entries,
the mapper takes its other branch and does not call `vtophys`/`phystokv`.
Lara's `ds_kwrite64` may support that direct-write strategy, subject to the
verified descriptor layout and a safe, checked mapper implementation.

That does not remove Momentarius's own translation dependency. In the A13
path, `kvtophys` supplies physical addresses for allocated page-table pages,
and `phystokv` converts page-table physical addresses back to kernel VAs.
`vtophys_lvl`'s return value (the translated PA) is ignored at both call
sites. Momentarius sets the requested leaf level to 3 and uses the
`leaf_tte_ttep` output as the address of the L3 PTE; it then reads the PTE
descriptor itself with `kread64`. Thus it needs the PTE's address, not the
translation return value or a returned descriptor/flags value. A plain
`pmap_find_phys` result cannot substitute for this output without another way
to derive the page-table entry address. See `momentarius_a13.c` around the
allocations and PTE setup. The specialized
`PurpleGfxMem` path in Lara's `darksword.m` maps its own contiguous surface and
uses memory-object/OOB operations. It does not expose arbitrary PA-to-kernel-VA
or kernel-VA-to-PA translation and cannot directly substitute for those A13
operations. Lara's new translation helper completed a read-only 20G75 smoke
round-trip on the user's iPhone12,1 for the kernel image VA. This confirms that
one VA translated and mapped back to itself during that run. It does not
independently validate the reported PA or establish the exact PTE-PA semantics
Momentarius expects from its adapter.

Ghidra's named-symbol search of the 20G75 kernelcache found no entries for
`kvtophys`, `phystokv`, or `vtophys_lvl`; it also found no named
`pmap_find_phys` entry. These three names are Dopamine/libjailbreak translation
helpers implemented in userspace `translation.c`, not expected XNU kernel
exports. So their absence does not indicate stripping or inlining from this
kernelcache, and adding their addresses to Lara's static kernel offset table
would be the wrong integration. Lara now has an exact-profile software walker
source using its own kernel reads and the Ghidra-confirmed TTE index layout.
The user's device reported a read-only smoke pass for the kernel image VA:
root `0xfffffff022e88000`, VA `0xfffffff0225cc000`, PA `0x8045cc000`, PTE KVA
`0xfffffff022e90b98`, and reverse KVA `0xfffffff0225cc000`, at level 3. The
round-trip is internally consistent, but the PA has no independent oracle yet
and the PTE KVA has not been compared with an independent page-table walk.
Treat this as preliminary runtime evidence, not validation for exploit use.

The root source differs by helper. Dopamine's generic `kvtophys()` calls
`vtophys(kconstant(cpuTTEP), va)`; `info.c` sets `cpuTTEP` by reading the
kernel global at `ksymbol(cpu_ttep)`. In contrast, `vtophys_lvl()` takes its
root as an argument. Momentarius's common init now obtains the PID 0 task,
then map, then pmap and reads `pmap + 0x0` as the software-walk root passed to
`vtophys_lvl`; it separately reads `pmap + 0x8` as the physical TTEP. Lara has
`procbypid(0)`, `proc_task()`, and `off_task_map` for the same chain, and its
read-only diagnostic uses the `+0x0` root. The `+0x8` field is Ghidra-confirmed
as the TTBR value on 20G75, but the current Momentarius adapter still must
translate Lara's returned PTE KVA to the PA expected by Momentarius before
calling `phystokv`. The one-VA smoke result does not validate that ABI boundary.

For a Lara walker based on `ds_kread64`, distinguish the two pmap roots:
`pmap + 0x0` is the KVA software-walk root and can be read through Lara's
kernel-read primitive; `pmap + 0x8` is the physical TTBR root. A walk starting
from the KVA root still encounters physical table addresses in valid table
descriptors, so each next-level table needs a verified PA-to-KVA conversion.
Using `+0x8` directly as a `ds_kread64` address would be incorrect. The runtime
smoke pass exercises one translation and reverse map, but not enough independent
cases to qualify the walker for PPL-bypass initialization.

Ghidra decompilation of `FUN_fffffff007ee0f34`, the kernel's PA-to-KVA helper
used by `pmap_remove_options_internal`, shows it first searches an eight-entry
runtime `{ PA base, KVA base, length }` table, then falls back to
`physBase`/`virtBase` plus a physical-range size check. Lara now has a
read-only, exact-profile adapter in `lara/kexploit/momentarius_translation.m`
for that conversion. Its 20G75 global RVAs from this kernelcache are:

| Global | RVA from `0xfffffff007004000` | Use |
| --- | ---: | --- |
| Physical range map | `0x8ff8e0` | Eight `{ PA base, KVA base, length }` entries. |
| Physical base | `0x94c2c8` | Fallback translation base. |
| Virtual base | `0x94a480` | Fallback translation base. |
| Physical range size | `0x8ff9a0` | Bounds the fallback range. |

The helper fails closed on other build/device profiles and non-kernel output
addresses. The user's read-only smoke run exercised its reverse mapping for
one kernel-image PA. The adapter now connects the helper to Momentarius source,
but it has not been build- or runtime-validated. The companion `kvtophys` and
level-aware walker have one on-device smoke case, not independent validation
across addresses or an independent PA oracle.

Lara does have `kernelStruct.IOSurface.ranges` support in newer XPF source, but
the bundled `lara/lib/libxpf.dylib` contains no IOSurface resolver identifiers
(checked for `kernelStruct.IOSurface.*`). The current `resolvekernoffsets()`
also requests only `base`, `translation`, and `struct` sets. Thus adding a
runtime check around the existing bundled resolver cannot currently produce
verified IOSurface range offsets. The local Dopamine copy contains no built
`libxpf` replacement or populated XPF sources to link instead.

The Tools test entry intentionally exposes only an experimental init attempt
for iPhone12,1 / 20G75. It does not set `momentariusready`: init returning is
not a PPL-write readiness probe. Remaining blockers are the unbounded poll,
no validated crash/failure recovery, no independent PPL physical-write probe,
and no device validation of the IOSurface mapper or pipe allocator. Do not
describe this as production-ready or as a successful PPL bypass until those
checks are completed. Xcode build validation has not been run in this Windows
workspace.
