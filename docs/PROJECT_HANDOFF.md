# PROJECT HANDOFF — p2jb / poopsploit host + the Bagagwa-on-13.60 effort

**Audience:** the next engineer or AI agent picking this up cold.
**Written:** 2026-09-16, at commit `ab97584`.
**Rule of this document:** every claim is tagged. Do not promote a tag.

| tag | meaning |
|---|---|
| **VERIFIED** | measured on real PS5 hardware, evidence is in §10 |
| **DERIVED** | derived by static reasoning, reproducible, not yet measured |
| **UPSTREAM** | copied from a public repo; cite it, do not trust it |
| **UNKNOWN** | nobody knows yet |

---

## 0. WHERE TO RESUME — read this first

The state of play in five lines:

1. The **WebKit/userland half works on 13.60** and its ROP syscall executor is fully
   calibrated and hardware-verified (§10). This is genuinely new; no public repo has a
   working 13.60 executor for this engine.
2. **The Bagagwa syscalls exist on 13.60.** `aio_multi_wait` (syscall 663) answers
   `EINVAL`, **not** `ENOSYS`. The bug is therefore *reachable in principle*.
3. **The ABI is measured on 13.60 hardware** (§11.7): `(ids, num, states, mode, timeout)`.
4. **The arming step HAS now run once on 13.60** (11:21 run, §12.4): `aio_submit_cmd`
   produced two LIVE pending requests (the request layout and encoding work!), but the
   armed `multi_wait(num=2)` hit EFAULT because states was NULL — it never reached the
   linking code. The states fix is committed; **the next ARM run is the first one that
   genuinely tests the bug.**
5. **Read §12.4 first** — it records what the ARM run taught and the P2JB/poops tile
   (T2c). The DO-NOT-DO list (§13) grew two entries.

**Nothing in this repo writes kernel memory on 13.60.** Keep it that way until §12 is
done and the operator has explicitly approved the arming step (§13, "do-not-do").

---

## 1. What this project is

A **static website** that runs on the PS5's built-in browser and jailbreaks the console.
No build step. Two independent exploit chains share one boot:

| entry | firmware | technique | state |
|---|---|---|---|
| Poopsploit | 9.00 – 12.00 | IPv6 `rthdr` UAF | works (upstream) |
| P2JB | 12.00 – 12.70 | `cr_ref` overflow via `kqueueex`, ~1 h leak | works (upstream) |
| **Syscall test** | **13.00 – 13.60** | *nothing kernel-side* — measures reachability only | **VERIFIED working** |

12.00 is the only firmware both upstream chains cover. 13.60 is the firmware the operator
actually owns, and it is the firmware both upstream chains are patched on. So the entire
13.60 effort is: **establish that the kernel path still exists, then arm a new bug
(Bagagwa) on it.**

---

## 2. Repositories, remotes, hosting

`pooP2JB/` is **its own git repo**, nested inside the workstation workspace.

```
origin  https://github.com/soniciso1/pooP2JB     (upstream, WE DO NOT PUSH HERE)
bwslop  https://github.com/badrcoderman/bwslop   (ours, public, PUSH HERE)
```

* Live site: **https://badrcoderman.github.io/bwslop/**
* Branch `main`. `gh` CLI is authenticated as `badrcoderman`.
* GitHub Pages is enabled from the branch root. `.nojekyll` is required and present —
  without it Pages runs Jekyll and silently drops `_`-prefixed paths.
* **Deploy = push to `bwslop`.** Pages rebuilds in ~25 s. Verify with:
  `gh api repos/badrcoderman/bwslop/pages/builds/latest --jq '.status+" "+.commit[0:7]'`
* Recent commits (newest first): `ab97584` ABI map, `6bd29bb` errno convention,
  `2da50f2` calibrate picker fix, `52b6269` slot_expect calibration, `eccf280` probe
  hardening, `91f6354` 13.60 userland + payload menu.

There is a **second, private-looking repo referenced by the operator**,
`github.com/OzRviju/bagagwa-exploit` — a slopkit fork that stops at 12.00. Its offset
table is dangerous (§11.5). Do not port its numbers.

---

## 3. Workstation layout — what matters and what does not

Workspace root (not a repo, or rather *a* repo with a huge mixed history):

```
pooP2JB/        ← THE project. Everything we changed lives here.
analysis/       ← our own deep-dive notes (see §4)
noslop/         ← separate slopkit-style toolkit; supplied the unverified 13.60 userland
                  candidate table (noslop/offsets/offsets.json)
slopkit2/       ← reference WebKit chains, incl. the 13.20 profile
slopkit-main/, slopkit-webkit-exploit-main/, slopkit/   ← more upstream copies
ps5-libs/, research_12_00/, backup/                     ← archives, ignore
zecoxao.github.io/, session-ses.md                      ← archives, ignore
```

**Where the 13.60 offsets originally came from**, in order of trustworthiness:

1. `pooP2JB/offsets/13.60.js` — the one that actually runs (**VERIFIED** for the layer it
   covers; see §7).
2. `noslop/offsets/offsets.json` — `"13.60": {"source": "local-unverified-candidate"}`.
   Its own metadata says *"runtime verification is mandatory"* and *"No static PS5 13.60
   kernel offsets are supplied."* It carries `hc`, `gd`, `nt`, `gps`, `gpe`, `cls`, `cle`,
   `ers`, `ere` — the same nine names the X1NON-PSJB 13.60 file lists at its bottom.
3. `X1NONs/Bagagwa_chain` → `slopkit2-13.20.js` — userland only.
4. `X1NONs/X1NON-PSJB` → `offsets/13.XX/13.60` — userland + libkernel_web + gadget map +
   syscall stub map. **Useful, but see the two traps in §8.**
5. `X1NONs/X1NON-PSJB` → `offsets/kernel/data.js` — **A TRAP. Do not paste it in.** §8.3.

---

## 4. Prior written analysis (read these before re-deriving anything)

All in `analysis/`:

| file | what it is |
|---|---|
| `psaito-bagagwa-chain-findings.md` | **most current.** Bagagwa chain vs the writeup, all four public implementations, now includes the 2026-09-14 PSAITO UAF payload analysis |
| `bagagwa-1360.md` | the 13.60-specific plan |
| `bagagwa-conversion.md` | the osem conversion path + the waker primitives |
| `bagagwa-integration-plan.md` | how Bagagwa would be wired into this host |
| `pooP2JB-deep-analysis.md` | the host itself, stage by stage |
| `ps5_fw12_deep_analysis.json` | 299 KB of 12.00 kernel RE |

---

## 5. Architecture — the boot chain, file by file

`index.html` (landing, picks firmware from the UA) → `p2jb.html?go=1&…` → boot:

```
core.js          WebKit primitive (lapse-runtime style). Gives addrof/fakeobj/read/write.
int64.js         BigInt helpers used by core.js
mem.js           memory helpers
main.js          firmware gate + prepare(p) + WebKit base derivation
   ↓ prepare(p) publishes window.POOPS
   ↓ then, in p2jb.html's handoff block (~line 2082):
rop-worker.js    the synchronous ROP executor  ← THE crown jewels, read §6
p2jb_lk.js       per-firmware libkernel_web RVAs for rop-worker
p2jb_poops.js    Y2JB adapter; defines window.syscall / read64 / write64 / malloc / …
   ↓ branch on the query string:
   &sc=1  → bagagwa_probe.js   (the Syscall test entry)   ← ADDED BY US
   else   → p2jb.js            (the real kernel exploit)
```

Supporting files: `p2jb.js` (kernel exploit, 4497 lines), `poops.html`/`poops.js` (the
other chain), `syscalls.js` (331-entry number→stub map), `rop.js`, `rop_slave.js`,
`preflight.html`, `ui/`, `api/`, `payloads/` (ELF payloads, ~16 MB).

**`bagagwa.js` (256 lines) is NOT part of the boot chain.** It is a pre-existing,
unfinished 13.60 **kernel-stage scaffold** that documents the correct ids-first ABI and a
`KERNEL_OFFSETS_NEEDED` list. It never runs. Read it as a spec, not as code.

### 5.1 The one-line hook that adds all 13.60 support

`main.js` has `const supportedFirmwares = [...]` and throws
`no offsets for fw <fw>` before anything else runs. `"13.60"` was added there. That is the
gate that made the userland half possible at all. `offsets/13.60.js` is loaded from
`main.js`'s tail: `fwScript.setAttribute('src', 'offsets/'+fw_str+'.js?v=129')`.

### 5.2 Cache-busting convention — easy to get wrong

Every `<script>`/link carries `?v=NNN`. The engine files (`core.js`, `poops.js`,
`rop-worker.js`, `p2jb.js`, `p2jb_poops.js`, `main.js`, `offsets/*.js`) are pinned at
**`v=128`** in `p2jb.html`/`index.html` and have never been bumped. The files we touched
are at **`v=134`**:

* `index.html` — the `P2JB` link and the `Syscall test` link
* `p2jb.html` — the `bagagwa_probe.js?v=134` script tag

`tools/bump-version.py` exists. **If you edit an engine file, bump the `v=` on the files
you touched** — this is exactly the stale-cache trap `p2jb.html` warns about in its own
comments. A correct code change that never reaches the console is the single most
expensive mistake available here.

---

## 6. The syscall executor (`rop-worker.js`) — understand this before touching anything

This is what makes 13.60 measurable at all. Read `rop-worker.js` in full; the summary:

### 6.1 How it works

* The page's own worker thread is **parked in a kernel condvar**
  (`pthread_cond_wait`, libkernel_web+0x3E1D0 region).
* `resolveSlot()` scans the top `0x8000` of that worker's `0x80000` stack for a qword
  equal to `kbase + slot_expect`, frame-validated (cond_wait's callee pushes `rbp` first,
  so the qword at `candidate-8` must be a stack address inside the stack, above the
  candidate, 8-aligned).
* It overwrites that return address with `pop rsp`, then `chain` — hijacking the worker's
  resume.
* `fireSync()` builds a chain, writes it to `W.chainBuf`, stores `W.retval = 0`, fires,
  and **busy-polls** `W.retval` from the main thread. The main thread never yields, which
  is why `setjmp`/`longjmp` and a spin cap replace any async watchdog.

### 6.2 `syscallSync` is a raw syscall, and that has a consequence

```js
c.pop("rax", BigInt(num)).call(g("syscall_wrapper"));
c.pop("rdi", W.retval).raw(g("mov_qword_rdi_rax"));
```

`syscall_wrapper` is **`49 89 ca 0f 05 c3` = `mov r10,rcx; syscall; ret`** (from
`p2jb_lk.js`, confirmed in `p2jb_poops.js` as `libkernel_web+0x1AE27` on 12.00, the tail of
the `_umtx_op` stub). It is a **bare svc shim with no `-1` conversion**.

Two load-bearing consequences:

1. **Per-syscall stubs are not used.** The number goes in `rax` and one shared wrapper is
   called. Therefore `syscalls.js`'s 331-entry `syscall_map` is *decorative for this
   executor*, and — critically — **any syscall number is callable, including 727**, which
   has no libkernel wrapper at all. PSAITO's stub-mode engine *cannot* call 727. We can.
2. **A small positive `rax` is ambiguous.** On FreeBSD's raw ABI the errno is left *in*
   `rax` and failure is signalled by `CF`, which `syscall; ret` neither clears nor
   exports. So `0x16` means EINVAL, but `0x9` *could* be a value. This ambiguity produced
   a real bug (§9.1) and is now handled explicitly.

### 6.3 Register order for the syscall instruction

`rop-worker.js` pops `rdi, rsi, rdx, rcx, r8, r9`; the wrapper moves `rcx → r10`. So
syscall arguments 1–6 are **rdi, rsi, rdx, r10, r8, r9** — the FreeBSD convention, not the
Linux one. When you describe "argument 4" in this project, you mean **r10**, reached by
popping `rcx`.

### 6.4 The public API (all synchronous)

```
window.syscall(nr, a1..a6) -> BigInt retval
window.read64(addr) / window.write64(addr, val)
window.malloc(size) / window.write_buffer(ptr, u8) / window.read_buffer(ptr, n)
window.alloc_string(s)
window.rop_worker.state = { kbase, wbase, stack, stacksz, slot, ctx, retval, fired, dead }
window.flushMark(k, v) / window.syncMark(k, v) / window.send_notification(s)   // logging
window.P2JB_LK[fw] = { thread_list, syscall_wrapper, setjmp, longjmp, pthread_create, slot_expect }
```

`P2JB_LK[fw]` is passed **by reference** into the executor (`lk: lk || {}`), so mutating a
row at runtime reaches `W.lk` with no re-init. The calibrate tile relies on this.

---

## 7. `offsets/13.60.js` — what it carries and what it deliberately does not

Carries the **WebKit + libkernel_web + libc** layer (**VERIFIED**, since it boots and
every syscall works):

```
OFFSET_wk_host_constructor_candidates  [0x56A58, 0x56CA0, 0x57CE8]
OFFSET_wk_vtable_first_element         0   ← "needs a console"
OFFSET_wk_memset_import                0x03350850
OFFSET_wk___stack_chk_guard_import     0x0334E198
OFFSET_wk_getpid_slot 0x0334E238  exp 0x1B860
OFFSET_wk_close_slot  0x0334E228  exp 0x274E0
OFFSET_wk_error_slot  0x0334E230  exp 0xF7D0
OFFSET_lk___stack_chk_guard            0x000751D0
OFFSET_lk__thread_list                 0x0006C218
OFFSET_lk_worker_wait_return           0x0001FD01
OFFSET_lk_pthread_create_name_np       0x00021890
OFFSET_lk_pthread_join / _exit / sleep / sceKernelGetCurrentCpu
OFFSET_lc_memset 0x14700 / setjmp 0x5D990 / longjmp 0x5D9E0
OFFSET_WORKER_STACK_OFFSET             0x0007FB88
+ a 331-entry syscall stub map
```

**`OFFSET_KERNEL_*` is absent on purpose** (as in `13.00.js`/`13.20.js`). Those four data
offsets are needed only by stage6's allproc check and the kexp resolver, and **stage6
degrades gracefully without them**. 13.60's userland therefore runs and the executor
works while neither `poops.js` nor `p2jb.js` can reach kernel memory. That is not a
half-finished state; it is a deliberate boundary.

⚠️ `OFFSET_wk_vtable_first_element = 0`. `main.js` **throws** if the WebKit base cannot be
resolved and this is 0 — so on 13.60 the base must have come from the
`__ps5NativeCtor` global. If a future run throws
`has no OFFSET_wk_vtable_first_element and __ps5NativeCtor was absent`, the
host-constructor path broke; it is **not** an offsets-table problem.

⚠️ **`thread_list` conflict.** `Bagagwa_chain`'s 13.40 profile says `0x64218` (its own
comment admits "carried forward by assumption"). PSAITO says `0x6C218` for 13.60.
X1NON-PSJB's 13.60 file publishes `0x75258` as primary and **comments out `0x6C218` as a
fallback** — the inverted ordering is suspicious. **Our hardware run used `0x6C218` and
`find_worker()` succeeded end-to-end**, so the *commented-out* value is the one with
evidence and the published primary has none (§10).

---

## 8. Traps — things that look helpful and are not

### 8.1 Filename traps

`payloads/` ships `elfldr-ps5-1360.elf`. The **name** suggests 13.60 support. It is a
filename, not a capability. Same class of trap as `offsets/kernel/data.js` (§8.3).

### 8.1.1 **Calling an unproven syscall number WEDGES the kernel** (hardware lesson)

T0's first draft ended with `syscall 0x7FF` expecting ENOSYS. On real 13.60 the kernel did
**not** return ENOSYS — it stopped answering: the call spun out `fireSync`'s cap (~64 s of
page freeze) and three consecutive runs died at exactly that call. The textbook assumption
"out-of-range ⇒ ENOSYS" does not hold on this kernel path.

Rules that now stand (enforced by `tools/test_convention.mjs` scenario 6b):

* **Never call a syscall number that has not been proven to exist on this firmware** —
  either by being in the native stub map or by having answered on hardware.
* **Every tile that can misbehave ends with a canary call** (getpid): if the canary does
  not answer, the kernel wedged and NOTHING may be concluded — the verdict says so instead
  of guessing.
* The ENOSYS encoding is **inferred** from the measured convention, never "measured"; the
  verdict text keeps that wording honest.
* The kernel model in `test_convention.mjs` latches `wedged` and answers
  `WEDGED-BEFORE:` forever — any regression reintroducing an unproven call fails CI here
  instead of freezing a console.

### 8.2 `offsets/kernel/data.js` (X1NON-PSJB) — do not paste it in

```js
OFFSET_KERNEL_DATA 0x00CB0000  ALLPROC 0x03589E80
SECURITY_FLAGS 0x01A49064      ROOTVNODE 0x03DE7510   BUS_DATA_DEVICES 0x02D481E8
```
File header claims "13.40 … cross-verified against 12.70". It is **not a coherent set**:
`ROOTVNODE 0x03DE7510` matches **11.00–11.60 exactly**, while `DATA`/`ALLPROC`/
`SECURITY_FLAGS` match **no** firmware in this tree (11.x would need `DATA 0x00D30000`,
`ALLPROC 0x035A5D70`). Its sibling `offsets/bagagwa/` is elsewhere a 1-byte placeholder.
**Conclusion: nobody has published 13.60 kernel offsets.** They must be derived from a
13.60 kernel image. This is already documented in `offsets/13.60.js` — do not "fix" the
absence.

### 8.3 The struct table disagrees with `p2jb.js` — and that silently corrupts

`X1NON-PSJB/offsets/structs/offsets.js` is content-identical to OzRviju's table, and six
fields disagree with `p2jb.js` (which hardcodes them as firmware-**invariant**; only the
four `DATA_BASE_*` come from the per-firmware file):

| field | `p2jb.js` | X1NON-PSJB / OzRviju |
|---|---|---|
| `PIPE_SIGIO` | `0xD8` | `0xD0` |
| `FILE_F_COUNT` | `0x28` | `0x24` |
| `FD_CDIR` | `0x08` | `0x18` |
| `FD_JDIR` | `0x18` | `0x20` |
| `DYNLIB_SC_START/END` | `0xF0`/`0xF8` | `0x308`/`0x310` |
| `UCRED_ATTRS_QWORD` | `0x80` | `0x50` |

Everything else matches (`PROC_*`, `FILEDESC_*`, all `UCRED_CR_*`, kq magic `0x1430000`,
`KQ_FDP 0xA8`), which is what makes it dangerous: it is *mostly* right. Look at
`FD_CDIR`: their `FD_RDIR 0x10` is correct but their `FD_CDIR 0x18` is `p2jb.js`'s
**`FD_JDIR`** — one anchor right, neighbours shuffled. Two independent repos agreeing is
weak evidence for a shared ancestor, **not** a firmware measurement. Wrong `fd_cdir`
leaves a half-jailbreak on a corrupt vnode pointer; zeroing `dynlib+0x308` when the real
range is `+0xF0` wrecks two unrelated qwords.

---

## 9. `bagagwa_probe.js` — the Syscall test panel (1248 lines, the file we own)

Loaded instead of `p2jb.js` when the URL has `&sc=1`. It loads **everything a real run
loads except the two kernel modules**, so it exercises the *same* executor. It auto-runs
all tiles on load, and every line goes four ways: the on-screen pane, `#scr` via
`flushMark`, the crash-surviving beacon via `syncMark`, and a notification per verdict.
A `localStorage` copy (`bwslop_sc_log`, tail-capped 8 KB) is restored on the next boot
behind a banner — **a WebProcess death taking the only log with it is the normal failure
mode**, so this matters.

### 9.1 The tiles, in run order

| tile | proves | notes |
|---|---|---|
| **Calibrate LK row** | measures the real `slot_expect` from the parked stack, patches the row live, persists it | read-only; see §9.2 |
| **Syscall convention** (T0) | how this kernel reports errors | `close(0x7fffffff)` **must** fail ⇒ whatever `rax` holds is the error form; then a getpid **canary** proves the kernel still answers. ENOSYS encoding is **inferred** — calling an unproven number to measure it wedged real hardware (§8.1.1) |
| **Identity** (T1) | getpid/getppid/getuid/geteuid/getgid/getegid | the positive control |
| **Descriptors** (T2) | kqueue + pipe2 | fds are **proven** by `close()==0`, then closed again |
| **AIO reach** (T3) | `aio_init` + `aio_multi_wait` with **all-zero** args | num=0 cannot link a waiter list, so it cannot arm. The decisive test |
| **ABI map** (T4) | which argument is `ids` and which is `num` | arming-safe by construction, §9.3 |
| **osem** (T5) | the `+0x54` refcount target | handle proven by `close()==0` |
| **Executor state** (T6) | kbase/slot/LK row + a **poison self-check** | writes `0xC0FFEEDEADBEEF` to the retval slot, runs getpid, requires the poison to be overwritten |

### 9.2 The calibrate tile — why it exists

The 13.60 LK row was originally **extrapolated** (12.40 + `0x20` per group step). The
first console run failed *every* call with
`parked slot (kbase+0x1983b) not found in worker stack top` — `resolveSlot()` rejecting a
wrong `slot_expect` before any syscall. Signature-scanning libkernel **text** is
impossible (the libraries are **xotext**; reading code through the R/W primitive faults
and kills the process). But the **parked stack is readable data**, and the return address
sitting in it *is* `slot_expect`. So the tile measures it and derives the rest at deltas
that are identical in both 12.x groups:

```
syscall_wrapper - slot_expect = +0x162C
setjmp          - slot_expect = +0x3BB8
longjmp         - slot_expect = +0x3C11
```

Three hard-won details (each was a real failure):

* **Anchor-first pick.** The first picker chose the *highest* live frame — `0x2198D`, the
  **thread-entry trampoline**, wrong semantic. The real value `0x1988B` was in the
  candidate list all along (frame-validated at `stack+0x7fc28`; 12.00 parks at
  `0x7fc18`). A known anchor now wins whenever present.
* **Data-word exclusion.** 25 of 38 candidates were `libkernel+0x751D0` —
  **`__stack_chk_guard`**, a *data* word copied into many frames, not a return address.
  Repeated data words are collapsed and excluded. X1NON-PSJB's table independently names
  `0x751D0` as `OFFSET_lk___stack_chk_guard`, confirming the rule (§11.6).
* **BigInt discipline.** `slot_expect + DELTAS.x` threw `Invalid mix of BigInt and other
  type` — and threw it *after* the wrong row had already been applied and persisted. Delta
  constants are BigInt literals, and `JSON.stringify` needs a BigInt replacer.

Rows are persisted with a `verified` flag; restoring an unverified row says so loudly.

### 9.3 The ABI map — arming-safe **by construction**, and why that is testable

`aio_multi_wait`'s argument order matters because getting it wrong fails **silently**:
`mode` lands in the wrong register, no node is shared, the array is never freed, and the
call **returns cleanly** — which reads as "patched" when the truth is "called wrong".

The tile sets **at most two registers nonzero per call**: a valid zero-filled buffer in
one, `1` in another, everything else `0`. Let the kernel's real `ids` register be `I` and
`num` be `N`:

* `N ∉ {i,j}` → `num = 0` → rejected, nothing linked.
* `N = j` → `num = 1` → at most **one** request linked, so there is no second list for a
  node to be shared with and nothing can dangle.
* `N = i` → `num` = the buffer address, and `ids` is `1` or `0` — both unmapped, so the
  **first** `ids` read faults and the walk aborts before any link.

No assignment of `(i,j)` reaches a valid array with `num ≥ 2`. `tools/test_abimap.mjs`
asserts this as a **tripwire**: its kernel model latches `armed` on any
valid-array-with-`num≥2` call and the suite fails if it ever fires.

Deduction reads the matrix **relative to each row**, never against the baseline — when the
baseline is itself an `EFAULT` (absent array faults too), "differs from baseline" lights up
every cell of the true row. The first version of this reported **five** candidate pairs.
The signal is *within* a row: for a fixed array argument, `num` is 0 in every cell but one,
so the ids row is the one where a single column stands apart.

Phase 1 (single-register `0x1000` probes) finds whichever argument is validated **last** —
the array on an ids-first kernel, but the **num** argument when the kernel rejects
`num==0` first. The verdict states which end it observed rather than implying they agree.

### 9.4 Invariants to preserve if you edit the probe

* **Never** pass a real request id, `num ≥ 2`, or a valid array together with a nonzero
  `num`, in any tile.
* Zero-fill **all six** argument registers. An `undefined` argument means "don't touch",
  which leaves the *previous* chain's value in that register — and a stale register read as
  a pointer manufactures a fake `EFAULT`. This is the most likely source of the
  `osem_open=0xe` seen in the first run.
* Prove handles/fds with a follow-up call (`close()==0`), never by reading the create
  return. Under a raw convention a small positive `rax` is either a handle or an errno.
* Keep the tile's four-way logging. A console run that dies leaves only the beacon.
* Add a regression case to the harnesses for any behaviour you change (§14).

---

## 10. HARDWARE RESULTS — 13.60 console, 2026-09-16 (all VERIFIED)

### 10.1 The executor works

```
Calibrate: "executor already resolved its slot (slot=0x7ef34bc28)"
           → the persisted calibrated row was used at BOOT, and the adapter's own
             getpid had already fired before the panel loaded
T5-state:  kbase=0x821008000 wbase=0x825ef4000 stack=0x7ef2cc000
           ctx=0x10013ad480 retval=0x10013ad4c8 fired=19
T5-slot:   stack+0x7fc28   (predicted exactly by slot_expect=0x1988B)
T5-POISON: "chain ran, overwrote the poison -- retval slot proven (pid=79)"
```

`fired=19` + correct identity values + the predicted slot ⇒ **all four 13.60 text RVAs are
hardware-verified, not extrapolated** (`p2jb_lk.js`'s group-C comment now records this).

### 10.2 Identity — real

```
getpid 0x4f (79)   getppid 0x34 (52)   getuid 0x1   geteuid 0x1   getgid 0x1   getegid 0x1
```
`uid=1` is correct for a browser process; `0x3FF` would be the interesting wrong answer.
The poison test returned **pid 79 independently**, so these are not stale reads.

### 10.3 Descriptors — real

`kqueue → fd 7`, `close(7) → 0`; `pipe2 → 0` with `rfd 7 / wfd 8`, both closes `0`.

### 10.4 **AIO is ALIVE — this is the headline**

```
aio_init            (0x29E) -> 0x16   EINVAL     [13:44 & 20:13 runs]
aio_multi_wait      (0x297) -> 0x16   EINVAL     ← 663, the writeup's number
osem_create         (0x225) -> 0x16   EINVAL     ← see §11.4, this call was WRONG
osem_open           (0x227) -> 0xe    EFAULT     ← stale-register artefact, now fixed
osem_close          (0x228) -> 0x3    ESRCH
osem_delete         (0x226) -> 0x3    ESRCH
```

**ENOSYS is 78 = `0x4E`. We got `0x16`. The syscall exists and rejected the arguments.**
The chain is reachable in principle on 13.60. T0 (second run) also **measured** the raw
convention on hardware: `close(0x7fffff) -> 0x9 EBADF`, canary getpid alive, ENOSYS=0x4e
*inferred* — the direct measurement attempt via an out-of-range number had WEDGED the
kernel (three ~64 s freezes; §8.1.1).

Two caveats, stated plainly:

* `0x297` being *handled* is strong but not airtight proof it is specifically
  `aio_multi_wait`: the number is cross-checked by `getpid`/`kqueue`/`pipe2` all behaving
  correctly and by the writeup labelling **syscall 663 = aio_multi_wait**. Residual risk is
  small.
* This does **not** settle the argument order. That is §11.

### 10.5 Enumeration of the syscall numbers in play

```
identity  getpid 0x014  getppid 0x027  getuid 0x018  geteuid 0x019  getgid 0x02F  getegid 0x02B
fds       close 0x006   kqueue 0x16A   pipe2 0x2AF   write 0x004      socketpair 0x035
AIO       aio_init 0x29E  aio_submit 0x295  aio_multi_delete 0x296  aio_multi_wait 0x297 (=663)
          aio_multi_cancel 0x29A  aio_submit_cmd 0x29D (=669)  aio_debug_info 0x2D7 (=727)
osem      osem_create 0x225  osem_delete 0x226  osem_open 0x227  osem_close 0x228
misc      sched_yield 331   pthread_create (libkernel_web) 0x79B0
```

---

## 11. Bagagwa — the bug, and the state of every public implementation

### 11.1 The bug (from the writeup; kernel RVAs relative to `0xffffffff80000000`)

```
aio_multi_wait         0x5c0210   syscall 663
mode-0 dispatch        0x5c08e5
cleanup                0x5c0da1
free                   0x5c0f93
waker                  0x5c1d2d
  waker fields:  +0x00 -> dec dword #1     +0x08 -> dec dword #2 (NULL in mode 0)
                 +0x10 -> mtx_lock target  +0x20 -> controlled 32-bit write
aio_debug_info         0x5c3090   syscall 727 (the leak); copy loop 0x5c3325
osem_delete            0xe2632e (flag_off 0x45, refcount_off 0x54, size 0x60)
osem_open              0xe26120
sizes: waiter node 0x38; request 0x28; waiter array at num=2 = 0x70 (128 zone)
       osem malloc(0x60)=96 bytes (128 zone)  → the zones line up
```

With `num ≥ 2` and `mode = 0`, the dispatch (0x805c08e5) sets `rcx = [rbx+0x40]` **without
indexing**, so it links the *same* node (element 0) onto all N requests' waiter lists,
overwriting `node->owner` (+0x18) each iteration. Cleanup (0x805c0da1) unlinks by
`node->owner` ⇒ it detaches only from the **last** request. Then 0x805c0f93 frees the
array, leaving requests `0..N-2` with `req->waiters` dangling — the UAF. Mode 0 never
initialises `node->[8]` (mode 2 does), so it stays `M_ZERO` and is controllable post-free.

The writeup's own use of this: the waker is the primitive. `aio_debug_info` (727) is the
leak — `get_aio_debug_request_info` uses a slot index as a bias into a *different* array,
leaking a dword at +0x20 and two 8-byte pointers per element.

### 11.2 Four implementations exist. Three of them are wrong in the same place.

| build | ABI | stage-0 (live waiters) | verdict |
|---|---|---|---|
| upstream slopkit | ids-first | **correct** (leaves pipe empty) | reference for control flow |
| PSAITO / Wamphyre `bagagwa_uaf_1320.js` | **ids-first, confirmed** | **correct (socketpair, pending read)** | **most advanced; studied below** |
| `Bagagwa_chain` (X1NON) | instance-first | **wrong** — pre-fills the pipe | arming cannot work |
| OzRviju `bagagwa-exploit` | instance-first | **wrong** — pre-fills `64 * numRequests` | arming cannot work |

**2 of 4 get stage 0 right**, and both of the wrong ones also carry it. The defect is the
same in both: pre-filling the pipe means *"reads complete immediately"* ⇒ no request is
ever in flight ⇒ no node is ever linked onto a live waiter list ⇒ the shared-node link
never happens and nothing dangles.

### 11.3 **The ABI question is answered** (UPSTREAM, but checkable)

**UPDATE (20:13 hardware run): the pair is now MEASURED on 13.60, not just inherited.**
The ABI map's row-wise scan called the real matrix INCONCLUSIVE, but the matrix decodes
column-wise — the four EFAULT cells all sit in the arg2 column with num=1 (which is what
activates the derefs), while row arg2 (huge value in num) and row arg4 (huge value in mode)
stayed EINVAL: a **num domain check** and a **mode validation** both exist and precede the
derefs. `ids = argument 1, num = argument 2` — independently confirming PSAITO's
`(ids, num, states, mode, timeout)` on this firmware. Also measured: **states is
dereferenced too** (row arg1 col2 had a valid ids and still faulted — states@arg3=NULL),
and the kernel does NOT NULL-check ids before the num check (faults from NULL came through
the walk). Phase 1's all-EINVAL sweep is PREDICTED by this model, not a failure to probe.
Still unmeasured: mode/timeout positions, id encoding, which pointer is checked first.
The tile now carries this column model as its primary path (regression-guarded by
`tools/test_abimap.mjs` scenario 6, which replays the real 30-cell matrix).

The upstream text below is kept for provenance:

`PSAITO/payloads/bagagwa_uaf_1320.js` header:

```
// ABI real (confirmado en lapse.js y osem2_1320.js):
// aio_multi_wait(ids*, num_ids, states*, mode, timeout)   [0x297]
// aio_submit_cmd(cmd, reqs*, num_reqs, priority, ids*)    [0x29D]
// aio_multi_cancel(ids*, num_ids, states*)                [0x29A]
// aio_multi_delete(ids*, num_ids, states*)                [0x296]
// AIO_CMD_MULTI_READ = 0x1001
```

⇒ **ids first**, five arguments: rdi=ids, rsi=num, rdx=states, r10=mode, r8=timeout. The
named sources (`lapse.js`, `osem2_1320.js`) are in the same repo, so this is checkable, not
hearsay. It is confirmed on **13.20, not 13.60** — that is what the ABI map tile is for.
Note this also resolves the earlier "three implementations disagree" deadlock: the two
best-developed builds now agree.

### 11.4 `osem_create` is five-argument — our probe called it wrong

PSAITO calls `osem_create(0x225, [name, 0, 1, 1, 0])`. Our T5 sends `(name, attr)` — two
arguments — which zero-fills the rest, i.e. `(name,0,0,0,0)`. If the two `1`s are a
required mode/type pair, **§10.4's `0x16` was a bad call, not a kernel refusal**, and the
`ESRCH`/`EFAULT` that followed were just downstream noise on a bogus handle. (Also note
Bagagwa_chain calls `(name, attr)` while PSAITO calls `(name,0,1,1,0)` — another explicit
ABI disagreement.)

**UPDATE (20:13 hardware run): the 5-arg shape was sent and answered `0xa6 = 166` — above
any plausible errno band (max seen in practice is ENOSYS=0x4e). The tile classifies by
RANGE first (**cutoff `0x80`** — raised from the first draft's `0x100`, which MASKED a
likely-real handle; see below) and proves candidates by `osem_delete(candidate) == 0` (the
20:13 run's `delete(0xa6) -> 0x0` vs `delete(0x16) -> 0x3 ESRCH` differential), with
`close` only as a fallback and only when delete did not consume the object — `close` then
`delete` on a genuine handle is the documented DOUBLE-FREE (close frees at refcount 0,
delete frees again). The run left the verdict at "no proven handle" only because the OLD
proof heuristic was `close == 0` alone and it read `close(0xa6) -> 0x1 EPERM` as disproof.
The delete differential says otherwise:
**`0xa6` behaved like a real handle and the 128-zone allocation works from our executor.**
The tile now proves this in one run and stops at the first shape that passes. Open
questions it reports honestly: the name contract (own copy vs borrowed pointer — the tile
now tries both), attr semantics, and why close says EPERM on a live handle.

**SECOND UPDATE (22:12 hardware run): `osem_create(name,0,1,1,0)` → `0xa6` and
`osem_create(nameCopy,0,1,1,0)` → `0xa7` — successive creates returned successive handles,
which is an ALLOCATOR handing out objects, not a static errno table. Combined with
`delete(0xa6)=0` from 20:13, the `0x80` cutoff is the right line: handles live at/above
it, errnos below. The 22:12 run's tile still carried the `0x100` cutoff and declared both
"below the handle band" — that masking is now fixed, and a future run should PROVE the
handle via the delete-first epilogue. If the epilogue refuses a `0xa6`-class value, that
refusal is itself data (recorded in the verdict), not silence.**

### 11.5 PSAITO's payload structure — worth reading in full

`payloads/bagagwa_uaf_1320.js` (15,982 B, Spanish comments, by Wamphyre/Arya — same lineage
as slopkit and this repo). Phases:

* **F0** — AIO family alive check; aborts on total ENOSYS; in stub mode it pre-checks the
  stubs it needs and calls out that 727 has **no stub**.
* **F1** — create live requests: `socketpair(AF_UNIX, SOCK_STREAM)` (0x35), write the
  **read** end into `reqs[i]+0x20`, `aio_submit_cmd(AIO_CMD_MULTI_READ, reqs, N, prio=3,
  ids)`, and **leave the read pending**. `NREQ = 2`.
* **F2** — pre-set the control node's fields (`+0x00`/`+0x08` point at malloc'd 8-byte
  cells holding sentinels; `+0x10` points at a **valid aligned cell, not NULL**, because
  the waker's `mtx_lock` writes at `[[r15+0x10]]+0x18` and NULL there would panic) and fill
  a `0x70` witness block + a `0x60` osem witness (with a bogus 32-bit refcount `2` at
  `+0x54`), snapshotted for diffing.
* **F3** — fire: `aio_multi_wait(ids, NREQ, states, mode=0, timeout=0)`. **Destructive.**
  `timeout=0` keeps it non-blocking.
* **F4** — reclaim the freed 128-zone with `osem_create` ×4, names `WAKE0000`…`WAKE0003`.
  If the waker's `dec dword [rax]` has `rax = [node]` pointing at an allocated **name
  string**, the first dword of that string changes — and **that is readable from JS**.
  Detection without a kernel reader. Reclaim osems are left alive on purpose (deleting one
  whose refcount the waker already decremented = double free).
* **F5** — wake: `write(1 byte)` to the other socketpair end ⇒ pending reads complete ⇒ the
  waker walks `req->waiters`, the dangling pointer.
* **F6/F7** — diff the witnesses/name strings, then a verdict ladder: threw → ENOSYS →
  `decHit` on the sentinel cells → name-string change → witness change → *"sin efecto
  observable"*. Then cancel/delete/close, leaving the osems alive.

**The author's own header is the honest summary:**
`"NO implementa aun el leak 727 ni la conversion osem (son especulativos sin un testigo que
confirme el efecto)"` — the final two stages are **explicitly speculative with no witness
confirming the effect**. It arms the bug and measures with sentinels; it does **not**
convert it into a primitive.

Also: **727 has no libkernel wrapper** ⇒ PSAITO cannot call it in stub mode. Our executor
can (§6.2). That is our structural advantage and it matters for the leak stage.

### 11.6 Why our platform is better positioned than the reference

1. We can call **727** (raw `rax` dispatch); the reference cannot in stub mode.
2. Our executor is **calibrated and hardware-verified** on 13.60.
3. Our rows are **self-measuring** (calibrate) and **persisted**, so a crash is
   attributable and recoverable information rather than a lost run.
4. Our error decoding is convention-aware, so "patched" and "called wrong" cannot be
   confused (that confusion was a real bug we fixed — §9.1).

---

### 11.7 The 22:12 hardware run — ABI measured, osem allocator behaviour


The 22:12 run is the most complete yet (8/8 tiles). Two results matter:

**1. The ABI pair is MEASURED on 13.60, not inherited.** The matrix decoded column-wise:
all four EFAULTs sit in the arg2 **column** with `num=1` — i.e. `num=1` is what activates
the derefs; row arg2 (huge value in num) stayed EINVAL ⇒ a num **domain check** exists;
row arg4 (huge value in mode) stayed EINVAL ⇒ mode is **validated before** the derefs;
row arg1 col2 had a VALID ids and still faulted ⇒ **states is dereferenced too**. That is
PSAITO's `(ids, num, states, mode, timeout)` — now confirmed on 13.60 hardware, not just
their 13.20. The tile's verdict carries this model and names what is still unmeasured
(which of ids/states is checked first, mode/timeout positions, id encoding).

**2. osem_create behaves like an allocator.** Successive creates with different name
buffers returned `0xa6` then `0xa7` — a counter, not an errno table. With the 20:13
`delete(0xa6) -> 0x0` differential, handles live at/above `0x80` and the first draft's
`0x100` cutoff was masking them (fixed; regression-tested in test_convention 6c).

**Added after that run: the "AIO live request" tile (T3b)** — the first tile that puts a
LIVE pending AIO request in the kernel while staying arming-safe (`num=1` everywhere;
harness tripwire). It follows PSAITO's verified recipe: `socketpair` (0x35) →
`aio_submit_cmd(AIO_CMD_MULTI_READ=0x1001, reqs, 2, prio=3, ids)` with the read end at
`reqs[i]+0x20` (0x28-byte structs) and reads left PENDING → `aio_multi_wait(ids, num=1)`
→ wake-write to the other end → `aio_multi_cancel` + `aio_multi_delete` + closes. Its
verdict separates what it MEASURED (whether submit's ids work as raw handles, whether a
pending-request wait answers) from what it can never do (arm — that needs `num>=2` in ONE
call and stays behind explicit operator approval).



**A. DONE (20:13 + 22:12 runs).** The 5-arg shape is in and answered `0xa6`/`0xa7`;
`delete(0xa6)=0` on hardware. The tile's `0x80` cutoff now lets a future run PROVE the
handle via the delete-first epilogue instead of masking it.

**B. DONE (22:12 run).** ABI `(ids=arg1, num=arg2)` is MEASURED on 13.60 — see §11.7.

**B2. Run the new "AIO live request" tile (T3b, added after the 22:12 run).**
Non-destructive and arming-safe by construction: `socketpair` → `aio_submit_cmd(MULTI_READ,
N=2, prio=3)` with reads left PENDING → `aio_multi_wait(ids, num=1)` → wake-write →
cancel/delete cleanup. `num=1` can never reproduce the UAF (that needs `num>=2` in ONE
call — enforced by the harness tripwire, which fails the suite if any wire-call ever
carries a valid array with `num>=2`). It measures what the armed call will see: whether
submit's ids are raw handles, whether the pending-request wait answers (vs the EINVAL the
all-zero and num=1-on-nothing calls gave), and it exercises cancel/delete. This is the
last cheap read-only measurement before anything destructive.

**C. BUILT (behind a gate, at the operator's explicit request).** The arming payload now
EXISTS as the "UAF arm (UNSAFE)" tile on PSAITO's structure (live pending reads → armed
`aio_multi_wait(ids, num=2, states=NULL, mode=0, timeout=0)` → reclaim-before-wake with
WAKE0000-3 + SPRAY osems → wake-write → JS-readable detection ladder). It renders and runs
ONLY when `?arm=1` is in the URL, which index.html appends only while the operator's
**UNSAFE checkbox** is ticked (fresh on every load, never persisted). The harness asserts
the gate both ways: without `arm=1` no `num>=2` call can ever fire (test_convention 8b);
with it, EXACTLY ONE armed call with the measured ABI reaches the kernel model (scenario 8,
which also carries a real memory model so the tile's detector integrity self-check is
eXercised honestly). **A failed armed run is still a POWER CYCLE, not a reload.**

**D. Then, separately, the leak (727) and the osem conversion.** Treat both as UNKNOWN.

**Probability, stated honestly** (these are estimates, not measurements):

| stage | odds | reason |
|---|---|---|
| syscalls reachable on 13.60 | **85–90%** | already measured: `0x16` not `0x4e` |
| ABI same as 13.20 | **~80%** | same code family, confirmed only on 13.20 |
| arming **without** a panic | **35–50%** per attempt | PSAITO's own file warns phase 3+ can hang/panic; each failure costs a power cycle |
| reclaim landing where we want | **~50%** | the zones do line up (`0x70` array and `0x60` osem both 128-zone), but controlling placement is the hard part |
| turning the bug into a useful primitive | **10–25%** | needs the 727 leak for addresses first, then a data-only attack |
| **full jailbreak on 13.60 soon** | **~10–20%** | nobody has published a working Bagagwa jailbreak on any firmware |

Read it as: **measuring and arming are within reach; a working jailbreak is not yet.**

---

## 12.4 The P2JB/poops tile (T2c) and the 11:21 ARM analysis — 2026-09-17

### What the 11:21 ARM run taught (all VERIFIED, one console run)

1. **`aio_submit_cmd` WORKS end-to-end on 13.60**: `MULTI_READ n=2 prio=3` returned 0 and
   produced two live pending requests with raw ids (`0x120a600002a6`, then 0). Half of
   stage 0 is measured and functional, including the `0x28`/fd@+0x20 request layout.
2. **The armed `multi_wait(ids, num=2, states=NULL, mode=0, timeout=0)` returned EFAULT
   and NEVER REACHED THE LINKING CODE.** This is the MEASURED ABI model consuming itself:
   the ABI-map matrix proved states (arg3) is dereferenced whenever num≥1 (row arg1 col2:
   valid ids, states NULL → EFAULT). The arm tile passed 0 for states, so the kernel
   faulted on the walk before linking anything. THE FIX (committed): pass a real zeroed
   `states` buffer (0x40, room for one 0x38 io_state) — a wait on an incomplete request
   returns before writing state, so zeroed states are safe. **Re-run the ARM tile with
   this fix before concluding anything about mode/timeout positions or id encoding.**
3. `socketpair` refuses (0xe EFAULT) even while `pipe2` works — the fallback path matters;
   keep it.
4. osem allocator counter continued across the run (0xa6→0xaa WAKE, 0xab→0xae SPRAY) —
   another independent confirmation that these are kernel handles, not errnos.

### The T2c tile (P2JB/poops calls) — what it is and is not

`soniciso1/P2JB` is the 12.00-12.70 WebKit jailbreak; its kernel stage (p2jb.js) and the
poops variant (p2jb_poops.js) drive one primitive family: `socket(AF_INET6=28)` pairs,
`setsockopt(IPPROTO_IPV6=41, IPV6_RTHDR=51, tag, 0x38)` as the kernel poison-write, and
`getsockopt(IPV6_RTHDR)` as the read back (master/victim cross-descriptor = arbitrary
kernel R/W). T2c calls exactly that surface on 13.60, read-only:

- `0x061 socket(AF_INET6,SOCK_STREAM)`, `0x035 socketpair` ×2, `0x16A kqueue`
- `0x069 setsockopt(IPV6_RTHDR, tag 0x38)` — PASS = the 13.x validator ACCEPTED the pair;
  `IPV6_FL_AUDIT=0x6d` driven as the differential validator probe
- `0x06A getsockopt(IPV6_RTHDR)` read-back (tag echo?) and the **cross-descriptor bug
  shape**: `getsockopt(victim-pipe-fd, IPV6_RTHDR)` — on 12.x this crossed; **if it ever
  returns 0 on 13.60 that is the headline** (CROSS-FD-RETURNED-0)
- `0x0C2 getrlimit(RLIMIT_NOFILE)` — the helper both chains use

Everything closes again; nothing writes kernel memory. The verdict ladder: tag accepted +
echo (or cross-fd 0) ⇒ "12.x CHAIN PRIMITIVES ALIVE"; accepted-but-no-shape ⇒ "validator
passes benign pairs and still gates the bug"; all refused ⇒ "PATCHED as expected".
**PS5 notify carries the result.** (Design note: IPV6_FL_AUDIT=0x6d comes from
Wamphyre/PSAITO commit e0f3857's evidence-audit work on 13.x option validation.)

### Inherited from Wamphyre/PSAITO commits (f8554d4 + e0f3857), worth keeping

- **Gated chain pattern** (canary → AIO gate → shot, stop at first closed gate, CHAIN
  RESULT summary) — mirrors our checkbox + RUN ALL gating; already implemented here.
- **`?notify=0`** — their kill-switch because a wrong `nt` offset can kill the process on
  notify. Our panel does not have this; if the PS5 notify ever wedges the browser, add it.
- **osem ABI ground truth (osem2_1320.js)**: `CLOSE(0x228, live id) = EPERM` — our 0xa6
  close=0x1 reading was correct; `attr=0x10 or large → EINVAL`; real ids look like
  `0x61ab` (13.20); OPEN searches BY NAME after delete (ESRCH means the name is dead, not
  the call).
- **Their simulator discipline** (kernel model + tripwires) matches our harness approach;
  their `sim: hang-expected` payload marker is a good pattern if we ever add payloads.

### The BragaTy mirror (teste-exploit-ps5) — what diffing it against pArm taught

`BragaTy/teste-exploit-ps5` is a verbatim mirror of Wamphyre/PSAITO (commits 2026-09-15:
"Update menu.js" / "teste 3"; payloads are byte-identical PSAITO files incl.
`bagagwa_uaf_1320.js` v44bd1e95). Diffing it gave three concrete fixes, all shipped:

1. **TIMING — the biggest one.** Their payload yields `sched_yield` (331 = `0x14B`, a
   proven 13.60 stub in our map) **200x after the armed shot, 500x after the reclaim,
   500x after the wake**. The AIO completion and the waker run on KERNEL worker threads;
   a JS thread that never yields reads the detectors before the waker has run at all.
   Our 11:21 ARM run read detectors immediately — part of its "no observable effect" is
   now attributable to that. We ship `settle(n)`: silent yield loops at all three points.
2. **cancel/delete take THREE args: (ids, num, states)** — our old `(ids, 1, 0)` calls
   EFAULTed for the same states=NULL reason as the armed call. Fixed in pArm (num=2,
   covering both requests) and pLive (num=1).
3. **Their ids array is `4*NREQ` bytes and they read ids via `read32`** — ours is 0x10
   and read via read64. Both saw ids, so either works; kept ours, noted the difference.

Also noted: their F2 builds a `node` control block with a VALID mtx_cell pointer (never
NULL) — our allocCell does the same; their detectors are the same sentinels/witnesses;
their reclaim osems are deliberately left alive (double-free safety) — same as ours.

Harness lesson (cost us a green->red->green cycle): `settle()` must be SILENT — 1300 S()
rows flushed the panel log buffer and evicted the very tile output the scenarios assert
on. `S()` now honors `quiet` on the throw path too, and the kernel models know `0x14b`.

### pLive fixes shipped with T2c (both caught by the harness)

1. The wait now passes a real zeroed states buffer (arg3) — same EFAULT lesson as ARM.
2. The cleanup fd labels were INVERTED (`close w` closed the read fd). Verified against
   T2's pipe2 semantics: `rd[0]` is the read end. Harmless so far (both got closed), but a
   silent trap if a future tile ever closed only one end.

---

## 13. DO-NOT-DO list

1. **The UAF is wired ONLY behind `?arm=1`** (the index.html UNSAFE checkbox). Do not
   widen that gate to a plain button, a persisted flag, or an always-on tile. No disarm
   exists: cleanup unlinks only via `node->owner`, so `req->waiters` for `0..N-2` dangles
   into objects this process does not own. A failed armed run is a **power cycle, not a
   reload**. There is no `null_rthdr()` equivalent.
2. **Do not paste `offsets/kernel/data.js`** (§8.2) or port OzRviju's struct table (§8.3).
3. **Do not try to read libkernel *text*** to signature-scan. The libraries are xotext;
   reading code through the R/W primitive faults and kills the process. Read the *stack*.
4. **Do not push to `origin`** (`soniciso1/pooP2JB`). Push to `bwslop`.
5. **Do not edit an engine file without bumping its `?v=`** (§5.2).
6. **Do not trust a green verdict on osem** until §12.A is done — the current call shape
   is known-wrong.
7. **Do not assume `p2jb` is patched** from any log we have produced. The probe never
   reaches kernel memory, so it cannot test that; the operator's report that p2jb and
   poops are patched on 13.60 is the only source for it, and it is irrelevant to the probe
   anyway (the executor is pure WebKit userland; Bagagwa would replace p2jb's bug).
8. **Do not raise `aio_multi_wait`'s `num` past 1 outside the approved arming payload.**
   The T3b tile and the ABI sweep never do; the harness tripwire (test_convention 1b,
   test_abimap all scenarios) fails the suite if any wire-call ever carries a valid array
   with `num >= 2`.
9. **Do not run the ARM tile twice without a reboot between runs** — the tile itself says
   so, and the 11:21 run's reclaim osems (0xa6..0xae) were left ALIVE on purpose; a second
   run must not assume the zone is clean.
10. **Do not "fix" T2c to try the master/victim write shape** (setsockopt on one fd then
   getsockopt from another to move the rthdr pointer). That is the kernel-memory stage of
   the 12.x bugs; the tile deliberately measures only the reachability of the surface.

---

## 14. Testing — three headless harnesses, run them before every push

```
cd pooP2JB
node --check bagagwa_probe.js && node --check p2jb_lk.js
node tools/test_calibrate.mjs     # 14 checks: anchor pick, data-word exclusion, BigInt,
                                  #   persistence, crash-restore
node tools/test_convention.mjs    # raw / converted / plain-1 conventions,
                                  #   patched-firmware MUST report DEAD,
                                  #   osem handle proof + 0x80 cutoff regression,
                                  #   live-request tile incl. num>=2 tripwire
node tools/test_abimap.mjs        # 16 checks: deduction under 4 kernel shapes,
                                  #   attribution of which phase saw what,
                                  #   and the ARMING-SAFETY TRIPWIRE
```

All three run the real `bagagwa_probe.js` inside `vm` with a stubbed DOM/`window`, and read
the panel log out of the stubbed `localStorage` (`bwslop_sc_log`). When you change probe
behaviour, add a case — the convention harness's most valuable test is that a **patched**
firmware reports `BAGAGWA DEAD`; the ABI harness's is that the tripwire never fires.

`tools/lkfind.js` is the static scanner for libkernel_web signatures (it documents the
three byte signatures). Usage:
`node tools/lkfind.js <libkernel_web.sprx> --expect 12.00`. It needs a real sprx; there
is no 13.60 one locally, which is precisely why the runtime calibrate tile exists.

---

## 15. Open questions

1. Is `0x297` *specifically* `aio_multi_wait` on 13.60, or merely *a* handled syscall?
   (Strong circumstantial yes; a differential test against another AIO number would settle
   it.)
2. Does the kernel validate `ids` before or after `num==0`? (The ABI map's phase 1 will
   say; our baseline being `EINVAL` suggests `num` first.)
3. Does `osem_create(name,0,1,1,0)` succeed on 13.60? (§12.A.)
4. What is the correct `mode`/`timeout` **position**? The ABI map cannot pin these — it
   never passes a real request id. Known only from PSAITO's 13.20 claim.
5. Is the `0x1FD01` sighting at `stack+0x7fb68` related to the documented
   `OFFSET_WORKER_STACK_OFFSET = 0x7FB88`? They are `0x20` apart. **UNKNOWN** — recorded as
   an observation, not a conclusion.
6. Does the 727 leak's bounds bug behave as the writeup describes on 13.60? Untested.
7. `p2jb_lk.js`'s `thread_list`: is `0x75258` (X1NON-primary) or `0x6C218`
   (X1NON-commented, PSAITO, and our hardware run) right? Evidence favours `0x6C218`.

---

## 16. Attribution and provenance

* Host engine (`core.js`, `p2jb.js`, `poops.js`, `rop-worker.js`, `p2jb_poops.js`, …) —
  upstream by **j0rdy** / slopkit lineage, via `soniciso1/pooP2JB`.
* The Bagagwa bug description is a **publicly circulating writeup of unknown origin**
  ("Origin unknown. Publicly circulating writeup. Not our work." — X1NON-PSJB's own words).
* `X1NONs/PSAITO`, `X1NONs/X1NON-PSJB`, `X1NONs/Bagagwa_chain`, `OzRviju/bagagwa-exploit`
  — third-party, cited above with the specific claim each one supports.
* **Written by us** (this effort), and safe to treat as ours:
  `bagagwa_probe.js`, `docs/PROJECT_HANDOFF.md`, `tools/test_{calibrate,convention,abimap}.mjs`,
  the `13.60` row and group-C notes in `p2jb_lk.js`, the 13.60 entries in `main.js` and
  `index.html`, and the `&sc=1` branch in `p2jb.html`.
