# How a PS5 jailbreak works — every repo in this workspace, read end-to-end

> Written 2026-09-19. Companion to `psaito-bagagwa-chain-findings.md` (the Bagagwa
> specifics) and `bagagwa-conversion.md` (the UAF → R/W conversion). This document is the
> layer above those: what a PS5 jailbreak **is**, which repo demonstrates which layer, and
> what that means for 13.60.

---

## 1. The invariant: every jailbreak is the same five beats

Every working PS5 jailbreak in this workspace — IPV6 (p2jb), NetCtrl (poops), Lapse,
UMTX, AIO/Bagagwa — produces the same five beats in the same order. The only thing that
differs is **beat 0** (which kernel bug you use) and **beat 2** (which object you corrupt
to widen the window).

```
BEAT 0  trigger the kernel bug          → a free/overflow/race that yields a dangling
                                          kernel object or an OOB write
BEAT 1  shape the primitive             → reclaim/alias so the dangling object gives
                                          read or write of kernel memory
BEAT 2  widen to arbitrary kernel R/W   → corrupt ONE well-understood object (a pipe
                                          buffer) to get a stable PAGE_SIZE read/write
BEAT 3  escalate                        → ucred patch (uid 0, authid, caps) + rootvnode
                                          into fd_rdir/fd_jdir + dynlib widen
BEAT 4  persist + load                  → kexp shellcode thread → elfldr on :9021 → ELF
                                          payloads (etaHEN, ftpsrv, kstuff…)
```

Everything after beat 2 is **generic and firmware-portable** — it is pure offset lookups
against `struct proc`/`struct ucred`/`struct filedesc`. That is why `p2jb.js` stages 3–7
were ported almost verbatim into every later chain, and why a 13.60 jailbreak is "only"
beats 0–2 plus an offset table.

### The canonical beat 3–7 implementation (p2jb.js, 4497 lines)

| stage | does | key detail |
|---|---|---|
| 0 | trigger + leak | IPV6 `IPV6_RTHDR` triple-free race; `cr_ref` leak via rthdr↔uio alias; `find_twins`/`find_triplet` sockets |
| 1 | reclaim + poison | free `triplets[1]`, spin `kqueue()` until a fresh kqueue lands in the freed chunk (fixed-size zone!) |
| 2 | leak pipe pointers | `kslow64` walks `proc->fd_ofiles`, reads `file` structs → `master_pipe_data`, `victim_pipe_data` |
| 3 | **fast kernel R/W** | `kwrite_slow(master_pipe_data, pipe_overwrite, 24)` — overwrite the master pipe's `pipe_buffer` {cnt, inp, out, size=PAGE_SIZE, buffer=victim_pipe_data}. Then `read()`/`write()` on the victim pipe fd **are** kernel read/write |
| 3b | cleanup + `curproc` | refcount-bump all pipes (+0x100 so close can't free them), grab `ucred_A`, `curproc` via SIGIO/FIOSETOWN |
| 4 | rootvnode | walk `allproc` list (`p->le_prev` chain, pid 0 = kernel proc) → `fd_cdir` |
| 5 | **jailbreak** | ucred: `cr_uid..cr_svgid = 0`, `cr_sceAuthID = 0x480000000000000B`, `cr_sceCaps[0..1] = ~0`, attrs byte; `fd_rdir`/`fd_jdir = rootvnode` |
| 6 | data_base | find `allproc` by mask-scan `0xffff8040…`, derive kernel `.data` base (degrades gracefully) |
| 7 | dynlib | `p_dynlib` at `proc+0x3E8`: killed=0, refcount=1, mem_lock=~0, restrict set 0 |

**The `struct file` walk that everything depends on** (`p2jb.js:2640-2658`):

```js
fdescenttbl = kread64(proc + OFF.FILEDESC_OFILES);   // proc_filedesc + 0x0
fd_ofiles   = fdescenttbl + OFF.FDESCENTTBL_HDR;     // +0x0 header
fp          = kread64(fd_ofiles + fd * OFF.FILEDESCENT_SIZE);
f_data      = kread64(fp);                            // socket/pipe object
f_cred      = kread64(fp + 0x10);
f_count     = kread32(fp + 0x28);                     // the refcount stage3b bumps
```

---

## 2. The repos, layer by layer

### 2.1 `pooP2JB/` — the working 10.00–12.00 jailbreaks (our tree)

* **Entry:** WebKit userland (core.js → mem.js → main.js → rop-worker ROP executor).
  Serde desync → addrof/fakeobj → fake object with crafted JIT cell → sync `syscall()`
  via worker stack hijack. Works to 13.60 (proven on our console).
* **Kernel:** `p2jb.js` (IPV6 rthdr triple-free, 7.00–12.02) and `poops.js` (NetCtrl
  UAF, ~12.50–13.00). Both end in the five beats above. **Both are patched on 13.60.**
* What we own: `bagagwa_probe.js` — the measurement panel that proved userland on 13.60.

### 2.2 `other&old-explolts/PS5-UMTX-Jailbreak/` — the UMTX race (1.00–7.61)

`CVE-2024-43102` — FreeBSD `umtx` SHM-key race UAF. Structure (`document/en/ps5/exploit.js`):

1. `UMTX_OP_SHM` create/destroy loops from two racing ROP threads (`thread_destroyer_0/1`),
   pin cores via `rtprio_thread`, `UMTX_SHM_LOOKUP` to catch the freed key area.
2. The UAF gives a **mapping into a kernel thread stack** (`pipemap` style): resize/tag a
   shm, alias it against a kernel stack page.
3. Read the parked thread's stack to leak kernel pointers, then **re-use p2jb's pipe
   trick**: corrupt a pipe pair for stable R/W, then ipv6 socket pair for the final
   primitive — literally the same stage3 shape as p2jb.
4. Same tail: ucred patch, rootvnode, elfldr.

Limits it documents (still true): kernel `.text` is **XOM** (no kernel code dumps ⇒ no
kernel ROP gadgets), the **HV enforces kernel W^X** (no kernel patches/hooks), CFI is on,
SMAP/SMEP cannot be disabled. **A jailbreak is R/W + ucred, not kernel code exec.**

### 2.3 `other&old-explolts/kexp/` — the post-jailbreak shellcode loader

C shellcode run via `jitshm_create` (RWX) + `mmap` + `pthread_create(start_routine =
entry_addr)`. Its `payload_args` are the jailbreak's handoff:

```
+0x00 master_pipe[0]  +0x04 master_pipe[1]
+0x08 victim_pipe[0]  +0x0C victim_pipe[1]
+0x10 allproc         +0x18 elfldr_addr  +0x20 elfldr_size
```

**This is the contract:** a jailbreak's job is to hand the pipe fds + `allproc` +
`elfldr` bytes to kexp; kexp builds the rest (its own `src/` has `kernel.c`, `loader.c`,
`iommu.c` — it even does IOMMU work). Our `p2jb_poops.js` already vendors this handoff.

### 2.4 `other&old-explolts/Y2JB/` — the *other* userland entry (YouTube app)

Not WebKit: the YouTube app (Artemis-adjacent) loads remote JS via DNS hijack
(`127.0.0.2`), needs fake-activated account + specific PKG version. Relevant only as an
**alternative userland** if WebKit is patched someday, and for the savedata/lua ecosystem
(the `remote_lua_loader` route we already ruled out for our console).

### 2.5 `other&old-explolts/PS5-Webkit-Execution/`, `slopkit-webkit-exploit-main/`

Minimal WebKit RCE kits (webkit.js + rop.js + rop_slave.js). Same family as our
core/mem/main stack. Nothing new for 13.60.

### 2.6 `other&old-explolts/vue-after-free/` — PS4-oriented but instructive

CVE-2017-7117 userland 5.05–13.04 chained with **Lapse** (7.00–12.02) and
**Poopsploit/NetCtrl** (12.50–13.00). Confirms: userland is *rarely* the blocker; kernel
coverage is. Also the origin of the poops lineage we already carry.

### 2.7 `other&old-explolts/BD-JB5/` — BD-J sandbox escape, "up to 13.42"

Blu-ray Java escape with RemoteJarLoader (:9025) + network logging (:18194). For 13.60+
it says plainly: **"YOU NEED ALREADY JAILBROKEN PS5 — send `bdj_unpatch.elf` to elfldr"**.
One more witness for the elfldr-needs-jailbreak rule, and a *candidate future userland*
if BD-J remains unpatched (but 13.60 needs the unpatch ELF, i.e. a jailbreak first).

### 2.8 `noslop/`, `slopkit*`, `POC/` — hosts and controllers

Offsets controllers, host pages, the poops+slopkit merged lineage of our own tree. The
13.60 entries are **userland-only candidates** (see `bagagwa-1360.md`); none ships kernel
offsets for 13.60, by their own metadata.

### 2.9 `ps5-libs/` — the RE knowledge base

* `results.md`: **verified syscall ABI corrections** — `dlsym=0x24F` (not 0x24E!),
  `nananosleep=0xF0`, `jitshm_create/alias=0x215/0x216`, `kevent=0x16B`,
  `__sys_test_debug_rwmem=0x26B`, `ipmimgr_call=0x26E`, `unlink=0x0A`, mid-stub syscall
  gadget `kernel+0x1CB93`. Parser audits of libSceJpeg/Json2/Ipmi (defensive, no obvious
  bugs at that depth). **IPMI (0x26E) is the kernel-facing RPC surface** if we ever need
  a second entry.
* `plugns/ghidra_psx_ldr-master/`: the Ghidra loader for PS5 `.sprx`/kernel images —
  the tool to produce 13.60 kernel offsets **when we have a 13.60 kernel image**.
* `scripts/` (workspace root): `ps5_deep_analysis.py`, `ps4_elf_analyzer.py`,
  `ps4_fw_differ.py` — the FW-diff pipeline that produced the `-0x4000` rebase proof.

---

## 3. The bug inventory — what is actually available on 13.60

| bug | class | FW range | status on 13.60 |
|---|---|---|---|
| IPV6 rthdr triple-free (p2jb) | refcount UAF via `setsockopt(IPV6_RTHDR)` | 7.00–12.02 | **PATCHED** (validator refuses; measured by our T2c tile) |
| NetCtrl UAF (poops) | netcontrol UAF | ~12.50–13.00 | **PATCHED** on 13.60 (operator-verified; no public chain claims 13.60) |
| Lapse (fcred double-free) | double free | 5.00–12.02 (PS4 12.02 / PS5 10.01) | PATCHED |
| UMTX shm race (CVE-2024-43102) | race UAF | 1.00–7.61 | PATCHED (and WebKit entry needs ≤6.xx) |
| **AIO `aio_multi_wait` mode-0 UAF ("Bagagwa")** | shared waiter-node UAF + refcount dec + optional 727 leak | **≤13.60 per the writeup; the syscall still EXISTS and answers on 13.60 (our T3/T3b tiles measured it live)** | **THE ONLY LIVE LEAD** — unproven end-to-end, ABI partially measured |
| Gezine private zero-day | unknown kernel bug | reported ≤13.60; "13.60 did NOT patch it" per community reports (Jul 2026) | **private**; not actionable |
| `fsc2h_ctrl` kstack free (HackerOne #2900606) | kernel stack free | reported 2025 | no public exploit |
| IPMI surface (0x26E) | kernel RPC | all FW (unaudited) | research lead only |

External context (checked 2026-09-19): press coverage confirms a UAF "up to 13.60" is
known but **no public 13.60 jailbreak exists**; Slopkit has 13.60 *files/offsets* but
"needs verification on real consoles"; BD-JB5 needs a prior jailbreak at 13.60. Everything
public is consistent with our own measurements: **userland works, AIO answers, no kernel
R/W yet anywhere public.**

---

## 4. Why the AIO/Bagagwa lead is real — and what is still missing

Proven **on our console** (the probe logs):

1. `aio_multi_wait` (0x297) exists and answers `EINVAL` on all-zero args (not ENOSYS ⇒
   not removed).
2. **ABI measured**: `ids` = arg1, `num` = arg2 (30-cell matrix; matches PSAITO's
   `(ids, num, states, mode, timeout)`). `num` has a domain check; `states` is
   dereferenced when `num ≥ 1`.
3. `aio_submit_cmd` (0x29D) succeeds with 2 pending MULTI_READ requests on a real
   socketpair/pipe; ids come back **two 32-bit ids at stride 4** (PSAITO encoding).
4. `osem_create(name, 0, 1, 1, 0)` returns a **real handle** (delete==0) — kernel-side
   128-zone allocation works from our executor.
5. The 15:37→17:27 run evolution: the armed call went from EFAULT (wrong shape) to
   **0x0 accepted** — and the **timing tile** proved the wait does *not block*, which
   means the request ids are **not being matched** yet: `NO OBSERVABLE EFFECT` was our
   encoding, not the kernel's patch.

Missing (the honest gap list, in dependency order):

1. **id encoding/matching.** The wait over submitted ids returns immediately without
   blocking → the kernel found no matching pending request. Until `aio_multi_wait(ids,
   num=1)` *blocks* on a pending read, nothing downstream can mean anything. (T3b-idtest
   exists to settle exactly this.)
2. **mode/timeout positions.** The ABI map pins args 1–2; `mode` (the UAF needs mode=0
   with num≥2) and `timeout` are still unmeasured — and mode is the *silent no-UAF*
   risk: wrong mode position, no panic, nothing.
3. **The live-waiter precondition.** `bagagwa-chain`'s pre-filled pipe (reads complete
   immediately ⇒ no waiters to link) is the known-fatal design error to avoid; upstream +
   PSAITO both keep the pipe empty/blocking.
4. **The reclaim object.** Upstream reclaims the freed 0x38 node with an **osem** — but
   the waker derefs `node+0x10` (mtx_lock) *before* the decs, so the node must be
   attacker-shaped. The principled fix (already written in `bagagwa-conversion.md`
   §3): reclaim with **iov/uio worker buffers** (poops' `setup_iov_buffers`,
   `MSG_IOV_NUM=23`), which *are* attacker bytes at a kernel address; keep osem as the
   dec **target** only.
5. **13.60 kernel offsets.** Nobody has them. Needed: the AIO body/waker/cleanup RVAs
   to re-verify the bug shape on 13.60 (the writeup's addresses are for an older FW),
   plus the generic `struct` offsets for stage 2+ (most are stable across 13.x; the
   `thread_list` conflict — 0x64218 vs 0x6C218 — is already hardware-resolved in
   favour of 0x6C218 by our probe).
6. **A disarm story.** No `null_rthdr()` equivalent exists: cleanup unlinks by
   `node->owner` and frees the array regardless. Any armed run that fails is a
   power-cycle. (This is why the armed tile stays behind `?arm=1`.)

---

## 5. The 13.60 development roadmap

### Phase 0 — prerequisites (DONE, keep green)
- [x] WebKit userland + sync executor on 13.60 (proven: getpid/uid/pipes/notify).
- [x] libkernel base derivation + offset verification tiles (ELF magic, P2JB_LK row).
- [x] Syscall convention measured (raw; ENOSYS=0x4e inferred), wedge traps documented.
- [x] AIO reach + partial ABI + osem handle proof + live-request tiles.
- [x] Harnesses: `test_convention` (12 scenarios), `test_abimap`, `test_calibrate`,
      `test_offsets_parity` — all green.

### Phase 1 — settle the AIO ABI completely (read-only; the current bottleneck)
1. **T3b-idtest on hardware** until `aio_multi_wait(ids, num=1)` **BLOCKS** (the timing
   tile now detects this). Try: raw 64-bit id, two 32-bit at stride 4, stride 8, id±1
   (the `4*NREQ` hint says submitted ids may be stored at `base + 4*i`).
2. Once num=1 blocks: **num=2 with a blocking pipe read** — this is the first armed
   shape. Before running it: write the disarm checklist (§4.6) and the beacon design.
3. Locate `mode` and `timeout` by differential (one nonzero at a time from the now-known
   (ids, num) pair), using the 30-cell matrix method already in `pAbiMap`.
4. **Deliverable:** a written, hardware-measured ABI for 0x297 — the thing three upstream
   builds still disagree on.

### Phase 2 — reproduce the UAF (first armed work; power-cycle risk accepted)
1. `aio_multi_wait(valid_ids, num=2, states, mode=0, timeout=0)` with two *pending*
   reads (empty pipe — NOT bagagwa-chain's pre-filled one).
2. Detectors (already built): sentinel osems (WAKE/SPRAY names), witness blocks,
   `osem_delete` behaviour, and the zone model (0x70→128 zone, 0xA8/0xE0→256 zone).
3. Expected first success signal: an osem freed by a single `dec` (its delete returns
   ESRCH afterwards), or a sentinel dword decremented by the waker.
4. If the node is reclaimed uninterestingly: switch the reclaim to **iov/uio buffers**
   (Phase 3) — do not iterate on osem-reclaim hoping for different bytes.

### Phase 3 — convert to kernel R/W (port, do not invent)
1. Reclaim the freed node with iov/uio worker buffers (attacker bytes at kernel addr);
   point `node+0x10` at a valid lock (sprayed fake mtx or a real one we own), `node+0x00`
   and `node+0x08` at the target dwords (osem refcount +0x54, or `f_count` +0x28).
2. **The window:** find the read/write syscall pair for the reclaimed object (the §6
   question in `bagagwa-conversion.md`). Candidates: `osem_getvalue`-family, aio states
   array readback, `aio_get_data` (0x299).
3. Then port `p2jb stage3` **verbatim**: `kwrite_slow(master_pipe_data, pipe_overwrite,
   24)` → PAGE_SIZE pipe R/W → `kread64/kwrite64`. This is the single biggest "already
   written" block we inherit.

### Phase 4 — escalate + load (copy from p2jb, offsets only)
1. stage3_cleanup (refcount bumps, `curproc` via SIGIO), stage4 (rootvnode walk),
   stage5 (ucred + caps + rdir/jdir), stage6 (data_base, degrades gracefully),
   stage7 (dynlib widen).
2. kexp handoff (`payload_args` contract above) → elfldr → etaHEN/ftpsrv.
3. Kernel offsets for 13.60: obtain the 13.60 kernel image (slopkit has FW files),
   run `scripts/ps5_deep_analysis.py` + `ghidra_psx_ldr`, diff against 13.00/13.20
   (the `-0x4000` rebase precedent shows 13.x profiles move little).

### Phase 5 — productise into pooP2JB
1. `bagagwa.js` chain module behind the existing engine (mirroring `p2jb.js` structure
   so the two can be diffed stage-by-stage).
2. `?preflight=1` read-only mode for every stage boundary (the §7 checklist).
3. Harnesses extended: model the UAF, the reclaim, the pipe corruption — the same way
   scenarios 8/11/12 model the tiles today.

---

## 6. What NOT to do (each one is a documented, expensive lesson)

1. Do **not** call unproven syscall numbers (0x7FF wedged real hardware, ~64s freeze,
   three runs dead).
2. Do **not** trust a wait that returns in 0ms over pending requests — that is *our*
   encoding being rejected, not the kernel being patched (v144 log lesson).
3. Do **not** arm with `num ≥ 2` outside the approved arming payload; the harness
   tripwire fails the suite if a valid array ever reaches the kernel with num≥2.
4. Do **not** pre-fill the pipe before submit (bagagwa-chain's fatal design: no pending
   reads ⇒ no waiters ⇒ no UAF, silently).
5. Do **not** paste `X1NON-PSJB/offsets/kernel/kernel-data.js` into any profile — it is
   an incoherent set matching nothing (one value coincidentally matches 11.00-11.60's
   rootvnode).
6. Do **not** read kernel `.text` for gadget scanning — XOM, it faults and kills the
   process. Read the stack; the UMTX repo documents why.
7. Do **not** expect kernel patches/hooks: HV enforces W^X on kernel memory. The
   ceiling of every public PS5 jailbreak is R/W + ucred, not kernel code exec.
8. Do **not** load an ELF without a jailbreak (elfldr is started *by* the kernel
   exploit — §8.1.0 of the handoff).

---

## 7. Bottom line

* Userland on 13.60: **solved** (ours, hardware-proven).
* Kernel bug on 13.60: **one live lead** (AIO UAF), reachable, syscall family proven
  alive, ABI 40% measured, UAF not yet reproduced — and no public implementation to
  copy (three upstream builds disagree and none is verified).
* Everything past the bug: **porting work**, not research — p2jb stages 3–7, kexp,
  elfldr are sitting in this workspace, offsets permitting.
* The genuine research items, in order: **(1) id matching so num=1 blocks, (2) mode
  position, (3) armed num=2 with empty pipe, (4) iov reclaim, (5) the R/W window.**
  Each is a small, measurable step with the panel we already built.
