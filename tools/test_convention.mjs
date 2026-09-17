/*
 * tools/test_convention.mjs -- headless harness for bagagwa_probe.js's errno handling.
 *
 * The probe's verdicts are only as good as its error decoding, and syscall_wrapper is a
 * bare `mov r10,rcx; syscall; ret` with NO -1 conversion (p2jb_lk.js sig 49 89 ca 0f 05 c3).
 * That makes a small positive rax ambiguous: it can be a value OR an errno. Getting this
 * wrong is not cosmetic -- a PATCHED aio_multi_wait returns ENOSYS (0x4e), which a decoder
 * that only understands the -errno shape reads as a small positive SUCCESS, i.e. it prints
 * "aio_multi_wait REACHABLE" on the one firmware where the chain is dead.
 *
 * So this drives the whole probe IIFE against scripted syscall returns and asserts the
 * verdict text for each real-world outcome:
 *
 *   1. raw + AIO present    -> T0 "raw"; T3 REACHABLE (EINVAL); osem must NOT claim a handle
 *   2. raw + AIO PATCHED    -> T3 must say BAGAGWA DEAD          <-- the regression
 *   3. converted            -> T0 "converted"; -EINVAL reads as EINVAL; -EINVAL+ENOSYS DEAD
 *   4. minus1 + T0 unknown  -> expectFail alone must still catch ENOSYS (T3 safe pre-T0)
 *   5. minus1                -> ENOSYS unreadable: T3 must NOT claim reachable
 *
 * Scenario 1 mirrors the real 13.60 log: getpid=0x4f, kqueue=fd 7, pipe2 fds 7/8,
 * aio_init=0x16, aio_multi_wait=0x16, osem create=0x16 open=0xe close=0x3 delete=0x3.
 *
 * Run:  node tools/test_convention.mjs
 * Exit code 0 = all scenarios pass.
 */
import fs from "node:fs";
import vm from "node:vm";

const SRC = new URL("../bagagwa_probe.js", import.meta.url).pathname;
const src = fs.readFileSync(SRC, "utf8");

/* ---------------------------------------------------------------- stub DOM */
function makeEl(tag) {
    return {
        tagName: tag, style: {}, className: "", textContent: "", innerHTML: "",
        children: [], childNodes: [], firstChild: null, scrollTop: 0, scrollHeight: 0,
        appendChild(c) { this.children.push(c); this.childNodes.push(c); this.firstChild = this.childNodes[0] || null; return c; },
        removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); this.firstChild = this.childNodes[0] || null; },
        remove() {}, click() {},
        querySelector() { return makeEl("span"); },
    };
}

const U = (x) => BigInt.asUintN(64, x);

/* The syscalls whose return we care about. `over` overrides the baseline. */
function table(over) {
    const base = {
        "0x14": 0x4fn,          // getpid        -> 79
        "0x27": 0x34n,          // getppid       -> 52
        "0x18": 0x1n,           // getuid
        "0x19": 0x1n,           // geteuid
        "0x2f": 0x1n,           // getgid
        "0x2b": 0x1n,           // getegid
        "0x16a": 0x7n,          // kqueue        -> fd 7
        "0x2af": 0x0n,          // pipe2         -> 0 (success)
        "0x29e": 0x16n,         // aio_init      -> EINVAL
        "0x297": 0x16n,         // aio_multi_wait-> EINVAL
        "0x29d": 0x16n,         // aio_submit_cmd-> EINVAL
        "0x29a": 0x16n,         // aio_multi_cancel -> EINVAL
        "0x296": 0x16n,         // aio_multi_delete -> EINVAL
        "0x35": 0x16n,          // socketpair    -> EINVAL (no pair by default)
        "0x4": 0x16n,           // write         -> EINVAL (refuses by default)
        "0x225": 0x16n,         // osem_create   -> EINVAL
        "0x227": 0xen,          // osem_open     -> EFAULT
        "0x228": 0x3n,          // osem_close    -> ESRCH
        "0x226": 0x3n,          // osem_delete   -> ESRCH
        "0x61": 0x16n,          // socket(AF_INET6) -> EINVAL (validator refuses by default)
        "0x69": 0x16n,          // setsockopt(IPV6_RTHDR) -> EINVAL (13.x validator)
        "0x6a": 0x16n,          // getsockopt(IPV6_RTHDR) -> EINVAL
        "0xc2": 0x16n,          // getrlimit     -> EINVAL
        "0x14b": 0x0n,          // sched_yield   -> 0 (settle loops call it hundreds of times)
    };
    return Object.assign(base, over);
}

function run(name, over, opts) {
    opts = opts || {};
    const storage = {};
    const els = {};
    const getEl = (id) => (els[id] ||= makeEl("div"));
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: getEl };

    const T = table(over);
    const k = (nr) => "0x" + nr.toString(16);
    const calls = [];
    let wedged = false;
    const w = {
        fw_str: "13.60",
        location: { search: opts.search !== undefined ? opts.search : "?sc=1&scauto=1" },   // auto-run only behind scauto

        localStorage: {
            getItem: (key) => (key in storage ? storage[key] : null),
            setItem: (key, v) => { storage[key] = String(v); },
            removeItem: (key) => { delete storage[key]; },
        },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => 0x100000n,
        write_buffer() {},
        alloc_string: () => 0x100000n,
        read_buffer: () => new Uint8Array(new Int32Array([7, 8]).buffer),
        read64: () => 0n,
        syscall(nr, a0, a1, a2, a3, a4) {
            const key = k(nr);
            /* record EVERY provided argument: scenario 9 asserts on multi-arg shapes
             * (setsockopt(fd,41,51,...)); single-arg calls keep their exact old format. */
            const args = [a0, a1, a2, a3, a4];
            let last = -1;
            for (let i = 0; i < args.length; i++) if (args[i] !== undefined) last = i;
            calls.push(key + (last < 0 ? "" : "(" + args.slice(0, last + 1).map((x) => x.toString()).join(",") + ")"));
            /* close(fd): 0 for the fds the probe actually owns, EBADF/errno otherwise. */
            if (nr === 0x006) {
                const fd = a0 === undefined ? -1n : BigInt(a0);
                if (fd === 0x7FFFFFFFn) return opts.badClose !== undefined ? opts.badClose : 0x9n;
                return (fd === 7n || fd === 8n) ? 0x0n : 0x9n;
            }
            /* HARDWARE MODEL: a syscall number with no native stub does NOT return ENOSYS on
             * 13.60 -- it WEDGES (three real runs froze ~64 s at 0x7FF). The model latches
             * wedged and answers `WEDGED-BEFORE:` forever, which any scripted caller that
             * still tries a second call will see. A probe that only calls proven stubs can
             * never hit this path; a probe that regresses to unproven numbers fails here. */
            if (k(nr) === "0x7ff") {
                wedged = true;
                return "WEDGED-BEFORE:0x7ff";
            }
            if (wedged) return "WEDGED-BEFORE:" + key;
            if (key in T) return T[key];
            throw new Error("unscripted syscall " + key);
        },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0x0n, kbase: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    if (opts.noCalibStore) storage["bwslop_lk_13.60"] = JSON.stringify({ slot_expect: "104587", syscall_wrapper: "110263", setjmp: "119875", longjmp: "119964", verified: true });

    const ctx = {
        window: w, document: doc, localStorage: w.localStorage,
        setTimeout, Date, JSON, Math, console,
        Uint8Array, Int32Array, Blob: class { constructor() {} },
        URL: { createObjectURL: () => "blob:x" },
    };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });

    /* runAll is async (60ms between tiles); read the persisted panel log after it settles.
     * 1600ms started truncating after the live-request tile joined the RUN ALL sequence. */
    return new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "", calls }), 1600));
}

/* ---------------------------------------------------------------- the tests */
let fails = 0;
const check = (name, cond, extra) => {
    console.log((cond ? "PASS  " : "FAIL  ") + name + (cond || extra === undefined ? "" : "  -- " + String(extra).slice(-320)));
    if (!cond) fails++;
};

/* 1. raw convention, AIO present -- the shape the real 13.60 console produced. */
{
    const { log, calls } = await run("raw-present", {});
    check("1: T0 measures the raw convention", log.includes("RAW errno convention"));
    check("1: T0 reports EBADF as 0x9 and infers ENOSYS as 0x4e", log.includes("(EBADF)") && log.includes("ENOSYS on this kernel therefore reads 0x4e"));
    check("1: T0 never calls unproven numbers (no 0x7ff on the wire)", !calls.includes("0x7ff"), calls.join(","));
    check("1: T0 runs a canary after the failing call", calls.filter((c) => c.startsWith("0x14")).length >= 2, calls.join(","));
    check("1: T0 marks the ENOSYS shape inferred, not measured", log.includes("inferred"));
    check("1: close(bad fd) decodes as errno 9, not a value", log.includes("errno-raw EBADF"));
    check("1: T3 REACHABLE", log.includes("aio_multi_wait REACHABLE"));
    check("1: T3 names EINVAL", log.includes("(EINVAL)"));
    check("1: T3 says it did not settle the ABI", log.includes("does NOT settle the ABI"));
    /* Assert on the SEMANTIC marker, not the surrounding prose: a negative check written
     * against a whole sentence silently stops testing anything the moment the wording is
     * edited, which is exactly what happened here. */
    check("1: osem does NOT claim a reachable target from a bogus handle",
        !log.includes("REACHABLE KERNEL TARGET"));
    check("1: osem explains the sub-band rax was an errno, not a handle", log.includes("an errno, not a handle"));
    check("1: osem still reports the family EXISTS", log.includes("family EXISTS"));
    check("1: osem tried the documented 5-arg shape FIRST",
        log.indexOf("osem_create(name,0,1,1,0)") < log.indexOf("osem_create(name,attr,0,0,0)"));
    check("1: osem tried all THREE shapes (incl. copied name) before concluding",
        log.includes("osem_create(nameCopy,0,1,1,0)") && log.includes("NO create shape"));
    check("1: osem never sent an errno-sized rax to the epilogue",
        !calls.includes("0x228(22)"), calls.join(","));
    /* The live-request tile must have run inside RUN ALL and NEVER produced a num>=2 wait. */
    check("1: live-request tile ran", log.includes("T3b-VERDICT"), log);
    check("1: live request says num=1 can never reproduce the UAF",
        log.includes("num=1 can never reproduce the UAF") || log.includes("needs num>=2 in ONE call"));
}

/* 1b. the live-request tile end to end: socketpair ok, submit ok, wait num=1, cleanup --
 *      and the numbers the kernel model records must show num<=1 on every 0x297 call. */
{
    const storage = {};
    const els = {};
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")) };
    const T = table({});
    const k = (nr) => "0x" + nr.toString(16);
    const calls = [];
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },   // auto-run only behind scauto

        localStorage: { getItem: (key) => (key in storage ? storage[key] : null), setItem: (key, v) => { storage[key] = String(v); }, removeItem: (key) => { delete storage[key]; } },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => 0x100000n, write_buffer() {}, alloc_string: () => 0x100000n,
        read_buffer: () => new Uint8Array(new Int32Array([7, 8]).buffer),
        read64: () => 0x777n,
        syscall(nr, a0, a1, a2, a3, a4) {
            calls.push(k(nr) + "(" + [a0, a1, a2, a3, a4].filter((x) => x !== undefined).join(",") + ")");
            if (nr === 0x035) return 0x0n;                     // socketpair succeeds
            if (nr === 0x29D) return 0x0n;                     // submit succeeds
            if (nr === 0x297) {                                 // multi_wait
                if (a1 !== undefined && BigInt(a1) >= 2n) throw new Error("TRIPWIRE: multi_wait num>=2 on the wire");
                return T[k(nr)];                                // 0x16 EINVAL (id not ours yet)
            }
            if (nr === 0x29A || nr === 0x296) return 0x0n;      // cancel/delete succeed
            if (nr === 0x004) return 0x1n;                      // write completes a read
            if (nr === 0x006) return (a0 === 7n || a0 === 8n) ? 0x0n : 0x9n;
            if (k(nr) in T) return T[k(nr)];
            throw new Error("unscripted syscall " + k(nr));
        },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0x0n, kbase: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = { window: w, document: doc, localStorage: w.localStorage, setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array, Blob: class { constructor() {} }, URL: { createObjectURL: () => "blob:x" } };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });
    const { log } = await new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "" }), 1600));
    check("1b: socketpair proven live (fds named)", log.includes("T3b-socketpair") && log.includes("live pair"), log);
    check("1b: submit ok with pending reads", log.includes("2 pending MULTI_READ requests"), log);
    check("1b: the num=1 wait answered", log.includes("multi_wait(ids, num=1)"), log);
    check("1b: cleanup ran (cancel+delete)", log.includes("cancel=0x0") && log.includes("delete=0x0"), log);
    check("1b: verdict distinguishes measured vs never-armed",
        log.includes("LIVE-REQUEST REACHABILITY MEASURED") && log.includes("That step stays behind your explicit go"), log);
    /* THE tripwire, parsed from the recorded argument lists: for every 0x297 call that has
     * TWO nonzero arguments in array+num positions, num must be <= 1. Position matters --
     * in the ABI sweep the BUFFER itself lands in a1 (row arg2), so treating a1 as num
     * unconditionally misreads the sweep. The armed-bug condition is a VALID array (== the
     * malloc stub address 0x100000) in one register AND a num >= 2 in another; the model
     * above already throws if the probe ever constructs that call. */
    const mallocAddr = 0x100000n;
    const badWait = calls.filter((c) => {
        if (!c.startsWith("0x297(")) return false;
        const parts = c.slice(6, -1).split(",").map((s) => BigInt(s || "0"));   // skip "0x297("
        const hasValidArray = parts.some((v) => v === mallocAddr);
        const nums = parts.filter((v) => v !== mallocAddr && v >= 2n);
        return hasValidArray && nums.length > 0;
    });
    check("1b: TRIPWIRE -- no valid array with num>=2 reached the kernel", badWait.length === 0, calls.join(","));
}

/* 2. raw convention, firmware PATCHED -- the regression that mattered.
 *    Under the old decoder 0x4e read as a small positive value and printed REACHABLE. */
{
    const { log } = await run("raw-patched", { "0x297": 0x4en });
    check("2: T0 still measures raw", log.includes("RAW errno convention"));
    check("2: aio_multi_wait 0x4e decodes as ENOSYS", log.includes("errno-raw ENOSYS"));
    check("2: T3 reports BAGAGWA DEAD", log.includes("BAGAGWA DEAD"));
    check("2: T3 does NOT report reachable", !log.includes("REACHABLE"));
}

/* 3. converted (-errno in rax). */
{
    const { log } = await run("converted", { "0x297": U(-22n) }, { badClose: U(-9n) });
    check("3: T0 measures the converted convention", log.includes("CONVERTED convention"));
    check("3: T0 warns the AIO refusal must read -EINVAL", log.includes("(-EINVAL)"));
    check("3: -22 decodes as EINVAL", log.includes("-errno EINVAL"));
    check("3: T3 REACHABLE", log.includes("aio_multi_wait REACHABLE"));

    const p = await run("converted-patched", { "0x297": U(-78n) }, { badClose: U(-9n) });
    check("3b: -78 decodes as ENOSYS", p.log.includes("-errno ENOSYS"));
    check("3b: T3 reports BAGAGWA DEAD", p.log.includes("BAGAGWA DEAD"));
}

/* 4. plain -1 with T0 too broken to decide: expectFail alone must still catch ENOSYS,
 *    because a call with num=0 cannot have succeeded whatever the convention is. */
{
    const { log } = await run("minus1-patched", { "0x297": 0x4en }, { badClose: 0x1234n });
    check("4: T0 refuses to name a convention", log.includes("UNEXPECTED"));
    check("4: T3 STILL reports BAGAGWA DEAD (expectFail, no convention needed)", log.includes("BAGAGWA DEAD"));
    check("4: T3 does not report reachable", !log.includes("REACHABLE"));
}

/* 5. plain -1 convention: errno is outside rax, so ENOSYS is unknowable. Say so. */
{
    const { log } = await run("minus1", { "0x297": 0xFFFFFFFFFFFFFFFFn }, { badClose: 0xFFFFFFFFFFFFFFFFn });
    check("5: T0 detects the -1 convention", log.includes("PLAIN -1 convention"));
    check("5: T0 says the errno NUMBER is not recoverable", log.includes("not recoverable from rax"));
    check("5: T3 says CANNOT DETERMINE", log.includes("CANNOT DETERMINE"));
    check("5: T3 does not claim reachable", !log.includes("REACHABLE"));
}

/* 6. the range ladder: a sub-band rax (0x22) is an errno and never reaches the epilogue;
 *     a handle-sized rax must be proven by delete/close returning 0. */
{
    const { log } = await run("osem-correct", {});
    check("6: sub-band 0x22 is declared an errno, not chased", log.includes("an errno, not a handle"));
    check("6: no green refcount verdict", !log.includes("REACHABLE KERNEL TARGET"));
    const p = await run("osem-real", { "0x225": 0x1234n, "0x228": 0x0n, "0x227": 0x0n, "0x226": 0x0n });
    check("6b: a handle-sized rax PROVEN by delete==0 IS accepted",
        p.log.includes("PROVEN: osem_delete returned 0"), p.log);
    check("6b: the verdict names the 128-zone prerequisite", p.log.includes("128 zone"));
    const q = await run("osem-candidate-refused",
        { "0x225": 0x1234n, "0x226": 0x3n, "0x228": 0x1n, "0x227": 0xen });
    check("6c: an unproven candidate is refused with the epilogue errnos shown",
        q.log.includes("handle CANDIDATE") && q.log.includes("ESRCH") && q.log.includes("EPERM"), q.log);
    check("6c: verdict names the name/attr contract as the open question",
        q.log.includes("name/attr CONTRACT") && q.log.includes("Next differential"));
}

/* 6c. THE 0x80 CUTOFF REGRESSION -- the 20:13 hardware run's evidence: 0xa6 is a handle
 *      candidate (delete(0xa6)=0 on hardware) and must reach the epilogue; 0x22 stays an
 *      errno. The first cut used 0x100 and masked the likely-real handle. */
{
    const r = await run("osem-band-a6", { "0x225": 0xa6n, "0x226": 0x0n });
    check("6c: 0xa6 reaches the epilogue (cutoff is 0x80)",
        r.log.includes("PROVEN: osem_delete returned 0"), r.log);
    const s = await run("osem-band-sub", { "0x225": 0x79n, "0x226": 0x3n });
    check("6c: 0x79 (below 0x80) is still declared an errno", s.log.includes("an errno, not a handle"), s.log);
    const t = await run("osem-band-close", { "0x225": 0xa7n, "0x226": 0x3n, "0x228": 0x0n });
    check("6c: candidate proven by close (delete refused first) is accepted",
        t.log.includes("PROVEN: osem_close returned 0"), t.log);
}

/* 6b. THE WEDGE REGRESSION -- the exact hardware failure from 2026-09-16: if anything ever
 *      reintroduces an out-of-range call, the kernel model wedges and the run must not
 *      silently continue. */
{
    const { log, calls } = await run("wedge-guard", { "0x297": 0x16n });
    check("6b: no unproven syscall is ever on the wire", !calls.includes("0x7ff"), calls.join(","));
    check("6b: no WEDGED marker anywhere in the log", !log.includes("WEDGED-BEFORE"));
    check("6b: T0 still reaches its verdict", log.includes("T0-VERDICT"));
}

/* 7. AUTO-RUN GATE -- without ?scauto=1 the panel comes up IDLE after userland: no tile
 *      runs, and the operator must tap RUN ALL. */
{
    const { log } = await run("autorun-off", { "0x297": 0x16n }, { search: "?sc=1" });
    check("7: no tile ran without scauto (no RUN ALL header)", !log.includes("=== RUN ALL ==="), log.slice(-300));
    check("7: the panel says it is idle and waiting", log.includes("Auto-run is OFF"));
    check("7: userland still came up (the boot itself completed)", log.includes("Bagagwa panel up on 13.60"));
    const { log: log2 } = await run("autorun-on", { "0x297": 0x16n }, { search: "?sc=1&scauto=1" });
    check("7: scauto=1 still auto-runs", log2.includes("=== RUN ALL ==="), log2.slice(-300));
}

/* 8. THE ARMED TILE -- behind ?arm=1&scauto=1 it renders, runs LAST, and the model must
 *      see EXACTLY ONE num>=2 multi_wait (the UAF itself) with a VALID ids array -- the
 *      whole point of the exercise. This scenario carries a REAL MEMORY MODEL: malloc
 *      hands out distinct addresses and write/read round-trip, so the tile's detector
 *      integrity self-check passes honestly and the verdict must be NO OBSERVABLE EFFECT
 *      (the model kernel never decrements the sentinels). A stub read64() would trip the
 *      self-check and the tile would (correctly) refuse to arm -- which is exactly what
 *      the first draft of this scenario got wrong. */
{
    const storage = {};
    const els = {};
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")) };
    const T = table({});
    const k = (nr) => "0x" + nr.toString(16);
    const calls = [];
    let armedSeen = 0;
    /* -- the memory model -- */
    let nextAddr = 0x100000n;
    const mem = new Map();                                  // Number(addr) -> Uint8Array
    const LO = 0x100000n, HI = 0x300000n;
    const inRange = (p) => p !== undefined && p >= LO && p < HI;
    const memGet = (addr, len) => {
        const a = Number(addr);
        let b = mem.get(a);
        if (!b || b.length < len) { b = new Uint8Array(len); mem.set(a, b); }
        return b;
    };
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1&arm=1" },
        localStorage: { getItem: (key) => (key in storage ? storage[key] : null), setItem: (key, v) => { storage[key] = String(v); }, removeItem: (key) => { delete storage[key]; } },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => { const a = nextAddr; nextAddr += 0x100n; return a; },
        alloc_string: () => { const a = nextAddr; nextAddr += 0x100n; return a; },
        write_buffer: (addr, bytes) => { memGet(addr, bytes.length).set(bytes); },
        read_buffer: (addr, len) => new Uint8Array(memGet(addr, len)),
        read64: (addr) => { const b = memGet(addr, 8); let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; },
        syscall(nr, a0, a1, a2, a3, a4) {
            calls.push(k(nr) + "(" + [a0, a1, a2, a3, a4].filter((x) => x !== undefined).join(",") + ")");
            if (nr === 0x035) return 0x0n;                     // socketpair succeeds
            if (nr === 0x29D) return 0x0n;                     // submit succeeds
            if (nr === 0x297) {
                if (inRange(a0) && a1 !== undefined && BigInt(a1) >= 2n) armedSeen++;   // THE UAF
                else if (a1 !== undefined && BigInt(a1) >= 2n && !inRange(a0)) throw new Error("num>=2 with an INVALID array -- not even the armed tile may do that");
                return T[k(nr)];
            }
            if (nr === 0x29A || nr === 0x296) return 0x0n;
            if (nr === 0x004) return 0x1n;
            if (nr === 0x006) return (a0 === 7n || a0 === 8n) ? 0x0n : 0x9n;
            if (k(nr) in T) return T[k(nr)];
            throw new Error("unscripted syscall " + k(nr));
        },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0x0n, kbase: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = { window: w, document: doc, localStorage: w.localStorage, setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array, Blob: class { constructor() {} }, URL: { createObjectURL: () => "blob:x" } };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });
    const { log } = await new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "" }), 1600));
    check("8: arm=1 renders the UNSAFE tile", log.includes("UAF arm (UNSAFE)"), log.slice(-200));
    check("8: RUN ALL announces ARM MODE", log.includes("ARM MODE"));
    check("8: detector self-check PASSED before arming", !log.includes("DETECTOR UNRELIABLE"), log);
    check("8: EXACTLY ONE armed multi_wait (num>=2, valid ids) reached the model", armedSeen === 1, "seen=" + armedSeen);
    check("8: the armed call used the measured ABI (ids in arg1, num in arg2)",
        calls.some((c) => { if (!c.startsWith("0x297(")) return false; const p = c.slice(6, -1).split(","); return p[1] === "2" && inRange(BigInt(p[0])); }),
        calls.filter((c) => c.startsWith("0x297")).join(" "));
    check("8: the tile woke the pending reads", log.includes("write(wfd,1) wake"), log);
    check("8: four WAKE reclaim osems were created", log.includes("osem_create(WAKE0000)") && log.includes("osem_create(WAKE0003)"), log);
    check("8: verdict says no-observable-effect on the model kernel (sentinels untouched)",
        log.includes("NO OBSERVABLE EFFECT"), log.slice(-500));
    check("8: notify carried the arm result", log.includes("NOTIFY  ARM:"), log.slice(-500));
}

/* 8b. WITHOUT ?arm=1 the armed tile must NOT render and NO num>=2 may ever fire. */
{
    const { log, calls } = await run("arm-absent", { "0x297": 0x16n });
    check("8b: no UNSAFE tile without arm=1", !log.includes("UAF arm (UNSAFE)"));
    check("8b: no num>=2 multi_wait anywhere", !calls.some((c) => c.startsWith("0x297(") && c.split(",")[1] === "2"), calls.join(","));
}

/* 9. THE P2JB/poops TILE -- the patched 12.x kernel-bug surface, called for real. The
 *    baseline kernel refuses every bug shape (EINVAL on the socket option); the tile must
 *    still run all four probes, close EVERY descriptor, and print its verdict WITHOUT
 *    ever writing kernel memory or calling an unproven number. */
{
    const { log, calls } = await run("t2c-refused", {});
    check("9: T2c calls a real AF_INET6 socket", calls.some((c) => c.startsWith("0x61(")), calls.join(","));
    check("9: T2c drives setsockopt(IPV6_RTHDR) with the 0x38 tag",
        calls.some((c) => c.startsWith("0x69(") && c.includes(",41,51,")), calls.join(","));
    check("9: T2c probes the IPV6_FL_AUDIT validator", calls.some((c) => c.startsWith("0x69(") && c.includes(",41,109,")), calls.join(","));
    check("9: T2c drives getsockopt(IPV6_RTHDR)", calls.some((c) => c.startsWith("0x6a(")), calls.join(","));
    check("9: T2c drives getrlimit(NOFILE)", calls.some((c) => c.startsWith("0xc2(")), calls.join(","));
    check("9: T2c verdict reached on the refusing kernel", log.includes("T2c-VERDICT") && log.includes("closed again"), log.slice(-600));
    check("9: T2c does NOT claim the cross-fd shape reproduced", !log.includes("CROSS-FD-RETURNED-0"));
    /* every close in the log comes back 0 -- nothing stays open */
    check("9: T2c cleanup closed everything it opened", !log.includes("close(ipv6)  ret=0x16") && log.includes("close(kq)"), log.slice(-600));
}

/* 9b. the headline path: if a kernel ever ACCEPTS the tag pair AND echoes it AND lets the
 *     cross-descriptor read return 0, the verdict must say the 12.x primitives are ALIVE. */
{
    /* 0x35 must also succeed: the cross-descriptor probe (the headline trigger) needs a
     * victim pair to exist; without one the tile skips it and no ALIVE verdict can fire. */
    const { log } = await run("t2c-alive", { "0x61": 0x5n, "0x69": 0x0n, "0x6a": 0x0n, "0x35": 0x0n });
    check("9b: accepted pair + echo => the verdict says the 12.x primitives are alive",
        log.includes("THE 12.x CHAIN PRIMITIVES ARE ALIVE"), log.slice(-600));
    check("9b: notify carried the T2c result", log.includes("NOTIFY  T2c:"), log.slice(-600));
}

console.log(fails ? `\n${fails} check(s) FAILED` : "\nall convention scenarios pass");
process.exit(fails ? 1 : 0);
