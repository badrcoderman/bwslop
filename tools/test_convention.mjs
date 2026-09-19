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
        "0x87": 0x0n,           // socketpair    -> 0 (real PS5 number; succeeds by default)
        /* 0x35 is sigtimedwait, NOT socketpair -- our old tiles mislabeled it and its
         * EFAULT polluted three hardware runs. The model keeps it only as a tripwire:
         * if any tile ever calls 0x35 expecting a pair again, the assertions fail. */
        "0x35": 0xen,           // sigtimedwait  -> EFAULT (never called anymore)
        "0x2ca": 0x0n,          // SYS_NOTIFY_APP_EVENT -> 0 (toast queued; slopkit recipe)
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
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: getEl, addEventListener: () => { } };

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
        read32: () => 0xA0C9n,
        syscall(nr, a0, a1, a2, a3, a4) {
            const key = k(nr);
            /* opts.waitMs models a kernel that ACTUALLY BLOCKS in aio_multi_wait. Without a
             * model that blocks, the probe's new timing diagnosis would only ever exercise
             * one branch, and the other one -- the one that distinguishes "the kernel is
             * patched" from "our ids were not recognised" -- would never be tested. */
            if (key === "0x297" && opts.waitMs) {
                const t0 = Date.now();
                while (Date.now() - t0 < opts.waitMs) { /* spin, like the real executor */ }
            }
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
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0x0n, kbase: opts.kbase !== undefined ? opts.kbase : 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    /* window.call = the executor's native-call primitive (p2jb_poops.js). Only present
     * when a scenario supplies it; notify's route 1 needs it, route 2 (syscall) is the
     * fallback. `callRet` is what the mocked libkernel function answers. */
    if (opts.callRet !== undefined) {
        w.call = function (fn, a0, a1, a2, a3) {
            calls.push("call+0x" + BigInt(fn).toString(16));
            return opts.callRet;
        };
    }
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

/* 10. notify route ladder -- proves the slopkit/GoldHEN-proven libkernel FUNCTION
 *    (sceKernelSendNotificationRequest at kbase+0x48B0, shape 0/req/0xC30/0) is tried
 *    FIRST when window.call exists and a kbase is known, and that the syscall 0x2CA
 *    fallback is only used when that route does not answer 0. */
{
    const { log, calls } = await run("notify-call-route", {}, {
        search: "?sc=1&scauto=0", kbase: 0x820000000n, callRet: 0n,
    });
    check("10: libkernel notify call (kbase+0x48b0) was made", calls.some((c) => /^call\+0x[0-9a-f]+48b0$/.test(c)), calls.join(","));
    check("10: toast delivered via route 1", log.includes("DELIVERED via route 1"), log.slice(-400));
    check("10: syscall 0x2ca NOT used once the function route answered 0", !calls.some((c) => c.startsWith("0x2ca")), calls.join(","));
}
{
    const { log, calls } = await run("notify-syscall-fallback", {}, {
        search: "?sc=1&scauto=0", kbase: 0x820000000n, callRet: 0x1n,
    });
    check("10b: the function route was tried and refused (ret 1)", calls.some((c) => /^call\+0x[0-9a-f]+48b0$/.test(c)), calls.join(","));
    check("10b: syscall 0x2ca fallback used when the function route failed", calls.some((c) => c.startsWith("0x2ca")), calls.join(","));
    check("10b: toast delivered via route 2", log.includes("DELIVERED via route 2"), log.slice(-400));
}

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
    /* THE CRASH SELF-TEST MUST NEVER BE REACHABLE FROM RUN ALL. It closes the tab by
     * design, so an accidental wiring as a tile would turn every suite run into a process
     * death. Asserted on the observable, not the wiring: a normal RUN ALL must produce NO
     * crash row at all. */
    check("1: the crash self-test did NOT run during RUN ALL",
        !log.includes("crash-persistence self-test") && !log.includes("sc CRASH"), log.slice(-500));
    check("1: live request says num=1 can never reproduce the UAF",
        log.includes("num=1 can never reproduce the UAF") || log.includes("needs num>=2 in ONE call"));
}

/* 1b. the live-request tile end to end: socketpair ok, submit ok, wait num=1, cleanup --
 *      and the numbers the kernel model records must show num<=1 on every 0x297 call. */
{
    const storage = {};
    const els = {};
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")), addEventListener: () => { } };
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
    /* --- the id-encoding / timing diagnosis. These live HERE, not in scenario 1: in
     *     scenario 1's model aio_submit_cmd answers EINVAL, so the live tile exits at
     *     "submit refused" and never reaches any of these rows. Asserting them there would
     *     have been a test that could only have passed by accident. -------- */
    check("1b: T3b decodes ids as TWO 32-bit values, not one 64-bit handle",
        /T3b-submit[\s\S]{0,320}decoded as two 32-bit ids at stride 4/.test(log), log.slice(-900));
    check("1b: T3b prints a TIMING row for the wait", log.includes("T3b-timing"), log.slice(-900));
    check("1b: T3b timing says it did NOT block while the reads were pending (0ms model)",
        /T3b-timing[\s\S]{0,400}It did NOT block/.test(log), log.slice(-900));
    check("1b: T3b names the failure as OUR encoding, not a patched kernel",
        /T3b-timing[\s\S]{0,600}not a patched kernel/.test(log), log.slice(-900));
    /* out() pads tag and detail with TWO spaces, so match on the row NAME, not a
     * single-space phrase -- the first version of this assertion failed on whitespace
     * alone while the rows were plainly present. */
    check("1b: T3b runs the id-packing differential and prints a verdict",
        log.includes("T3b-idtest") && log.includes("stride4-as-submitted")
        && log.includes("stride8-widened") && log.includes("T3b-idverdict"),
        log.split("\n").filter((l) => l.includes("T3b-id")).join(" // ").slice(-400));
    /* THE FALSE-POSITIVE FALSIFICATION. This model answers EINVAL (0x16) to EVERY 0x297
     * call, exactly like a kernel rejecting the argument set. The differential must NOT
     * read that as "the kernel recognised this packing" -- the whole point of separating
     * 0x0 / EINVAL / other. The first implementation DID claim a winner here. */
    check("1b: an EINVAL-everywhere kernel is NOT reported as a recognised packing",
        !/T3b-idverdict[\s\S]{0,200}actually reacted to/.test(log),
        log.split("\n").filter((l) => l.includes("T3b-idverdict")).join(" // "));
    check("1b: the differential explains why EINVAL is not recognition",
        /T3b-idverdict[\s\S]{0,400}rejecting the ARGUMENT SET/.test(log),
        log.split("\n").filter((l) => l.includes("T3b-idverdict")).join(" // "));

    /* --- THE ARM TIMING ROW, exercised end to end. The ARM tile needs ?arm=1; with a
     *     non-blocking model the row must say the UAF was NOT armed and must explicitly
     *     refuse to let the operator read it as "this firmware is patched". -------- */

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
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")), addEventListener: () => { } };
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
    /* --- THE ARM TIMING ROW. This scenario is the only one that arms, so it is the only
     *     place these rows exist. On a 0ms model kernel the row must say the call did NOT
     *     block, and the verdict must explicitly refuse to let that be read as "the firmware
     *     is patched" -- the wrong verdict this panel is most likely to print. ---- */
    check("8: ARM-timing row exists and says the armed call did NOT block (0ms model)",
        /ARM-timing[\s\S]{0,520}did NOT block/.test(log), log.slice(-1000));
    /* The verdict phrase is its OWN wording -- the "not as a patched kernel" line lives in
     * the ARM-timing row, not in the verdict. Anchoring both to the same sentence is how an
     * assertion silently stops testing anything. */
    check("8: the ARM verdict blames the id encoding, not the firmware",
        /ARM-VERDICT[\s\S]{0,1200}NOT evidence about whether/.test(log),
        log.split("\n").filter((l) => l.includes("ARM-VERDICT")).join(" // ").slice(-400));
    check("8: ARM-timing carries the millisecond measurement",
        /ARM-timing[\s\S]{0,120}returned after \d+ms/.test(log), log.slice(-900));
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
    /* 0x076 = SYS_GETSOCKOPT. The tree used to call 0x06A here, which is SYS_LISTEN in
     * its own syscalls.js -- the model now asserts the CORRECTED number on the wire. */
    check("9: T2c drives getsockopt(IPV6_RTHDR) on 0x076", calls.some((c) => c.startsWith("0x76(")), calls.join(","));
    check("9: T2c no longer mislabels listen (0x06A) as getsockopt", !calls.some((c) => c.startsWith("0x6a(") && c.includes(",41,51,")), calls.join(","));
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
    const { log } = await run("t2c-alive", { "0x61": 0x5n, "0x69": 0x0n, "0x76": 0x0n, "0x87": 0x0n });
    check("9b: accepted pair + echo => the verdict says the 12.x primitives are alive",
        log.includes("THE 12.x CHAIN PRIMITIVES ARE ALIVE"), log.slice(-600));
    check("9b: notify carried the T2c result", log.includes("NOTIFY  T2c:"), log.slice(-600));
}

/* 1c. THE FALSIFICATION of the new timing diagnosis. A kernel model that really BLOCKS in
 *     aio_multi_wait must flip the verdict from "did NOT block" to "BLOCKED" -- and, when
 *     the armed call blocks but no detector moves, the ARM verdict must stop blaming the ids
 *     and say the link happened instead. A diagnostic that cannot be made to say the other
 *     thing is not measuring anything. */
{
    /* 0x29d (aio_submit_cmd) must SUCCEED for the live tile to reach its timing row at all. */
    const { log } = await run("aio-blocks", { "0x29d": 0x0n }, { waitMs: 45 });
    check("1c: T3b timing flips to BLOCKED when the kernel actually waits",
        /T3b-timing[\s\S]{0,400}It BLOCKED/.test(log), log.split("\n").filter((l) => l.includes("T3b-timing")).join(" // "));
    check("1c: a blocking wait means the ids ARE recognised (verdict says so)",
        /ID ENCODING:[\s\S]{0,200}does recognise our ids/.test(log), log.slice(-1400));
    check("1c: T3b timing no longer claims the ids were unrecognised",
        !/T3b-timing[\s\S]{0,400}It did NOT block/.test(log), log.split("\n").filter((l) => l.includes("T3b-timing")).join(" // "));
}

/* 11. LIBKERNEL EVIDENCE TOOLS -- offsets verification, the bounded peek, and the
 *     OOM-safe streaming dumper.
 *
 *     This scenario builds a real MEMORY MODEL: a fake libkernel image whose bytes at
 *     each anchor RVA are known, so the tiles' rows can be checked against the bytes that
 *     are genuinely at those addresses. It then drives the dumper end to end through a
 *     recording fetch() and DECODES every chunk back -- a dump that sends plausible-
 *     looking base64 is worthless if it does not round-trip, and that is exactly the bug
 *     a shape-only test misses. */
{
    const KB = 0x820000000n;
    /* Big enough for EVERY anchor RVA (the largest is thread_list at 0x6C218). A too-small
     * image is not a harmless test shortcut: it exercises the "unreadable" branch and makes
     * a passing tile look like a failing one. */
    const IMG = new Uint8Array(0x80000);                 /* the fake libkernel window */
    for (let i = 0; i < IMG.length; i++) IMG[i] = (i * 7 + 0x41) & 0xff;   /* known, non-zero */
    /* anchor RVAs the probe uses (from P2JB_LK + the notify entry) */
    const ANCHORS = { "0x1988b": 1, "0x1aeb7": 1, "0x1d443": 1, "0x1d49c": 1, "0x6c218": 1, "0x48b0": 1 };

    const storage = {}, els = {};
    const doc = {
        head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t),
        getElementById: (id) => (els[id] ||= makeEl("div")), addEventListener: () => { },
    };
    els["bwp-durl"] = makeEl("input"); els["bwp-durl"].value = "http://collector.test/dump";
    els["bwp-dlen"] = makeEl("input"); els["bwp-dlen"].value = "0x1000";
    els["bwp-dchunk"] = makeEl("input"); els["bwp-dchunk"].value = "0x400";
    els["bwp-dbase"] = makeEl("input"); els["bwp-dbase"].value = "lk";

    const posts = [];
    const T = table({});
    const calls = [];
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },
        localStorage: {
            getItem: (key) => (key in storage ? storage[key] : null),
            setItem: (key, v) => { storage[key] = String(v); },
            removeItem: (key) => { delete storage[key]; },
        },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => 0x100000n, write_buffer() {}, alloc_string: () => 0x100000n,
        /* the memory model: read_buffer(addr,n) returns the fake image bytes */
        read_buffer(addr, n) {
            const off = Number(BigInt(addr) - KB);
            if (off < 0 || off + n > IMG.length) throw new Error("unmapped");
            return IMG.slice(off, off + n);
        },
        read64: () => 0n,
        /* fetch recorder: every POST body is kept so the chunks can be decoded */
        fetch(url, init) { posts.push(String(init && init.body || "")); return { then: (ok) => { ok && ok(); return { then: (a) => (a && a(), {}) }; } }; },
        syscall(nr) { calls.push("0x" + nr.toString(16)); return T["0x" + nr.toString(16)] !== undefined ? T["0x" + nr.toString(16)] : 0x0n; },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0x0n, kbase: KB, wbase: 0x810000000n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = {
        window: w, document: doc, localStorage: w.localStorage,
        setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array,
        /* fetch must be a GLOBAL in the vm, the way it is in a browser: the probe calls
         * bare fetch(). Leaving it only on `window` is what made the first run of this
         * scenario report "0 chunks sent" with no error at all. */
        fetch: w.fetch,
        Blob: class { constructor() { } }, URL: { createObjectURL: () => "blob:x" },
    };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });

    /* RUN ALL is async and the dump is near the end. CAPTURE THE LOG REPEATEDLY: the
     * persisted store is a bounded TAIL, so a single read at the end would silently lose
     * whatever the earlier tiles wrote. Reading it at intervals and joining the distinct
     * fragments reconstructs the whole run -- which is also how the panel's own crash-
     * recovery log is meant to be read. */
    const frags = [];
    let elapsed = 0;
    for (const t of [400, 700, 1000, 1400, 1900, 2600]) {
        await new Promise((res) => setTimeout(res, t - elapsed));
        elapsed = t;
        const s = storage["bwslop_sc_log"] || "";
        if (s && (frags.length === 0 || s !== frags[frags.length - 1])) frags.push(s);
    }
    const log = frags.join("\n");

    /* -- offsets tile -------------------------------------------------------- */
    check("11: offsets tile prints the live libkernel base it resolved",
        log.includes("OFF-base") && log.includes("0x820000000"), log.slice(-800));
    check("11: offsets tile reads an anchor and shows the qword that is REALLY there",
        /OFF-thread_list {2}\+0x6c218 \u2192 0x[0-9a-f]+/.test(log),
        "OFF rows: " + log.split("\n").filter((l) => l.includes("OFF-")).join(" // ").slice(-400));
    check("11: offsets verdict counts live anchors and warns on zeroed ones",
        log.includes("OFF-verdict") && /\d+ anchor\(s\) hold non-zero code/.test(log), log.slice(-800));
    check("11: every anchor RVA in the live P2JB_LK row was read (none unreadable)",
        /OFF-verdict {2}6 anchor\(s\) hold non-zero code, 0 zeroed, 0 unreadable/.test(log),
        log.split("\n").filter((l) => l.includes("OFF-verdict")).join(" // "));

    /* -- peek tile ---------------------------------------------------------- */
    check("11: peek reads the notify entry window", log.includes("PEEK-notify entry") && log.includes("0x48b0"), log.slice(-1500));
    check("11: peek prints real bytes, not a placeholder", /PEEK-notify entry[\s\S]{0,400}0x8200048b0/.test(log), log.slice(-1500));
    check("11: peek verdict names how many windows were read", log.includes("PEEK-verdict"), log.slice(-600));

    /* -- the dump: chunking, framing and ROUND-TRIP ------------------------- */
    check("11: dump announced the stream with the base and the target",
        log.includes("DUMP") && log.includes("streaming libkernel"), log.slice(-900));
    const begin = posts.find((p) => p.startsWith("BAGA-BEGIN"));
    const end = posts.find((p) => p.startsWith("BAGA-END"));
    const chunks = posts.filter((p) => p.startsWith("BAGA "));
    check("11: dump sent a BAGA-BEGIN frame carrying fw/base/total",
        !!begin && begin.includes("fw=13.60") && begin.includes("base=0x820000000") && begin.includes("total=4096"), begin);
    check("11: dump sent a BAGA-END frame with chunk/byte/failed counts", !!end && end.includes("chunks=") && end.includes("bytes="), end);
    check("11: dump chunked 4096 bytes at 1024 per POST (4 chunks)", chunks.length === 4, "got " + chunks.length);
    check("11: dump verdict claims nothing was retained and reports the counts",
        log.includes("DUMP-VERDICT") && log.includes("Nothing was retained in memory"), log.slice(-700));

    /* decode every chunk and compare against the image -- the real test */
    const B64D = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let reassembled = new Uint8Array(4096), badFrames = 0, sumBytes = 0;
    for (const c of chunks) {
        const m = /^BAGA (0x[0-9a-f]+) (\d+) ([A-Za-z0-9+/=]+)\n$/.exec(c);
        if (!m) { badFrames++; continue; }
        const off = Number(BigInt(m[1])), len = Number(m[2]);
        const s = m[3];
        let o = 0;
        for (let i = 0; i < s.length; i += 4) {
            const n = [0, 1, 2, 3].map((j) => B64D.indexOf(s[i + j]));
            const v = (n[0] << 18) | (n[1] << 12) | ((n[2] < 0 ? 0 : n[2]) << 6) | (n[3] < 0 ? 0 : n[3]);
            if (o < len) reassembled[off + o++] = (v >> 16) & 0xff;
            if (o < len) reassembled[off + o++] = (v >> 8) & 0xff;
            if (o < len) reassembled[off + o++] = v & 0xff;
        }
        sumBytes += len;
    }
    check("11: every BAGA frame is well formed", badFrames === 0, badFrames + " malformed");
    check("11: dumped byte count adds up to the requested length", sumBytes === 4096, "got " + sumBytes);
    let mismatches = 0;
    for (let i = 0; i < 4096; i++) if (reassembled[i] !== IMG[i]) mismatches++;
    check("11: the base64 DECODES back to the exact libkernel bytes (round-trip)",
        mismatches === 0, mismatches + " byte(s) differ");
}

/* 12. THE NEW EVIDENCE TILES + THE LAYOUT FIX -- verified against a real memory model and
 *     a modelled kernel, not merely present in the source.
 *
 *     What is asserted here:
 *       - verify:      the ELF magic is read from the real base and the verdict is positive
 *                      (and the missing webkit mapping is reported, not silently skipped);
 *       - offtable:    the LIVE P2JB_LK row is printed field by field;
 *       - umtx:        both surfaces are probed all-zero and reported as present;
 *       - ftp:         a real socket/bind/listen sequence runs AND the FreeBSD dirent
 *                      parser turns a crafted directory buffer into the right names;
 *       - the dumper:  the byte ceiling CLAMPS a too-large request, and the heap watchdog
 *                      stops the dump itself before the tab dies;
 *       - the layout:  the tiles region exists and the show/hide toggle actually flips it.
 */
{
    const KB = 0x820000000n;
    const storage = {}, els = {}, posts = [], calls = [];
    const doc = {
        head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t),
        getElementById: (id) => (els[id] ||= makeEl("div")), addEventListener: () => { },
    };
    els["bwp-durl"] = makeEl("input"); els["bwp-durl"].value = "http://collector.test/dump";
    els["bwp-dlen"] = makeEl("input"); els["bwp-dlen"].value = "0x999999";   /* must CLAMP */
    els["bwp-dchunk"] = makeEl("input"); els["bwp-dchunk"].value = "0x400";
    els["bwp-dbase"] = makeEl("input"); els["bwp-dbase"].value = "lk";
    els["bwp-dgap"] = makeEl("input"); els["bwp-dgap"].value = "1";

    /* -- the memory model: a window at the base, ELF magic at its head -------- */
    const mem = new Map();
    const LO = 0x100000n, HI = 0x400000n;
    const inRange = (p) => p !== undefined && p >= LO && p < HI;
    const memGet = (addr, len) => {
        const a = Number(addr);
        let b = mem.get(a);
        if (!b || b.length < len) { b = new Uint8Array(len); mem.set(a, b); }
        return b;
    };
    const IMG = new Uint8Array(0x2000);
    for (let i = 4; i < IMG.length; i++) IMG[i] = (i * 5 + 3) & 0xff;   /* non-zero code */
    IMG[0] = 0x7f; IMG[1] = 0x45; IMG[2] = 0x4c; IMG[3] = 0x46;        /* \x7fELF */
    const imgGet = (addr, n) => {
        const off = Number(BigInt(addr) - KB);
        if (off < 0 || off + n > IMG.length) throw new Error("unmapped");
        return IMG.slice(off, off + n);
    };

    /* -- a crafted FreeBSD directory buffer -------------------------------- */
    const DIRENTS = ["app0", "mnt", "dev"];
    function buildDirents() {
        const out = [];
        DIRENTS.forEach((nm, idx) => {
            const reclen = 12 + nm.length + 1 <= 16 ? 16 : 20;
            const rec = new Uint8Array(reclen);
            for (let i = 0; i < 8; i++) rec[7 - i] = (idx + 3) & 0xff;      /* d_fileno (LE) */
            rec[8] = reclen & 0xff; rec[9] = (reclen >> 8) & 0xff;          /* d_reclen */
            rec[10] = 4;                                                     /* d_type  */
            rec[11] = nm.length;                                             /* d_namlen */
            for (let i = 0; i < nm.length; i++) rec[12 + i] = nm.charCodeAt(i);
            out.push(...rec);
        });
        return new Uint8Array(out);
    }
    const DIRBYTES = buildDirents();

    /* -- a heap that grows past the watchdog threshold ----------------------- */
    let heap = 40 * 1048576;
    let chunksSeen = 0;

    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },
        performance: { memory: { get usedJSHeapSize() { return heap; }, jsHeapSizeLimit: 512 * 1048576 } },
        localStorage: { getItem: (k) => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); }, removeItem: (k) => { delete storage[k]; } },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => { const a = 0x200000n; return a; },
        write_buffer: (addr, bytes) => { memGet(addr, bytes.length).set(bytes); },
        read_buffer: (addr, len) => {
            const a = BigInt(addr);
            if (a >= KB && a < KB + BigInt(IMG.length)) return imgGet(a, len);
            return new Uint8Array(memGet(a, len));
        },
        read64: () => 0n, read32: () => 0n,
        fetch(url, init) { posts.push(String((init && init.body) || "")); return { then: (ok) => { ok && ok(); return { then: (a) => (a && a(), {}) }; } }; },
        syscall(nr, a0, a1, a2, a3) {
            calls.push("0x" + nr.toString(16));
            if (nr === 0x061) return 7n;              /* socket   -> fd 7 */
            if (nr === 0x068) return 0n;             /* bind     -> ok   */
            if (nr === 0x06A) return 0n;             /* listen   -> ok   */
            if (nr === 0x005) return 8n;             /* open     -> fd 8 */
            if (nr === 0x110) {                      /* getdents: WRITE the crafted block */
                memGet(a1, DIRBYTES.length).set(DIRBYTES);
                return BigInt(DIRBYTES.length);
            }
            if (nr === 0x1C6) return 0x16n;          /* umtx_op  -> EINVAL (present) */
            if (nr === 0x08D) return 0x16n;          /* kqueueex -> EINVAL (present) */
            if (nr === 0x006) return (a0 === 7n || a0 === 8n) ? 0n : 0x9n;
            return 0x16n;
        },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0n, kbase: KB, wbase: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = {
        window: w, document: doc, localStorage: w.localStorage,
        setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array,
        /* performance must be a GLOBAL, the way a browser exposes it: heapNote/heapNow
         * read the bare identifier, and leaving it only on window made every heap figure
         * silently zero (which also disables the watchdog) -- a guard that cannot fire is
         * not a guard. */
        performance: w.performance,
        fetch: w.fetch, Blob: class { constructor() { } }, URL: { createObjectURL: () => "blob:x" },
    };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });

    /* the watchdog needs the heap to grow BETWEEN chunks, so bump it per POST */
    const realSet = w.localStorage.setItem;
    w.localStorage.setItem = realSet;   /* untouched: the hook below is on fetch */
    const origFetch = w.fetch;
    w.fetch = function (u, i) { if (String((i && i.body) || "").startsWith("BAGA ")) { chunksSeen++; if (chunksSeen >= 2) heap = 400 * 1048576; } return origFetch(u, i); };
    ctx.fetch = w.fetch;

    const frags = [];
    let elapsed = 0;
    /* RECORD EVERY WRITE rather than SAMPLE the store. The store is throttled with a
     * trailing flush, so sampling could miss the final write and make a line that IS in
     * the panel read as absent -- a flaky test is worse than no test. Hooking setItem
     * captures each version, and the union of them is the exact reconstructed log. */
    const snapSet = w.localStorage.setItem;
    w.localStorage.setItem = function (key, value) {
        if (key === "bwslop_sc_log") frags.push(String(value));
        return snapSet(key, value);
    };
    await new Promise((res) => setTimeout(res, 3500));
    if (storage["bwslop_sc_log"]) frags.push(storage["bwslop_sc_log"]);
    const log = frags.join("\n");

    /* -- verify ------------------------------------------------------------ */
    check("12: verify reads the ELF magic at the real libkernel base",
        /VER-libkernel {2}first bytes 7f 45 4c 46 {2}ascii \|\.ELF\| {2}ELF/.test(log),
        log.split("\n").filter((l) => l.includes("VER-")).join(" // ").slice(-400));
    check("12: verify reports a base it could NOT resolve instead of hiding it",
        /VER-libwebkit {2}no base resolved/.test(log),
        log.split("\n").filter((l) => l.includes("VER-libwebkit")).join(" // "));
    check("12: verify verdict counts the verified bases",
        /VER-verdict {2}1\/2 bases carry 7f 45 4c 46/.test(log),
        log.split("\n").filter((l) => l.includes("VER-verdict")).join(" // "));
    check("12: verify prints the byte window as a hexdump line (the VERY SMALL text)",
        /0x0*820000000 {2}7f 45 4c 46/.test(log), "no tiny dump line");

    /* -- real offsets ------------------------------------------------------ */
    check("12: offtable prints the live P2JB_LK row field by field",
        log.includes("OFFT-slot_expect") && log.includes("OFFT-thread_list") && log.includes("OFFT-syscall_wrapper"), log.slice(-900));
    check("12: offtable verdict counts the live fields",
        /OFFT-verdict {2}5 field\(s\) from the LIVE P2JB_LK row/.test(log),
        log.split("\n").filter((l) => l.includes("OFFT-verdict")).join(" // "));

    /* -- umtx / kqueueex --------------------------------------------------- */
    check("12: umtx probes both surfaces all-zero",
        calls.includes("0x1c6") && calls.includes("0x8d"), calls.join(","));
    check("12: umtx verdict reports them PRESENT (EINVAL, not ENOSYS)",
        /UMTX-VERDICT[\s\S]{0,200}umtx_op EXISTS, kqueueex EXISTS/.test(log),
        log.split("\n").filter((l) => l.includes("UMTX-VERDICT")).join(" // "));

    /* -- socket + files (the FTP question) --------------------------------- */
    check("12: ftp opens a socket, binds 1337 and listens",
        log.includes("FTP-socket  AF_INET stream socket fd=7") && log.includes("FTP-bind") && log.includes("the port is OURS") && log.includes("a LISTENING socket exists"), log.slice(-1200));
    check("12: ftp parses the crafted dirents into the right names",
        /FTP-files {2}getdents\("\/"\) -> \d+ bytes, 3 entr\(y\/ies\): app0, mnt, dev/.test(log),
        log.split("\n").filter((l) => l.includes("FTP-files")).join(" // "));
    check("12: ftp verdict states the accept() limitation instead of implying a server",
        /FTP-VERDICT[\s\S]{0,900}accept\(\)/.test(log) && log.includes("ftpsrv-ps5.elf"), log.slice(-1400));
    /* AN ELF CANNOT BE LAUNCHED WITHOUT A JAILBREAK (main.js refuses elfldr in webkit-only
     * mode; p2jb_poops.js says its stage-7 elfldr helpers are "only USED after jailbreak").
     * The panel must say that where it lists the payloads, or an unqualified link list reads
     * as "tap to run" on the one firmware that cannot. */
    check("12: ftp verdict says an ELF needs a jailbreak, which 13.60 cannot get",
        /FTP-VERDICT[\s\S]{0,1200}JAILBREAK/.test(log), log.slice(-1600));
    check("12: the payload list is labelled with the jailbreak precondition",
        String(els["bwp-note"].textContent).includes("JAILBREAK"),
        String(els["bwp-note"].textContent).slice(0, 200));
    check("12: the ELF row label carries the precondition too",
        String(els["bwp-payloads"].textContent || "").includes("JAILBREAK") ||
        String(els["bwp-payloads"].children.map((c) => c.textContent).join(" ")).includes("JAILBREAK"),
        "label missing");
    check("12: ftp closed everything it opened",
        calls.filter((c) => c === "0x6").length >= 2, calls.join(","));

    /* -- the dump: clamp + watchdog ---------------------------------------- */
    check("12: dump CLAMPS an over-large byte request in code, not in the input box",
        log.includes("bytes clamped to 262144"), log.slice(-1500));
    check("12: the BAGA-BEGIN frame carries the CLAMPED total",
        (posts.find((p) => p.startsWith("BAGA-BEGIN")) || "").includes("total=262144"),
        posts.find((p) => p.startsWith("BAGA-BEGIN")));
    check("12: the HEAP WATCHDOG stops the dump itself with a named verdict",
        log.includes("DUMP-OOM-GUARD") && /HEAP-WATCHDOG \(\+\d/.test(log),
        log.split("\n").filter((l) => l.includes("OOM-GUARD") || l.includes("DUMP-VERDICT")).join(" // ").slice(-400));
    check("12: the dump verdict says it stopped early on purpose",
        /DUMP-VERDICT[\s\S]{0,400}STOPPED EARLY BY HEAP-WATCHDOG/.test(log), log.slice(-700));

    /* -- layout: the tiles region and its show/hide toggle ------------------ */
    check("12: the panel built a scrolling tiles region", !!els["bwp-top"], Object.keys(els).join(",").slice(0, 200));
    const pvBtn = els["bwp-payloadsbtn"], topEl = els["bwp-top"];
    const before = topEl.style.display;
    if (pvBtn && typeof pvBtn.onclick === "function") pvBtn.onclick();
    check("12: the show/hide payloads toggle flips the tiles region",
        topEl.style.display === "none" && before !== "none" && pvBtn.textContent === "show tiles",
        "before=" + JSON.stringify(before) + " after=" + JSON.stringify(topEl.style.display) + " label=" + pvBtn.textContent);
    check("12: hiding the tiles is remembered in localStorage",
        storage["bwslop_tiles_hidden"] === "1", String(storage["bwslop_tiles_hidden"]));
}

console.log(fails ? `\n${fails} check(s) FAILED` : "\nall convention scenarios pass");
process.exit(fails ? 1 : 0);
