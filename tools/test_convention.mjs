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
        "0x225": 0x16n,         // osem_create   -> EINVAL
        "0x227": 0xen,          // osem_open     -> EFAULT
        "0x228": 0x3n,          // osem_close    -> ESRCH
        "0x226": 0x3n,          // osem_delete   -> ESRCH
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
    const w = {
        fw_str: "13.60",
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
        syscall(nr, a0) {
            const key = k(nr);
            calls.push(key + (a0 === undefined ? "" : "(" + a0.toString() + ")"));
            /* close(fd): 0 for the fds the probe actually owns, EBADF/errno otherwise. */
            if (nr === 0x006) {
                const fd = a0 === undefined ? -1n : BigInt(a0);
                if (fd === 0x7FFFFFFFn) return opts.badClose !== undefined ? opts.badClose : 0x9n;
                return (fd === 7n || fd === 8n) ? 0x0n : 0x9n;
            }
            /* Out-of-range syscall number: whatever `nosys` says, else ENOSYS. */
            if (nr === 0x7FF) return opts.nosys !== undefined ? opts.nosys : 0x4En;
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

    /* runAll is async (60ms between tiles); read the persisted panel log after it settles. */
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
    const { log } = await run("raw-present", {});
    check("1: T0 measures the raw convention", log.includes("RAW errno convention"));
    check("1: T0 reports EBADF as 0x9 and ENOSYS as 0x4e", log.includes("(EBADF)") && log.includes("ENOSYS reads 0x4e"));
    check("1: close(bad fd) decodes as errno 9, not a value", log.includes("errno-raw EBADF"));
    check("1: T3 REACHABLE", log.includes("aio_multi_wait REACHABLE"));
    check("1: T3 names EINVAL", log.includes("(EINVAL)"));
    check("1: T3 says it did not settle the ABI", log.includes("does NOT settle the ABI"));
    check("1: osem does NOT claim a refcount target from a bogus handle",
        !log.includes("refcount at +0x54 is a reachable target"));
    check("1: osem explains 0x16 was an errno, not a handle", log.includes("was an errno, not"));
    check("1: osem still reports the family EXISTS", log.includes("family EXISTS"));
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
    const { log } = await run("minus1-patched", { "0x297": 0x4en }, { badClose: 0x1234n, nosys: 0x1234n });
    check("4: T0 refuses to name a convention", log.includes("UNEXPECTED"));
    check("4: T3 STILL reports BAGAGWA DEAD (expectFail, no convention needed)", log.includes("BAGAGWA DEAD"));
    check("4: T3 does not report reachable", !log.includes("REACHABLE"));
}

/* 5. plain -1 convention: errno is outside rax, so ENOSYS is unknowable. Say so. */
{
    const { log } = await run("minus1", { "0x297": 0xFFFFFFFFFFFFFFFFn }, { badClose: 0xFFFFFFFFFFFFFFFFn, nosys: 0xFFFFFFFFFFFFFFFFn });
    check("5: T0 detects the -1 convention", log.includes("PLAIN -1 convention"));
    check("5: T0 says the errno NUMBER is not recoverable", log.includes("not recoverable from rax"));
    check("5: T3 says CANNOT DETERMINE", log.includes("CANNOT DETERMINE"));
    check("5: T3 does not claim reachable", !log.includes("REACHABLE"));
}

/* 6. the real log's osem row must not be mislabelled: close=0x3 is ESRCH, not success. */
{
    const { log } = await run("osem-correct", {});
    check("6: osem_close 0x3 decodes as ESRCH", log.includes("ESRCH"));
    check("6: no green refcount verdict", !log.includes("refcount at +0x54 is a reachable target"));
    const p = await run("osem-real", { "0x225": 0x22n, "0x228": 0x0n, "0x227": 0x0n, "0x226": 0x0n });
    check("6b: a real handle (close returns 0) IS accepted", p.log.includes("refcount at +0x54 is a reachable target"));
}

console.log(fails ? `\n${fails} check(s) FAILED` : "\nall convention scenarios pass");
process.exit(fails ? 1 : 0);
