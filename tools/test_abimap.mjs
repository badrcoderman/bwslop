/*
 * tools/test_abimap.mjs -- headless harness for bagagwa_probe.js's ABI map tile.
 *
 * Two things are tested, and the second one is the important one:
 *
 *  A. DEDUCTION. The tile must derive (ids, num) from measurement for a known argument
 *     order, with no table lookup -- phase 1 (a pointer-shaped sentinel in one argument)
 *     and phase 2 (a VALID array in one argument, num=1 in another).
 *
 *  B. ARMING SAFETY, as a TRIPWIRE rather than an assertion in prose. The kernel model
 *     latches `armed` the moment a call presents a VALID array with num >= 2 (the exact
 *     condition the mode-0 aliasing bug needs) and the suite fails if it ever fires,
 *     across every scenario. If a future edit makes the sweep set one register too many,
 *     this catches it here instead of on a console.
 *
 * Three kernel shapes, because the answer must not depend on which check the kernel does
 * first: ids-then-num, num-then-ids, and an order that puts the ids array in argument 2.
 *
 * Run:  node tools/test_abimap.mjs
 * Exit code 0 = all scenarios pass.
 */
import fs from "node:fs";
import vm from "node:vm";

const SRC = new URL("../bagagwa_probe.js", import.meta.url).pathname;
const src = fs.readFileSync(SRC, "utf8");

function makeEl(tag) {
    return {
        tagName: tag, style: {}, className: "", textContent: "", innerHTML: "",
        children: [], childNodes: [], firstChild: null, scrollTop: 0, scrollHeight: 0,
        appendChild(c) { this.children.push(c); this.childNodes.push(c); this.firstChild = this.childNodes[0] || null; return c; },
        removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); this.firstChild = this.childNodes[0] || null; },
        remove() {}, click() {}, querySelector() { return makeEl("span"); },
    };
}

const BUF = 0x100000n;                     // the probe's array buffer (malloc stub)
const UNMAPPED = (p) => p === 0n || p === 1n || p === 0x1000n;   // what the stub kernel accepts as "unmapped"

/*
 * model(opts) -> syscall handler for 0x297 plus a `tripwire` object.
 *   opts.idsArg  index of the ids array argument
 *   opts.numArg  index of the num argument
 *   opts.checkNumFirst  if true the kernel rejects num==0 before touching the array
 */
function model(opts) {
    const tripwire = { armed: false, calls: 0 };
    const handler = (a) => {
        tripwire.calls++;
        const ids = a[opts.idsArg], num = a[opts.numArg];
        const idsValid = (ids === BUF);
        if (idsValid && num >= 2n) tripwire.armed = true;      // THE condition
        if (opts.checkNumFirst && num === 0n) return 22n;      // EINVAL
        if (!idsValid) return 14n;                             // EFAULT: copyin of the array fails
        if (num === 0n) return 22n;                            // EINVAL
        return 2n;                                             // ENOENT: request id 0 is not ours
    };
    return { handler, tripwire };
}

function run(name, opts) {
    const { handler, tripwire } = model(opts);
    const storage = {};
    const els = {};
    const getEl = (id) => (els[id] ||= makeEl("div"));
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: getEl };

    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },   // probe auto-runs only behind scauto

        localStorage: {
            getItem: (k) => (k in storage ? storage[k] : null),
            setItem: (k, v) => { storage[k] = String(v); },
            removeItem: (k) => { delete storage[k]; },
        },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => BUF, write_buffer() {}, alloc_string: () => BUF,
        read_buffer: () => new Uint8Array(new Int32Array([7, 8]).buffer),
        read64: () => 0n,
        syscall(nr, a0, a1, a2, a3, a4, a5) {
            if (nr === 0x297) return handler([a0, a1, a2, a3, a4, a5]);
            if (nr === 0x006) return (a0 === 7n || a0 === 8n) ? 0n : 9n;
            if (nr === 0x14) return 0x4fn;
            if (nr === 0x16a) return 7n;
            if (nr === 0x2af) return 0n;
            if (nr === 0x7FF) return 0x4en;
            return 0x16n;                                       // everything else: EINVAL
        },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0n, kbase: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };

    const ctx = {
        window: w, document: doc, localStorage: w.localStorage,
        setTimeout, Date, JSON, Math, console,
        Uint8Array, Int32Array, Blob: class {}, URL: { createObjectURL: () => "blob:x" },
    };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });
    /* The ABI tile alone makes ~37 spaced calls; 1600ms truncated the log mid-T5 and made
     * the verdict checks race. Wait for the whole run. */
    return new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "", tripwire }), 12000));
}

let fails = 0;
const check = (name, cond, extra) => {
    console.log((cond ? "PASS  " : "FAIL  ") + name + (cond || extra === undefined ? "" : "  -- " + String(extra).slice(-420)));
    if (!cond) fails++;
};

/* 1. ids first, num second -- ids checked before num.
 *    Here EVERY call without a valid array faults (ids=NULL -> EFAULT), so phase 1 cannot
 *    isolate the array argument: it reports EFAULT for all six. The deduction must still be
 *    correct, and it must attribute itself to the pair sweep rather than claim phase-1
 *    agreement it did not have. */
{
    const { log, tripwire } = await run("ids0-num1", { idsArg: 0, numArg: 1 });
    check("1: phase 1 ran", log.includes("ABI-phase1"), log);
    check("1: deduces ids=arg1 num=arg2", log.includes("ids = argument 1") && log.includes("num = argument 2"), log);
    check("1: does NOT claim phase-1 agreement it did not have", !log.includes("Phase 1 agrees independently"));
    check("1: TRIPWIRE -- no valid array with num>=2", !tripwire.armed);
}

/* 2. the ids array in argument 2 instead -- the mapper must not hardcode arg1. */
{
    const { log, tripwire } = await run("ids1-num2", { idsArg: 1, numArg: 2 });
    check("2: deduces ids=arg2 num=arg3", log.includes("ids = argument 2") && log.includes("num = argument 3"), log);
    check("2: TRIPWIRE -- no valid array with num>=2", !tripwire.armed);
}

/* 3. num checked BEFORE the array, so phase 1 cannot see the deref. The pair sweep still must. */
{
    const { log, tripwire } = await run("num-first", { idsArg: 0, numArg: 1, checkNumFirst: true });
    check("3: still deduces ids=arg1 num=arg2 from the pair sweep", log.includes("ids = argument 1") && log.includes("num = argument 2"), log);
    /* With num checked first, phase 1's single EFAULT lands on the NUM argument: a bad pointer
     * there is just a large num, which clears the num==0 test and lets the array check fault.
     * That is corroboration from the opposite end, and the verdict must say which end it saw. */
    check("3: phase 1 corroborates from the num side, and says so", log.includes("Phase 1 corroborates from the OTHER END"), log);
    check("3: TRIPWIRE -- no valid array with num>=2", !tripwire.armed);
}

/* 4. a kernel that refuses the whole argument set: must NOT invent an answer. */
{
    const storage = {};
    const els = {};
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")) };
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },   // probe auto-runs only behind scauto

        localStorage: { getItem: (k) => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); }, removeItem: (k) => { delete storage[k]; } },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => BUF, write_buffer() {}, alloc_string: () => BUF,
        read_buffer: () => new Uint8Array(new Int32Array([7, 8]).buffer), read64: () => 0n,
        syscall(nr) { return nr === 0x297 ? 22n : 0n; },      // always EINVAL, never faults
        rop_worker: { state: { fired: 0n, dead: false, stack: 0n, kbase: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = { window: w, document: doc, localStorage: w.localStorage, setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array, Blob: class {}, URL: { createObjectURL: () => "x" } };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });
    const { log } = await new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "" }), 12000));
    check("4: reports INCONCLUSIVE rather than guessing", log.includes("ABI-VERDICT") && log.includes("INCONCLUSIVE"), log);
    check("4: warns not to arm on it", log.includes("do NOT arm on a guess"));
}

/* 4b. ids-first AND a NULL array rejected with EINVAL instead of faulting: now phase 1's lone
 *     EFAULT DOES land on the ids argument, so the verdict must claim corroboration there. */
{
    const storage = {};
    const els = {};
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")) };
    const tripwire = { armed: false };
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },   // probe auto-runs only behind scauto

        localStorage: { getItem: (k) => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); }, removeItem: (k) => { delete storage[k]; } },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => BUF, write_buffer() {}, alloc_string: () => BUF,
        read_buffer: () => new Uint8Array(new Int32Array([7, 8]).buffer), read64: () => 0n,
        syscall(nr, a0, a1, a2, a3, a4, a5) {
            if (nr === 0x297) {
                const ids = a0, num = a1;
                if (ids === BUF && num >= 2n) tripwire.armed = true;
                if (ids === 0n) return 22n;            // NULL array: EINVAL, not a fault
                if (ids !== BUF) return 14n;           // non-NULL bad pointer: EFAULT
                if (num === 0n) return 22n;
                return 2n;                             // ENOENT
            }
            if (nr === 0x006) return (a0 === 7n || a0 === 8n) ? 0n : 9n;
            if (nr === 0x14) return 0x4fn;
            if (nr === 0x16a) return 7n;
            if (nr === 0x2af) return 0n;
            if (nr === 0x7FF) return 0x4en;
            return 0x16n;
        },
        rop_worker: { state: { fired: 19n, dead: false, stack: 0n, kbase: 0n, slot: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = { window: w, document: doc, localStorage: w.localStorage, setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array, Blob: class {}, URL: { createObjectURL: () => "x" } };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });
    const { log } = await new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "" }), 12000));
    check("4b: deduces ids=arg1 num=arg2 on a NULL-is-EINVAL kernel", log.includes("ids = argument 1") && log.includes("num = argument 2"), log);
    check("4b: phase 1 corroborates from the ids side", log.includes("that IS the argument the kernel dereferences"), log);
    check("4b: TRIPWIRE -- no valid array with num>=2", !tripwire.armed);
}

/* 5. the safety statement is present in the output, not just in a comment. */
{
    const { log } = await run("safety-text", { idsArg: 0, numArg: 1 });
    check("5: prints the arming-safety reasoning", log.includes("arming-safe by construction"));
    check("5: says a valid array is never paired with num>=2", log.includes("never paired with num >= 2"));
}

/* 6. THE REAL 13.60 MATRIX, cell for cell from the 20:13 console run. This is the shape
 *    the row-wise scan declared INCONCLUSIVE and the column model must decode:
 *      num==0 -> EINVAL (25 cells); num huge -> EINVAL (a domain check; row arg2);
 *      mode invalid -> EINVAL (row arg4); num=1 -> derefs activate and the call faults
 *      because the sweep set only ONE pointer (4 EFAULT cells, all in the arg2 column).
 *    The model must NOT claim anything about a huge-num walk that the data does not show.
 *    Regression guard: if the deduction ever changes, this cell-set fails here first. */
{
    const storage = {};
    const els = {};
    const doc = { head: makeEl("head"), body: makeEl("body"), createElement: (t) => makeEl(t), getElementById: (id) => (els[id] ||= makeEl("div")) };
    const tripwire = { armed: false };
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },   // probe auto-runs only behind scauto

        localStorage: { getItem: (k) => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); }, removeItem: (k) => { delete storage[k]; } },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => BUF, write_buffer() {}, alloc_string: () => BUF,
        read_buffer: () => new Uint8Array(new Int32Array([7, 8]).buffer), read64: () => 0n,
        syscall(nr, a0, a1, a2, a3, a4, a5) {
            if (nr === 0x297) {
                const a = [a0, a1, a2, a3, a4, a5];
                if (a[0] === BUF && a[1] >= 2n) tripwire.armed = true;   // ids@arg1, num@arg2
                if (a[1] === 0n) return 22n;                 // num==0 -> EINVAL, first
                if (a[1] > 4n) return 22n;                   // num domain check -> EINVAL
                if (a[3] !== 0n && a[3] !== 1n) return 22n;  // mode validated before derefs
                /* derefs activate: ids and states are both walked; our sweep only ever sets
                 * one pointer, so whichever is NULL faults. With a VALID ids, states=NULL
                 * still faults (hardware: row arg1 col2). */
                const idsValid = a[0] === BUF, statesValid = a[2] === BUF;
                return (idsValid && statesValid) ? 2n : 14n;
            }
            if (nr === 0x006) return (a0 === 7n || a0 === 8n) ? 0n : 9n;
            if (nr === 0x14) return 0x4fn;
            if (nr === 0x16a) return 7n;
            if (nr === 0x2af) return 0n;
            return 0x16n;
        },
        rop_worker: { state: { slot: 0n, fired: 19n, dead: false, stack: 0n, kbase: 0n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": { slot_expect: 0x1988Bn, syscall_wrapper: 0x1AEB7n, setjmp: 0x1D443n, longjmp: 0x1D49Cn, thread_list: 0x6C218n } },
    };
    const ctx = { window: w, document: doc, localStorage: w.localStorage, setTimeout, Date, JSON, Math, console, Uint8Array, Int32Array, Blob: class {}, URL: { createObjectURL: () => "x" } };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });
    const { log } = await new Promise((res) => setTimeout(() => res({ log: storage["bwslop_sc_log"] || "" }), 12000));
    check("6: real matrix -> ids=arg1 num=arg2 MEASURED", log.includes("MEASURED on this console") && log.includes("num = argument 2"), log);
    check("6: the model names the num domain check (row arg2 EINVAL)", log.includes("num DOMAIN check"));
    check("6: the model notes states is dereferenced too (row arg1 col2)", log.includes("states is dereferenced too"));
    check("6: phase 1 all-EINVAL explained as PREDICTED", log.includes("PREDICTED"));
    check("6: it does NOT claim mode/timeout are measured", !log.includes("mode = argument") || log.includes("NOT yet measured"));
    check("6: TRIPWIRE -- no valid array with num>=2", !tripwire.armed);
}

console.log(fails ? `\n${fails} check(s) FAILED` : "\nall ABI-map scenarios pass");
process.exit(fails ? 1 : 0);
