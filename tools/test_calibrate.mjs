/*
 * tools/test_calibrate.mjs -- headless harness for bagagwa_probe.js's Calibrate tile.
 *
 * Runs the whole probe IIFE inside a stubbed DOM/window and drives the calibrate
 * path through its three outcomes, mirroring what the 13.60 console produced:
 *
 *   A. anchor present  -> picker must take the statically derived anchor
 *                         (0x1988b) even though a HIGHER frame-validated
 *                         candidate exists (the 0x2198d thread-entry trampoline
 *                         that the first hardware run wrongly picked).
 *   B. anchor absent   -> highest frame-validated candidate wins, explicitly
 *                         labelled unverified.
 *   C. stack unreadable-> the persisted row is restored, flagged by its
 *                         `verified` bit.
 *
 * Run:  node tools/test_calibrate.mjs
 * Exit code 0 = all scenarios pass.
 */
import fs from "node:fs";
import vm from "node:vm";
import assert from "node:assert";

const SRC = new URL("../bagagwa_probe.js", import.meta.url).pathname;
const src = fs.readFileSync(SRC, "utf8");

/* ---------------------------------------------------------------- stub DOM */
function makeEl(tag) {
    const el = {
        tagName: tag, style: {}, className: "", textContent: "", innerHTML: "",
        children: [], childNodes: [], firstChild: null, scrollTop: 0, scrollHeight: 0,
        appendChild(c) { this.children.push(c); this.childNodes.push(c); this.firstChild = this.childNodes[0] || null; return c; },
        removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); this.firstChild = this.childNodes[0] || null; },
        remove() {}, click() {},
        querySelector() { return makeEl("span"); },
    };
    return el;
}

function run(scenario) {
    const storage = {};
    const els = {};
    const getEl = (id) => (els[id] ||= makeEl("div"));
    const doc = {
        head: makeEl("head"), body: makeEl("body"),
        createElement: (t) => makeEl(t), getElementById: getEl,
    };

    /* Worker-stack memory model, matching the first 13.60 hardware run:
     * stack=0x7eeefc000, kbase=0x820038000, wbase=0x807c94000. The scan walks
     * [top-0x8000, top), top = stack+0x80000, one qword at a time. */
    const STACK = 0x7eeefc000n, KBASE = 0x820038000n;
    const mem = {};
    const put = (off, val, rbpOff) => {
        mem[(STACK + off).toString()] = val;
        if (rbpOff !== undefined) mem[(STACK + off - 8n).toString()] = STACK + rbpOff;
    };
    if (scenario === "anchor") {
        put(0x7ffc8n, KBASE + 0x2198dn, 0x7fff0n);  // thread-entry trampoline, frame-valid, HIGHEST
        put(0x7fc28n, KBASE + 0x1988bn, 0x7fc40n);  // the anchor (the parked frame)
        put(0x7fb68n, KBASE + 0x1fd01n, 0x7fc20n);  // PSAITO's worker_wait_return, also valid
        put(0x7f428n, KBASE + 0x2071an);            // stray, no frame validation
        for (let i = 0; i < 25; i++)                // __stack_chk_guard data copies
            put(0x7c000n + BigInt(i) * 8n, KBASE + 0x751d0n, i === 3 ? 0x7d708n : undefined);
    } else if (scenario === "noanchor") {
        put(0x7ffc8n, KBASE + 0x2198dn, 0x7fff0n);
        put(0x7f428n, KBASE + 0x2071an);
        for (let i = 0; i < 25; i++) put(0x7c000n + BigInt(i) * 8n, KBASE + 0x751d0n);
    } // "restore": mem stays empty

    if (scenario === "restore")
        storage["bwslop_lk_13.60"] = JSON.stringify({
            slot_expect: "104587", syscall_wrapper: "110263",   // 0x1988B, 0x1AEB7
            setjmp: "119875", longjmp: "119964",                // 0x1D443, 0x1D49C
            ts: Date.now(), via: "anchor-0x1988b", candidates: 38, verified: true,
        });

    const row = { slot_expect: 0x1983B, syscall_wrapper: 0x1AE67, setjmp: 0x1D3F3, longjmp: 0x1D44C, pthread_create: 0x79B0, thread_list: 0x6C218 };
    const w = {
        fw_str: "13.60",
        location: { search: "?sc=1&scauto=1" },   // probe auto-runs only behind scauto

        localStorage: {
            getItem: (k) => (k in storage ? storage[k] : null),
            setItem: (k, v) => { storage[k] = String(v); },
            removeItem: (k) => { delete storage[k]; },
        },
        send_notification() {}, flushMark() {}, syncMark() {},
        malloc: () => 0x100000n, write_buffer() {},
        read64: (a) => (mem[BigInt(a).toString()] ?? 0n),
        syscall: () => 4242n,
        rop_worker: { state: { slot: 0n, fired: 0n, dead: false, stack: STACK, kbase: KBASE, wbase: 0x807c94000n, ctx: 0n, retval: 0n } },
        P2JB_LK: { "13.60": row },
    };

    const logs = [];
    const ctx = {
        window: w, document: doc, localStorage: w.localStorage,
        setTimeout, Date, JSON, Math, console,
        Uint8Array, Blob: class { constructor(a, o) { this.a = a; this.o = o; } },
        URL: { createObjectURL: () => "blob:x" },
    };
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: "bagagwa_probe.js" });

    return new Promise((resolve) => setTimeout(() => resolve({ w, row, storage, logs: ctx.__lines || logs }), 1600));
}

/* runAll is async (60ms steps); capture the panel log from localStorage instead. */
const logOf = (storage) => (storage["bwslop_sc_log"] || "");

/* ---------------------------------------------------------------- the tests */
let fails = 0;
const check = (name, cond, extra) => {
    console.log((cond ? "PASS  " : "FAIL  ") + name + (cond || extra === undefined ? "" : "  -- " + extra));
    if (!cond) fails++;
};

const A = await run("anchor");
{
    const log = logOf(A.storage);
    check("A: calibrate did not throw", !log.includes("calibrate-THREW"), log.slice(-400));
    check("A: anchor 0x1988b picked", log.includes("slot_expect=0x1988b"), log.slice(-400));
    check("A: data word excluded with count", /\[x\d+ -- repeated data word, excluded\]/.test(log));
    check("A: trampoline not picked despite being higher", !log.includes("slot_expect=0x2198d"));
    check("A: off-by report is +0x50", log.includes("off by +0x50"));
    check("A: row patched live", A.row.slot_expect === 0x1988Bn && A.row.syscall_wrapper === 0x1AEB7n
        && A.row.setjmp === 0x1D443n && A.row.longjmp === 0x1D49Cn,
        JSON.stringify(A.row, (k, v) => typeof v === "bigint" ? v.toString() : v));
    const saved = JSON.parse(A.storage["bwslop_lk_13.60"] || "{}");
    check("A: persisted with verified flag", saved.verified === true && saved.via === "anchor-0x1988b");
}

const B = await run("noanchor");
{
    const log = logOf(B.storage);
    check("B: did not throw", !log.includes("calibrate-THREW"));
    check("B: highest frame-validated fallback picked", log.includes("slot_expect=0x2198d"));
    check("B: pick labelled unverified", log.includes("NOT on the stack"));
    const saved = JSON.parse(B.storage["bwslop_lk_13.60"] || "{}");
    check("B: persisted unverified", saved.verified === false);
}

const C = await run("restore");
{
    const log = logOf(C.storage);
    check("C: restore path ran", log.includes("re-applied the persisted row"));
    check("C: restored row flagged anchor-verified", log.includes("anchor-verified"));
    check("C: row equals persisted values", C.row.slot_expect === 0x1988Bn);
}

console.log(fails ? `\n${fails} check(s) FAILED` : "\nall calibrate scenarios pass");
process.exit(fails ? 1 : 0);
