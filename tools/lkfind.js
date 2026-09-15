#!/usr/bin/env node
/*
 * lkfind.js — signature scanner for libkernel_web.sprx (the sync executor's constants).
 *
 * This is the tool p2jb_lk.js describes but does not ship. Its whole reason to exist is
 * that a NEW firmware's P2JB_LK row must be produced by validated signature matching, not
 * by guessing or by inheriting a neighbouring firmware's values.
 *
 * Convention (from p2jb_lk.js):  rva = file_off - 0x4000
 *
 * Signatures (all from p2jb_lk.js, verified there against the retail modules):
 *   syscall_wrapper : 49 89 ca 0f 05 c3            (mov r10,rcx; syscall; ret)
 *   setjmp          : 48 89 f9 48 8b 14 24 48 89 11
 *   longjmp         : 48 89 fa 89 f0 48 8b 0a 48 8b 5a 08
 *   slot_expect     : eb 15 4c 89 f7 48 89 de b9 01 00 00 00 31 d2   (cond_wait resume)
 *   thread_list     : 4c 8b 38 4d 85 ff            (mov r15,[rax]; test r15,r15)
 *                     reached via a preceding  48 8d 05 disp32   (lea rax,[rip+X]) -> X
 *   pop_rsp         : 5c c3                        (REMOVED in 12.xx -> count 0; the
 *                                                  adapter takes WebKit's pop rsp instead)
 *
 * Usage:
 *   node tools/lkfind.js <libkernel_web.sprx>
 *   node tools/lkfind.js <libkernel_web.sprx> --fw 13.60        # emit a P2JB_LK row
 *   node tools/lkfind.js <libkernel_web.sprx> --expect 12.00    # validate the method
 *   node tools/lkfind.js <libkernel_web.sprx> --json
 *
 * --expect is the important one. The method is only trustworthy once it has reproduced a
 * firmware whose values are already known (netctrl's 10.00, or the 12.00/12.40 groups in
 * p2jb_lk.js). Run it on a known image FIRST; if it disagrees, the image or the base
 * convention is wrong and any new row it prints is worthless.
 */
"use strict";

const fs = require("fs");

const SIGS = {
    syscall_wrapper: { bytes: "49 89 ca 0f 05 c3", note: "mov r10,rcx; syscall; ret" },
    setjmp: { bytes: "48 89 f9 48 8b 14 24 48 89 11", note: "_setjmp-style (rip@0/rsp@0x10)" },
    longjmp: { bytes: "48 89 fa 89 f0 48 8b 0a 48 8b 5a 08", note: "ends mov [rsp],rcx; ret" },
    slot_expect: { bytes: "eb 15 4c 89 f7 48 89 de b9 01 00 00 00 31 d2", note: "cond_wait resume" },
    thread_list: { bytes: "4c 8b 38 4d 85 ff", note: "mov r15,[rax]; test r15,r15", ripLea: true },
    pop_rsp: { bytes: "5c c3", note: "pop rsp; ret" },
};

// Expected values, for method validation. Sources are named so a disagreement can be
// argued about rather than just noticed.
const EXPECT = {
    // netctrl's known-good values, reproduced by p2jb_lk.js and hardcoded as defaults in
    // rop-worker.js (LK_POP_RSP / LK_SETJMP / LK_LONGJMP / SLOT_EXPECT / LK_THREAD_LIST).
    "10.00": { syscall_wrapper: 0x1A5B7, setjmp: 0x1CB43, longjmp: 0x1CB9C, slot_expect: 0x190DB, thread_list: 0x64218, pop_rsp: 0x343AA },
    // p2jb_lk.js group A: libkernel_web 528364 bytes
    "12.00": { syscall_wrapper: 0x1AE27, setjmp: 0x1D3B3, longjmp: 0x1D40C, slot_expect: 0x197FB, thread_list: 0x64218, pop_rsp: null, pthread_create: 0x79B0 },
    // p2jb_lk.js group B: libkernel_web 544860 bytes
    "12.40": { syscall_wrapper: 0x1AE47, setjmp: 0x1D3D3, longjmp: 0x1D42C, slot_expect: 0x1981B, thread_list: 0x68218, pop_rsp: null, pthread_create: 0x79B0 },
};
const ALIAS = { "12.02": "12.00", "12.20": "12.00", "12.60": "12.40", "12.70": "12.40" };
// pop_rsp == null means "expected ABSENT": libkernel_web dropped `5C C3` in 12.xx.
//
// These are NOT byte-scannable: they are dynsym exports, resolved by NID. They must not
// count as validation failures or the validator would be permanently red on a correct image.
const EXPORT_ONLY = new Set(["pthread_create"]);

function parseHex(pattern) {
    return Buffer.from(pattern.split(/\s+/).map((h) => parseInt(h, 16)));
}

function findAll(hay, needle) {
    const hits = [];
    let at = hay.indexOf(needle, 0);
    while (at !== -1) {
        hits.push(at);
        at = hay.indexOf(needle, at + 1);
    }
    return hits;
}

// thread_list is a pointer load, not a constant: the address IS a rip-relative LEA that
// immediately precedes the walk head. Resolve it rather than reporting the head's offset.
function resolveRipLea(buf, headOff) {
    for (let back = 1; back <= 16; ++back) {
        const at = headOff - back;
        if (at < 0) break;
        if (buf[at] === 0x48 && buf[at + 1] === 0x8d && buf[at + 2] === 0x05) {
            const disp = buf.readInt32LE(at + 3);
            return { leaOff: at, target: at + 7 + disp };
        }
    }
    return null;
}

function scan(buf, strip) {
    const out = {};
    for (const [name, sig] of Object.entries(SIGS)) {
        const hits = findAll(buf, parseHex(sig.bytes));
        const rec = { name, hits: hits.length, fileOffsets: hits, note: sig.note, rva: null, resolved: null };
        if (hits.length === 1) {
            if (sig.ripLea) {
                const lea = resolveRipLea(buf, hits[0]);
                if (!lea) {
                    rec.resolved = "no rip-relative lea within 16 bytes -- head pattern matched something else";
                } else {
                    rec.resolved = lea;
                    rec.fileOffsets = [hits[0]];
                    rec.rva = lea.target - strip;
                }
            } else {
                rec.rva = hits[0] - strip;
            }
        } else if (hits.length > 1) {
            rec.resolved = "AMBIGUOUS -- " + hits.length + " hits; a hardcoded stack/text constant must be unique";
        }
        out[name] = rec;
    }
    return out;
}

function hex(v) {
    return v === null || v === undefined ? "(absent)" : "0x" + v.toString(16).toUpperCase();
}

function main() {
    const argv = process.argv.slice(2);
    const file = argv.find((a) => !a.startsWith("--"));
    const flag = (name) => {
        const i = argv.indexOf("--" + name);
        return i === -1 ? null : (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--") ? argv[i + 1] : true);
    };
    if (!file) {
        console.error("usage: node tools/lkfind.js <libkernel_web.sprx> [--strip 0x4000] [--expect FW] [--fw FW] [--json]");
        process.exit(2);
    }

    const strip = flag("strip") && flag("strip") !== true ? Number(flag("strip")) : 0x4000;
    const asJson = flag("json") === true;
    const expectKey = flag("expect");
    const fwOut = flag("fw");

    let buf;
    try {
        buf = fs.readFileSync(file);
    } catch (e) {
        console.error("cannot read " + file + ": " + e.message);
        process.exit(2);
    }

    const res = scan(buf, strip);
    const summary = {
        file,
        size: buf.length,
        stripRvaBase: strip,
        results: res,
    };

    if (asJson) {
        console.log(JSON.stringify(summary, null, 2));
    } else {
        console.log("# " + file + "  (" + buf.length + " bytes, rva = file_off - 0x" + strip.toString(16) + ")");
        console.log("");
        for (const [name, r] of Object.entries(res)) {
            let line = name.padEnd(16) + " hits=" + String(r.hits).padEnd(3) + " rva=" + hex(r.rva);
            if (r.hits !== 1) line += "   <-- not usable: " + (r.hits === 0 ? "no match" : "ambiguous");
            console.log(line);
            if (r.resolved && typeof r.resolved === "object")
                console.log("".padEnd(16) + " rip-lea@file+0x" + r.resolved.leaOff.toString(16) + " -> rva " + hex(r.rva));
            else if (typeof r.resolved === "string")
                console.log("".padEnd(16) + " " + r.resolved);
        }
        console.log("");
    }

    // pop_rsp is the negative control: its ABSENCE is the proof you are looking at 12.xx+
    // rather than a 10.00-era module, and the adapter must therefore take WebKit's pop rsp.
    const pop = res.pop_rsp;
    if (!asJson) {
        if (pop.hits === 0) console.log("[ok]  pop_rsp absent -- expected on 12.xx+ (use W.gadgets.pop_rsp from WebKit)");
        else if (pop.hits === 1) console.log("[!!] pop_rsp PRESENT at " + hex(pop.rva) + " -- this looks like a 10.00-era module, not 12.xx+");
        else console.log("[!!] pop_rsp ambiguous (" + pop.hits + " hits)");
    }

    if (expectKey) {
        const key = ALIAS[expectKey] || expectKey;
        const want = EXPECT[key];
        console.log("");
        if (!want) {
            console.log("[--] no expected values on file for FW " + expectKey
                + " (known: " + Object.keys(EXPECT).join(", ") + "). Nothing to validate against.");
        } else {
            let pass = 0, fail = 0, skipped = [];
            for (const [name, wantRva] of Object.entries(want)) {
                if (EXPORT_ONLY.has(name)) { skipped.push(name); continue; }
                const got = res[name] ? res[name].rva : null;
                const amAbsent = wantRva === null;
                const ok = amAbsent ? got === null && (res[name] ? res[name].hits : 0) === 0 : got === wantRva;
                console.log((ok ? "[ok]  " : "[FAIL]") + " " + name.padEnd(16)
                    + " expected " + (amAbsent ? "(absent)" : hex(wantRva)) + "  got " + hex(got));
                if (ok) pass++; else fail++;
            }
            for (const name of skipped)
                console.log("[--]  " + name.padEnd(16)
                    + " dynsym export, not byte-scannable -- expected " + hex(want[name])
                    + " (resolve by NID; excluded from validation)");
            console.log("");
            if (fail === 0) {
                console.log("METHOD VALIDATED on " + expectKey + " (" + pass + "/" + pass + "). "
                    + "A row produced for another firmware by this tool is now trustworthy.");
            } else {
                console.log("METHOD NOT VALIDATED (" + fail + " mismatch). Do NOT trust a row from this run: "
                    + "check the image, the --strip convention, and that the file really is libkernel_web.");
                process.exitCode = 1;
            }
        }
    }

    if (fwOut) {
        const r = (n) => (res[n] && res[n].rva !== null ? "0x" + res[n].rva.toString(16).toUpperCase() : null);
        const row = {
            syscall_wrapper: r("syscall_wrapper"),
            setjmp: r("setjmp"),
            longjmp: r("longjmp"),
            pthread_create: null,   // export, not a signature -- resolve from the dynsym by NID
            slot_expect: r("slot_expect"),
            thread_list: r("thread_list"),
        };
        console.log("");
        console.log("// paste into p2jb_lk.js (pthread_create must come from the dynsym by NID"
            + " 6UgtwV+0zb4; it is not a byte signature)");
        console.log("\"" + fwOut + "\": { " + Object.entries(row)
            .map(([k, v]) => k + ": " + v)
            .join(", ") + " },");
    }
}

main();
