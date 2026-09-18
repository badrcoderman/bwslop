#!/usr/bin/env node
/* test_offsets_parity.mjs -- the fourth headless harness.
 *
 * WHY THIS EXISTS
 * ---------------
 * The 13.60 userland table (host-constructor candidates, the natural trampoline,
 * the notify entry and the three WebKit import GOT slots) exists in THREE places:
 *
 *   1. offsets/13.60.js            -- the offset file every stage reads
 *   2. bagagwa.js  USERLAND_1360   -- the Bagagwa engine's own frozen copy
 *   3. ../noslop/offsets/offsets.json["13.60"]   -- the workstation reference table
 *
 * They agree today, but nothing enforced that. A one-digit edit in any of them
 * would silently desynchronise the others, and the failure mode is ugly: the
 * WebKit stage derives libkernelBase by SUBTRACTING the export RVA from a live
 * GOT slot and requiring three-way agreement, so a stale slot or export does not
 * throw a clear error -- it fails the agreement check and looks like a KASLR
 * problem or a missing console value.
 *
 * So: parse all three, compare field by field, and FAIL LOUDLY on any drift.
 * The pinned baseline below is noslop/POC's table and is also asserted, so the
 * check still runs on a machine where ../noslop does not exist (CI, Pages, a
 * fresh clone) -- it just loses the third-source comparison and says so.
 *
 * This is a READ-ONLY text parse. It evaluates nothing, loads no exploit code,
 * and needs no console. Run it before every push, next to the other three:
 *     node tools/test_offsets_parity.mjs
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const NOslop_PATH = path.resolve(ROOT, "..", "noslop", "offsets", "offsets.json");

const FW = "13.60";

/* ------------------------------------------------------------------ the baseline
 * noslop/offsets/offsets.json["13.60"] (also mansoor0x/POC's offsets.mjs, per the
 * USERLAND_1360 header in bagagwa.js). Hex literals are printed the way each
 * source prints them, for a readable diff; the comparison is numeric.
 */
const EXPECTED = {
    hc: [0x56a58, 0x56ca0, 0x57ce8],
    gd: 0x1d6fa,
    nt: 0x48b0,
    gps: 0x334e238,
    gpe: 0x1b860,
    cls: 0x334e228,
    cle: 0x274e0,
    ers: 0x334e230,
    ere: 0xf7d0,
};
const FIELDS = ["hc", "gd", "nt", "gps", "gpe", "cls", "cle", "ers", "ere"];

/* ------------------------------------------------------------------ parsing */

let fails = 0;
const check = (name, cond, extra) => {
    console.log((cond ? "PASS  " : "FAIL  ") + name + (!cond && extra !== undefined ? "  -- " + extra : ""));
    if (!cond) fails++;
};

function read(file) {
    try {
        return fs.readFileSync(file, "utf8");
    } catch (e) {
        return null;
    }
}
/* SEP is "=" for the offsets file's `const X = 0x..` lines and ":" for bagagwa.js's
 * `x: 0x..` object literal. Getting this wrong silently reports every field as MISSING,
 * which is exactly what the first run of this harness did -- keep both paths tested (F0b). */
/* One hex literal after a name, tolerant of padding/alignment spaces. */
function one(src, name, sep) {
    const m = new RegExp(name + "\\s*" + sep + "\\s*(0[xX][0-9A-Fa-f]+)").exec(src);
    return m ? Number(BigInt(m[1])) : undefined;
}
/* An array of hex literals after a name. */
function list(src, name, sep) {
    const m = new RegExp(name + "\\s*" + sep + "\\s*\\[([^\\]]*)\\]").exec(src);
    if (!m) return undefined;
    const parts = m[1].split(",").map((s) => s.trim()).filter(Boolean);
    if (!parts.length) return undefined;
    return parts.map((s) => Number(BigInt(s)));
}

/* --- source 1: offsets/13.60.js ------------------------------------------- */
function parseOffsetFile(src) {
    const E = "=";
    return {
        hc: list(src, "OFFSET_wk_host_constructor_candidates", E),
        gd: one(src, "OFFSET_wk_natural_trampoline", E),
        nt: one(src, "OFFSET_lk_sceKernelSendNotificationRequest", E),
        gps: one(src, "OFFSET_wk_getpid_slot", E),
        gpe: one(src, "OFFSET_wk_getpid_exp", E),
        cls: one(src, "OFFSET_wk_close_slot", E),
        cle: one(src, "OFFSET_wk_close_exp", E),
        ers: one(src, "OFFSET_wk_error_slot", E),
        ere: one(src, "OFFSET_wk_error_exp", E),
    };
}

/* --- source 2: bagagwa.js USERLAND_1360 ----------------------------------- */
function parseBagagwa(src) {
    const block = /const\s+USERLAND_1360\s*=\s*Object\.freeze\(\{([\s\S]*?)\}\)/.exec(src);
    if (!block) return null;
    const b = block[1];
    const O = ":";                     /* object literal: `gd: 0x1d6fa` */
    return {
        hc: list(b, "hc", O),
        gd: one(b, "gd", O),
        nt: one(b, "nt", O),
        gps: one(b, "gps", O),
        gpe: one(b, "gpe", O),
        cls: one(b, "cls", O),
        cle: one(b, "cle", O),
        ers: one(b, "ers", O),
        ere: one(b, "ere", O),
    };
}

/* --- source 3: noslop JSON (optional, workstation-only) ------------------- */
function parseNoslop(file) {
    const src = read(file);
    if (src === null) return null;
    let j;
    try {
        j = JSON.parse(src);
    } catch (e) {
        return { broken: String(e && e.message).slice(0, 80) };
    }
    const e = j[FW];
    if (!e) return { broken: "no \"" + FW + "\" key" };
    const out = {};
    for (const f of FIELDS) {
        const v = e[f];
        if (v === undefined) continue;
        out[f] = Array.isArray(v) ? v.map((x) => Number(BigInt(x))) : Number(BigInt(v));
    }
    return out;
}

/* ------------------------------------------------------------------ compare */

const eq = (a, b) => {
    if (a === undefined || b === undefined) return false;
    if (Array.isArray(a) || Array.isArray(b)) {
        return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => v === b[i]);
    }
    return a === b;
};
const show = (v) => (v === undefined ? "MISSING" : Array.isArray(v) ? v.map((x) => "0x" + x.toString(16)).join(",") : "0x" + v.toString(16));

/* ---- load */

const offsetSrc = read(path.join(ROOT, "offsets", "13.60.js"));
check("F0: offsets/13.60.js exists and is readable", offsetSrc !== null, path.join(ROOT, "offsets", "13.60.js"));
if (offsetSrc === null) { console.log("\noffsets file missing -- cannot continue"); process.exit(1); }

const bagSrc = read(path.join(ROOT, "bagagwa.js"));
check("F0: bagagwa.js exists and is readable", bagSrc !== null);

const A = parseOffsetFile(offsetSrc);
const B = bagSrc ? parseBagagwa(bagSrc) : null;
const C = parseNoslop(NOslop_PATH);

check("F0: bagagwa.js USERLAND_1360 block parsed", B !== null,
    "the Object.freeze block was not found -- did the table get renamed?");
/* F0b: the parser itself must find every field on BOTH syntaxes. Without this, a
 * broken separator regex reports "MISSING" everywhere and the harness looks like a
 * real drift alarm -- it did exactly that once. */
if (B) {
    const bMissing = FIELDS.filter((f) => B[f] === undefined);
    check("F0b: bagagwa.js parser resolved every field", bMissing.length === 0,
        "unparsed: " + bMissing.join(",") + " (separator/name drift?)");
}

/* ---- 1. every field present in the offsets file (regression guard) */

for (const f of FIELDS) {
    check("F1: offsets/13.60.js carries " + f, A[f] !== undefined,
        "missing constant for " + f + " -- a stage reading the offsets file will not find it");
}

/* ---- 2. offsets file vs the pinned noslop/POC baseline */

for (const f of FIELDS) {
    check("F2: offsets/13.60.js " + f + " == pinned noslop baseline [" + show(EXPECTED[f]) + "]",
        eq(A[f], EXPECTED[f]), "got " + show(A[f]));
}

/* ---- 3. in-repo parity: offsets file vs bagagwa.js */

if (B) {
    for (const f of FIELDS) {
        check("F3: offsets/13.60.js " + f + " == bagagwa.js USERLAND_1360." + f,
            eq(A[f], B[f]), "offsets=" + show(A[f]) + " bagagwa=" + show(B[f]));
    }
}

/* ---- 4. third source: noslop JSON, when the workstation has it */

if (C === null) {
    console.log("SKIP  F4: ../noslop/offsets/offsets.json not present -- cross-source check skipped");
    console.log("      (this is expected on CI / Pages / a fresh clone; F2 still pins the values)");
} else if (C.broken) {
    check("F4: ../noslop/offsets/offsets.json parses", false, C.broken);
} else {
    for (const f of FIELDS) {
        check("F4: offsets/13.60.js " + f + " == noslop[\"" + FW + "\"]." + f,
            eq(A[f], C[f]), "offsets=" + show(A[f]) + " noslop=" + show(C[f]));
    }
    if (B) {
        for (const f of FIELDS) {
            check("F4: bagagwa.js " + f + " == noslop[\"" + FW + "\"]." + f,
                eq(B[f], C[f]), "bagagwa=" + show(B[f]) + " noslop=" + show(C[f]));
        }
    }
}

/* ---- 5. the deliberate 13.60-only fact, so it is not "fixed" by copying 13.00
 *         (noslop's 13.60 table has no sibling in this repo; assert the 13.60
 *          file actually declares a value rather than inheriting a 0 placeholder) */

check("F5: the trampoline is a real value, not the vtable placeholder 0",
    A.gd !== undefined && A.gd !== 0, "gd=" + show(A.gd));

/* ---- result */

console.log("");
if (fails) {
    console.log(fails + " parity check(s) FAILED -- the 13.60 userland table has drifted between sources.");
    console.log("Fix the source that is wrong; do NOT make them agree by editing the baseline.");
    process.exit(1);
}
console.log("all 13.60 userland offset sources agree (" + FIELDS.length + " fields x sources checked)");
