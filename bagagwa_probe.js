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
 * window.syscall() returns the RAW 64-bit rax from syscall_wrapper (mov r10,rcx; syscall;
 * ret). We have not confirmed on hardware which error convention 13.60 uses, so every
 * call logs its raw word and the decode is offered as a HEURISTIC, labelled "enc=".
 * -errno means the high word is 0xFFFFFFFF with a negative low word, which is what
 * p2jb_poops.js assumes (create_pipe tests the low 32 bits for non-zero). enc=raw with a
 * small positive value means the call succeeded.
 *
 * FreeBSD errno numbering -- in particular ENOSYS = 78, NOT 38, and not ENOSPC. 78 is the
 * single most important value here: it means the syscall does not exist in this kernel,
 * which is the answer that stops the Bagagwa chain dead.
 */
(function () {
    "use strict";

    if (window.__BWP_LOADED) return;
    window.__BWP_LOADED = true;

    var FW = window.fw_str || "?";

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

    function decode(ret) {
        var r;
        try { r = BigInt(ret); } catch (e) { return { ok: false, errno: -1, enc: "unparsed" }; }
        var lo = Number(BigInt.asIntN(32, r));
        var hi = Number((r >> 32n) & 0xFFFFFFFFn);
        if (hi === 0xFFFFFFFF && lo < 0) {
            var n = -lo;
            return { ok: false, errno: n, errName: ERRNO[n] || ("errno" + n), enc: "-errno" };
        }
        if (r >= 0n && r <= 0xFFFFFFFFn) return { ok: true, val: r, enc: "raw" };
        return { ok: true, val: r, enc: "raw-wide" };
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
        "font:12.5px/1.55 ui-monospace,Menlo,Consolas,monospace;color:#c9c9d1;",
        "white-space:pre-wrap;word-break:break-word;-webkit-user-select:text;user-select:text;}",
        ".bwp-sec{color:#fff;font-weight:800;}",
        ".bwp-ok{color:#5fdc90;}",
        ".bwp-err{color:#ff8080;}",
        ".bwp-warn{color:#ffce5c;}",
        ".bwp-dim{color:#6f7076;}",
        ".bwp-foot{display:flex;gap:11px;flex-wrap:wrap;margin-top:13px;}",
        ".bwp-btn{padding:.68rem 1.3rem;border-radius:1.05rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 .92rem Arial;transition:background-color .18s ease;}",
        ".bwp-btn:hover{background:#a2a2a6;color:#202020;}",
        ".bwp-btn:focus{outline:2px solid #5fdc90;outline-offset:2px;}",
        ".bwp-mini{position:fixed;bottom:14px;right:14px;z-index:2147483647;",
        "padding:.7rem 1.5rem;border-radius:1.15rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 1rem Arial;display:none;}",
        ".bwp-mini:hover{background:#a2a2a6;color:#202020;}",
    ].join("");

    var styleEl = document.createElement("style");
    styleEl.textContent = CSS;
    document.head.appendChild(styleEl);

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
        '<div class="bwp-foot">',
        '  <button class="bwp-btn" id="bwp-all">run all</button>',
        '  <button class="bwp-btn" id="bwp-clear">clear output</button>',
        '  <button class="bwp-btn" id="bwp-dl">download log</button>',
        '  <button class="bwp-btn" id="bwp-clearsaved" style="display:none;">clear saved log</button>',
        '</div>',
    ].join("");
    document.body.appendChild(root);

    var mini = document.createElement("button");
    mini.className = "bwp-mini";
    mini.textContent = "show bagagwa panel";
    document.body.appendChild(mini);

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
            if (cur.length > 16000) cur = cur.slice(-8000);
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
    function notify(msg) {
        try { if (window.send_notification) window.send_notification(msg); } catch (e) { }
    }

    /* --------------------------------------------------- call one syscall */

    /* Never throws: a throw is a RESULT here. The most likely first outcome on a new
     * firmware is resolveSlot() failing to find the parked worker, and the operator has to
     * be able to read that rather than watch the tab die silently. */
    function S(label, nr, args) {
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
        while (a.length < 6) a.push(undefined);
        var t0 = Date.now();
        try {
            var ret = window.syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
            var d = decode(ret);
            var ms = Date.now() - t0;
            out(label, "ret=" + hex(ret) + " enc=" + d.enc
                + (d.ok ? "" : " " + (d.errName || d.errno)) + "  (" + ms + "ms)",
                d.ok ? "ok" : "err");
            return { label: label, nr: nr, ok: d.ok, errno: d.errno, errName: d.errName, ret: ret, ms: ms };
        } catch (e) {
            var why = String((e && e.message) || e).slice(0, 110);
            out(label, "THREW " + why, "err");
            return { label: label, nr: nr, threw: why, ok: false };
        }
    }

    function B(x) { return (typeof x === "bigint") ? x : BigInt(x); }
    function malloc(sz) { return B(window.malloc(sz)); }
    function zeros(ptr, n) {
        var z = new Uint8Array(n);
        if (window.write_buffer) window.write_buffer(B(ptr), z);
        return ptr;
    }

    /* ====================================================== the payloads */

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
            out("T1-VERDICT", "no call returned -- read the RW-* beacons: the executor did not start", "err");
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
        if (kq.ok) {
            ok++;
            var fd = Number(BigInt.asIntN(32, kq.ret));
            out("T2-kqueue", "fd=" + fd + (fd >= 0 ? " -- a real descriptor, closed again" : " -- not a sane fd"),
                fd >= 0 ? "ok" : "warn");
            if (fd >= 0) S("close(kqueue)", 0x006, [BigInt(fd)]);
        }

        try {
            var pfd = zeros(malloc(8), 8);
            var pr = S("pipe2", 0x2AF, [pfd, 0n]);
            total++;
            if (pr.ok) {
                ok++;
                if (window.read_buffer) {
                    var buf = window.read_buffer(pfd, 8);
                    var rd = new Int32Array(buf.buffer, buf.byteOffset, 2);
                    out("T2-pipe2", "rfd=" + rd[0] + " wfd=" + rd[1], "ok");
                    if (rd[0] >= 0) S("close(pipe r)", 0x006, [BigInt(rd[0])]);
                    if (rd[1] >= 0) S("close(pipe w)", 0x006, [BigInt(rd[1])]);
                }
            }
        } catch (e) {
            out("T2-pipe2", "THREW " + String((e && e.message) || e).slice(0, 90), "err");
        }

        notify("bagagwa T2 resources " + ok + "/" + total);
        return { ok: ok > 0, summary: ok + "/" + total };
    }

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
        var init = S("aio_init", 0x29E, [0n]);
        var wait = S("aio_multi_wait(all-zero)", 0x297, [0n, 0n, 0n, 0n, 0n]);

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
        out("T3-VERDICT", "aio_multi_wait REACHABLE (" + hex(wait.ret)
            + (wait.errName ? " " + wait.errName : "")
            + "). The chain is still reachable in principle -- but this did NOT settle the ABI.", "ok");
        chip(elVerdict, "ok", "aio_multi_wait reachable");
        notify("bagagwa: aio_multi_wait reachable on " + FW);
        return { ok: true, summary: wait.errName || "ok" };
    }

    /* T4 -- osem. Bagagwa's conversion targets osem's 32-bit refcount at +0x54, the same
     * width as the AIO decrement, so if osem is unreachable too the chain has no target.
     *
     * The ABI here is NOT settled either: Bagagwa_chain calls (name, attr) while PSAITO's
     * probe calls (name, 0, 1, 1, 0). We use (name, attr) and print the raw return, so one
     * run tells you which the kernel accepted instead of us guessing. */
    function pOsem() {
        try {
            var name = window.alloc_string("bwp_probe");
            var attr = zeros(malloc(0x20), 0x20);
            var cr = S("osem_create(name,attr)", 0x225, [name, attr]);
            if (!cr.ok) {
                out("T4-VERDICT", "osem_create refused (" + (cr.errName || cr.ret) + "). "
                    + "The ABI may simply be the other shape -- try (name,0,1,1,0) before concluding.", "warn");
                return { ok: false, summary: cr.errName || "refused" };
            }
            var h = cr.ret;
            out("T4-create", "handle=" + hex(h), "ok");
            S("osem_open", 0x227, [h]);
            S("osem_close", 0x228, [h]);
            var del = S("osem_delete", 0x226, [h]);
            out("T4-VERDICT", del.ok
                ? "osem create/open/close/delete all answered -- the refcount target exists."
                : "created, but delete refused -- that is itself information (see the raw return).",
                del.ok ? "ok" : "warn");
            notify("bagagwa T4 osem reachable");
            return { ok: true, summary: "reachable" };
        } catch (e) {
            out("T4-VERDICT", "THREW " + String((e && e.message) || e).slice(0, 90), "err");
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

    /* ============================================================ the menu */

    var PAYLOADS = [
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
            id: "aio", label: "AIO reach", run: pAio,
            desc: "aio_init and aio_multi_wait with ALL-ZERO arguments. num=0 cannot link a "
                + "waiter list, so this cannot arm the UAF. THE decisive test.",
        },
        {
            id: "osem", label: "osem", run: pOsem,
            desc: "osem_create / open / close / delete. The 32-bit refcount at +0x54 is the "
                + "chain's intended target.",
        },
        {
            id: "exec", label: "Executor state", run: pExecutor,
            desc: "Read-only. Dumps kbase, the resolved hijack slot and the P2JB_LK row, so a "
                + "failure above can be attributed.",
        },
    ];

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

    function runPayload(p) {
        if (STATE[p.id] === "run") return;
        STATE[p.id] = "run";
        renderTile(p.id);
        paint("--- " + p.label + " ---", "sec");
        var res;
        try { res = p.run(); } catch (e) {
            out(p.id + "-THREW", String((e && e.message) || e).slice(0, 140), "err");
            res = { ok: false };
        }
        STATE[p.id] = res && res.ok ? "ok" : "bad";
        renderTile(p.id);
        if (res && res.summary) paint("    " + p.label + ": " + res.summary, res.ok ? "dim" : "warn");
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
        paint("=== RUN ALL ===  fw=" + FW + "  (userland only, no kernel writes)", "sec");
        var q = PAYLOADS.slice();
        (function next() {
            if (!q.length) {
                var ok = PAYLOADS.filter(function (p) { return STATE[p.id] === "ok"; }).length;
                out("RUNALL-VERDICT", ok + "/" + PAYLOADS.length + " payloads reported ok. "
                    + "Read the AIO reach row above: it is the one that decides Bagagwa's fate.", "sec");
                notify("bagagwa: " + ok + "/" + PAYLOADS.length + " payloads ok on " + FW);
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
    paint("errno 78 = ENOSYS. If AIO reach reports it, the chain is dead on this firmware.", "dim");
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
    try { runAll(); } catch (e) {
        out("PANEL-FAIL", String((e && e.message) || e).slice(0, 140), "err");
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
     *    "we called it wrong". Settle it from the AIO reach raw returns first.
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
