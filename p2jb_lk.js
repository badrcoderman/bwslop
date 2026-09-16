/*
 * p2jb_lk.js — per-firmware libkernel_web.sprx offsets for rop-worker.js's
 * synchronous fireSync executor. window.P2JB_LK[fw] -> rop_worker.init({lk}).
 *
 * RE'd from I:\EXTRACTED\<fw>\system_b\common\lib\libkernel_web.sprx
 * (E:\ps5\p2jb\lk\lkfind.py). Method VALIDATED: reproduces netctrl's known-good
 * 10.00 offsets exactly (pop_rsp 0x343AA, syscall_wrapper 0x1A5B7, setjmp 0x1CB43,
 * longjmp 0x1CB9C, slot_expect 0x190DB, thread_list 0x64218). Convention: rva =
 * file_off - 0x4000. NO GUESSING — every value is a validated signature match.
 *
 * Signatures:
 *   syscall_wrapper : 49 89 ca 0f 05 c3            (mov r10,rcx; syscall; ret)
 *   setjmp          : 48 89 f9 48 8b 14 24 48 89 11
 *   longjmp         : 48 89 fa 89 f0 48 8b 0a 48 8b 5a 08
 *   slot_expect     : eb 15 4c 89 f7 48 89 de b9 01 00 00 00 31 d2  (cond_wait resume)
 *   thread_list     : lea rax,[rip+X]; mov r15,[rax]; test r15,r15  -> X
 *
 * NOT here:
 *   pop_rsp  — `5C C3` was REMOVED from libkernel_web in 12.xx (whole-file count 0;
 *              present once on 10.00). The adapter supplies the WEBKIT pop rsp
 *              (libSceNKWebKit gadgets["pop rsp"], verified 12.00-12.70) via
 *              W.gadgets.pop_rsp instead. rop-worker g() falls through to it.
 *   slot_off — parked-worker stack offset; a RUNTIME value (stack depth), not in
 *              the module. rop-worker scans the 0x80000 worker stack for the
 *              qword == kbase+slot_expect and uses that offset (no guess).
 *   pthread_next/stack/stacksz — libthr struct fields 0x38/0xA8/0xB0; the thread-
 *              walk head (`4c 8b 38 4d 85 ff`) is byte-identical 10.00..12.70, so
 *              the struct layout is unchanged. rop-worker defaults apply.
 */
// pthread_create = scePthreadCreate export (NID 6UgtwV+0zb4), resolved from the
// libkernel_web dynsym = 0x79B0 on BOTH size groups (12.00..12.70). p2jb's leak-worker
// + elf_run spawn threads through this (4-arg: pthread_t*, attr=NULL, start, arg).
// NOTE: p2jb.js's ORIGINAL setjmp/longjmp/Thrd_create were libc_base+0x58F80/0x58FD0/
// 0x4BF0 — WRONG for this build (0x58F80 lands in FPU-math code -> spawned thread ran
// garbage -> SIGILL/WebProcess crash). setjmp/longjmp are the SIMPLE _setjmp-style in
// libkernel_web (0x1D3B3/0x1D40C, rip@0/rsp@0x10/fpu@0x40, IDA-verified) — same ones
// fireSync uses. libc setjmp@0x5b850 is sigsetjmp (saves sigmask) -> wrong for p2jb's
// manual jmpbuf. The adapter feeds these to p2jb via window.P2JB_SETJMP/LONGJMP/PTHREAD_CREATE.
window.P2JB_LK = {
    // group A: libkernel_web 528364 bytes
    "12.00": { syscall_wrapper: 0x1AE27, setjmp: 0x1D3B3, longjmp: 0x1D40C, pthread_create: 0x79B0, slot_expect: 0x197FB, thread_list: 0x64218 },
    "12.02": { syscall_wrapper: 0x1AE27, setjmp: 0x1D3B3, longjmp: 0x1D40C, pthread_create: 0x79B0, slot_expect: 0x197FB, thread_list: 0x64218 },
    "12.20": { syscall_wrapper: 0x1AE27, setjmp: 0x1D3B3, longjmp: 0x1D40C, pthread_create: 0x79B0, slot_expect: 0x197FB, thread_list: 0x64218 },
    // group B: libkernel_web 544860 bytes
    "12.40": { syscall_wrapper: 0x1AE47, setjmp: 0x1D3D3, longjmp: 0x1D42C, pthread_create: 0x79B0, slot_expect: 0x1981B, thread_list: 0x68218 },
    "12.60": { syscall_wrapper: 0x1AE47, setjmp: 0x1D3D3, longjmp: 0x1D42C, pthread_create: 0x79B0, slot_expect: 0x1981B, thread_list: 0x68218 },
    "12.70": { syscall_wrapper: 0x1AE47, setjmp: 0x1D3D3, longjmp: 0x1D42C, pthread_create: 0x79B0, slot_expect: 0x1981B, thread_list: 0x68218 },

    // group C: 13.40/13.60. READ THIS BEFORE TRUSTING THE FOUR TEXT VALUES.
    //
    // thread_list = 0x6C218 is VERIFIED. Source: X1NONs/PSAITO offsets/13.XX/13.60
    // (declared "X1NON-verified"), vendored byte-identically from X1NON-PSJB. It
    // also fits the one clean progression this table shows across every group:
    //     12.00 0x64218  ->  12.40 0x68218  ->  13.60 0x6C218      (+0x4000 per group)
    //
    // syscall_wrapper / setjmp / longjmp / slot_expect are EXTRAPOLATED, not RE'd.
    // 13.60 sits exactly one group-step from 12.40 (see thread_list above), and every
    // text RVA in this table moves by the same +0x20 when a group changes
    // (12.00 0x1AE27 -> 12.40 0x1AE47, 0x1D3B3 -> 0x1D3D3, 0x197FB -> 0x1981B), so
    // each value is 12.40's plus 0x20. NO upstream publishes these: PSAITO and
    // slopkit2's 13.20 profile both stop at the WebKit/GOT layer, and X1NON-PSJB has
    // no libkernel_web table at all. This is the only place the numbers could come
    // from without the 13.60 sprx.
    //
    // VERIFY IN ONE COMMAND before trusting a run:
    //     node tools/lkfind.js <13.60 libkernel_web.sprx> --expect 12.00
    // Failure modes are benign for a first run, and none of them writes kernel
    // memory: a wrong slot_expect makes resolveSlot()'s scan find nothing (clean
    // throw), while a wrong syscall_wrapper/setjmp/longjmp jumps to a bad address and
    // kills the WebProcess (browser tab, recoverable).
    //
    // HARDWARE RESULT (13.60 console, 2026-09): slot_expect 0x1983B is WRONG
    // -- resolveSlot() found no parked slot at kbase+0x1983B (every syscall threw
    // before any kernel call). thread_list=0x6C218 is hardware-VERIFIED: find_worker()
    // succeeded. bagagwa_probe.js's "Calibrate LK row" tile measures the real
    // slot_expect from the parked worker stack (the qword resolveSlot scans for IS
    // the live return address into libkernel text) and derives the other three RVAs
    // at the fixed 12.x-group deltas, patching THIS row live via the executor's
    // by-reference lk.
    //
    // CALIBRATED VALUES (hardware 2026-09, two independent derivations agreeing):
    //  * slot_expect = 0x1988B. (a) 12.00's 0x197FB + the verified stub shift: EVERY
    //    syscall stub moved exactly +0x90 from 12.00 to 13.60 (0x001: 0x1BA8A->0x1BB1A,
    //    0x007: 0x1AE50->0x1AEE0, ...). (b) Found frame-validated in the parked worker
    //    stack top at stack+0x7fc28 (12.00 parks at 0x7fc18). The probe's picker now
    //    prefers this anchor explicitly.
    //  * 0x1FD01 also frame-validated on the stack = PSAITO's worker_wait_return.
    //    Second anchor; recorded for cross-reference, not used by the executor.
    //  * syscall_wrapper/setjmp/longjmp were delta-derived (anchor + the fixed
    //    12.x-group deltas +0x162C/+0x3BB8/+0x3C11).
    //
    // HARDWARE RESULT, calibrated run (13.60 console, 2026-09): ALL FOUR ARE NOW
    // VERIFIED, not extrapolated.
    //  * The 0x2198d pick was abandoned (thread-entry trampoline); with the anchor-first
    //    picker, the hijack landed at stack+0x7fc28 -- exactly the frame slot_expect
    //    0x1988B predicts (12.00 parks at 0x7fc18). fired=19.
    //  * syscall_wrapper = 0x1AEB7 is PROVEN: 19 chains executed and returned correct
    //    values (getpid=0x4f, getppid=0x34, getuid/getgid=0x1, kqueue=fd 7, pipe2 wrote
    //    rfd 7 / wfd 8, close -> 0). A wrong wrapper address would have killed the
    //    WebProcess on the first call.
    //  * setjmp 0x1D443 / longjmp 0x1D49C are PROVEN too: fireSync runs "big" mode
    //    through the manual jmp_buf on EVERY call, so 19 clean fires exercise both.
    //  * The poison self-check (write64(retval, C0FFEEDEADBEEF) then getpid) came back as
    //    pid 0x4f, so the return slot is genuinely written by this chain.
    // The +0x90 stub shift and the +0x20 group step both hold on real hardware; this row
    // no longer needs the "one unverified leg" caveat.
    "13.60": { syscall_wrapper: 0x1AEB7, setjmp: 0x1D443, longjmp: 0x1D49C, pthread_create: 0x79B0, slot_expect: 0x1988B, thread_list: 0x6C218 },
};
