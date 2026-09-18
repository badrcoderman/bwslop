# Lua payloads (remote_lua_loader family) — **CANNOT RUN HERE**

Mirrored from **n0llptr/remote_lua_loader**. Read this before assuming they are usable.

## The hard blocker, in the upstream project's own words

> Remote lua loader for PS4 and PS5, based on gezine's finding that allows games built with
> **Artemis engine** to load arbitrary lua file. … Currently this loader is specific for the
> following list of games: Raspberry Cube (CUSA16074), Aibeya (CUSA17068), Hamidashi
> Creative (CUSA27389) … *"If you have the savedata setup and want to update the files,
> please refer to UPDATE.md"*

So a Lua payload needs **three** things, none of which this repo provides:

1. One of **18 specific Artemis-engine visual novels installed** on the console;
2. **Crafted savedata** injected into that game (the loader's `SETUP.md` / `UPDATE.md`);
3. That **game launched**, so its Lua VM loads the payload.

Then the payload runs **inside the game process**, and everything it can do comes from the
loader's injected globals. `/` in these files is *the game process's view*, not the console.

## The payloads prove it themselves

`streaming_output.lua` opens with a gate, not a comment:

```lua
function check_prerequisites()
    if not memory then
        errorf("stage #1 not loaded")     -- hard stop if the loader's globals are absent
    end
end
```

and `ftp_server.lua` immediately calls `memory.alloc(16)` at the top level. Every file here
uses `memory.alloc/read_qword/write_qword`, `syscall.resolve/thr_self`,
`run_lua_code_in_new_thread`, `printf`, `errorf`, `hex` and `eboot_base` / `libc_base` /
`libkernel_base` — **all of them loader-provided**. Bare Lua has none of them.

**Our page is WebKit with no Lua engine, so a tile in `bagagwa_probe.js` can never execute
one of these.** That is a fact about the environment, not a missing feature.

## Why these were NOT ported to JavaScript

| Lua payload | What it actually does | Equivalent that already exists here | Verdict |
|---|---|---|---|
| `ftp_server.lua` | FTP server on **127.0.0.1:1337** via `memory.alloc` + raw sockets | **`../ftpsrv-ps5.elf`** and **`../websrv-ps5.elf`** — the maintained PS5 FTP / HTTP+WebDAV servers, delivered through `../elfldr-ps5-1360.elf` | **Don't port.** A JS rewrite would be a worse copy of an ELF we already ship. And it is structurally wrong for this executor: an FTP server is a **blocking `accept()` loop**, while our ROP executor is a synchronous call that **busy-spins the main thread** — a blocking accept wedges the browser (the documented wedge pathology), so it would need non-blocking sockets + `kqueue` + a worker. Large, and pointless next to the ELF. |
| `streaming_output.lua` | Prints the three bases, then writes two bogus addresses to force **two SIGSEGVs**, proving output keeps streaming across a crashing payload | The **bases** and the **real-time streaming log** are already us: `OFF-base` / `T5-state` rows, and the log goes to the DOM + `localStorage` + `flushMark`/`syncMark` beacons | Mostly covered. The **deliberate-crash half has no equivalent** — and it is the one genuinely portable idea (see below). |
| `threading_test.lua` | Runs Lua in new threads (`run_lua_code_in_new_thread`) | **Web Workers**, which this repo already uses for the executor: `rop-worker.js` / `rop_slave.js` | Nothing to port. |

## The one piece worth porting, and its honest cost

`streaming_output.lua`'s real contribution is the **crash test**: it proves the output
pipeline survives the payload dying. We make the same claim — the saved log
(`bwslop_sc_log`) is supposed to survive a WebProcess death — and we have never tested it.

A JS port is one line of substance: `window.write64(<unmapped address>, 0)`. What it costs:

* it **kills the browser tab** on the console (that is the point, and it is what the Lua
  payload does too);
* the console then needs a reload before anything else runs;
* the proof is *after the fact*: a marker written to `localStorage` before the crash must
  still be readable from the restored log on the next load.

It is therefore **not** a tile, **not** in RUN ALL, and not implemented here. It belongs
behind an explicit button with a "this closes the tab" warning — ask before adding it.

## Serving these (for the game-side route)

```
python3 -m http.server 8000
# -> http://<host>:8000/ftp_server.lua
```

then point the upstream loader at that URL for whichever of the 18 games you own.
Companion payload server: **ps5-payload-dev/websrv** (HTTP + WebDAV, port 8080) — also the
right place to serve the `.elf` files in `../`.

## Provenance

Fetched from `raw.githubusercontent.com/n0llptr/remote_lua_loader/main/payloads/...`
(`payloads/`, plus `payloads/test_cases/` for the two test cases). **Unmodified.** Licence
and authorship belong to the upstream project — this directory is a local mirror for
offline console work, not a fork.
