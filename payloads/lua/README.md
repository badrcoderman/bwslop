# Lua payloads (remote_lua_loader family)

These came from **n0llptr/remote_lua_loader** (`payloads/` and `payloads/test_cases/`).
They are kept here because they are the Lua-side counterpart of what this repo does on
the WebKit side, and because two of them are genuinely useful diagnostics on a console.

## What they are, and what they are NOT

**They do not run in the browser.** This repo's exploit is WebKit -> libkernel. These
`.lua` files are loaded by a **Lua-capable game process** (the loader injects them over
the game's own Lua engine). No tile in `bagagwa_probe.js` can execute them, and nothing
in this repo claims otherwise. They are here to be *served*, and to be read as
reference for how a game-side loader is shaped.

Same caveat the upstream repo carries: an unjailbroken game process can only reach the
sandbox it already has. A jailbroken one reaches more of the filesystem. "Runs an FTP
server" means *as seen by that game process*, not as the console's root.

## The files

| File | Upstream path | What it does |
|---|---|---|
| `ftp_server.lua` | `payloads/ftp_server.lua` | FTP server on **port 1337**, browsing/uploading/downloading the filesystem *as the game process sees it*. Use **WinSCP** as the client. FileZilla has known issues upstream. |
| `streaming_output.lua` | `payloads/test_cases/streaming_output.lua` | Prints basic info and deliberately triggers **two SIGSEGV crashes mid-run** -- the point is to prove the loader keeps streaming real-time output *across* a crashing payload. |
| `threading_test.lua` | `payloads/test_cases/threading_test.lua` | Examples of running Lua code in **new threads**. |

## Serving them

```
# from this directory, on a host the console can reach
python3 -m http.server 8000
# -> http://<host>:8000/ftp_server.lua
```

The upstream loader takes a URL per payload; point it at the file above. Two reference
servers worth having on the same host:

- **ps5-payload-dev/websrv** -- HTTP + WebDAV payload server (port 8080 by default).
  Also the right place to serve the `.elf` files in `../` over the network.
- **n0llptr/remote_lua_loader** -- the loader that consumes these Lua files.

## Provenance

Fetched from `raw.githubusercontent.com/n0llptr/remote_lua_loader/main/payloads/...`
(commit at fetch time: `main`). Unmodified. Licence and authorship belong to the
upstream project -- this directory is a local mirror for offline console work, not a
fork.
