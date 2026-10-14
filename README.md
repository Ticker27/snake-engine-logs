# Snake Engine 2.2.6 — GitHub Actions Logs

**Package:** `com.snake` · **Version:** 2.2.6 · **Source:** `Snake_Engine_2.2.6.apk` (30 MB, DEX 3.7 MB, 5,448 classes, arm64-v8a)
**Engine:** Flutter 3.5.4 (Dart AOT) + VirtualApp native (`libengine.so` 8.1 MB)

> **Boundary:** This repository is **GitHub Actions — log assemble only**. CI uses a **suitable environment** (Alpine/Linux sandbox via `androguard` + `capstone` + `readelf`/`objdump`), not this repo's Actions. Actions here only re-assembles the same `readelf -sida` / `objdump -d` / Ghidra-headless logs as workflow artifacts — see `SOUL.md` (`Use GitHub Actions for assembling files only; CI uses a suitable environment`).

## What this repo stores

- `logs/readelf/` — `readelf -h -S -s -d -r -n -l` for `libengine.so` / `libapp.so` / `libflutter.so` (Symbols, Dynamic, Sections, Headers, Relocs)
- `logs/ghidra/` — `objdump -d` (trimmed to `JNI_OnLoad` `0xF3FA0` + `.mytext` `0x81EEAC` + helpers `0xB01C4`/`0xB134C`) + Capstone disassembly for the same offsets (no Ghidra GUI needed; Ghidra headless can re-run from the same inputs on a suitable runner)
- `logs/dex/` + `logs/manifest/` — `androguard apkid/sign/axml` + `ilil` call-site table (7 sites, 6 constants, `F1/F2/F3` encoding)
- `logs/dart/` — `libapp.so` Dart isolate snapshot strings (`IsolateSnapshotData` 1.3 MB @ `0x40C0`) + `libapp.so` all strings
- `docs/` — Full reports: `SnakeEngine_Analysis_Report.md` (architecture, permissions, components, data flows) + `SnakeEngine_DeepDive_ilil_Dart.md` (ilil encode, C++ Offset↔Java, Dart 3.5.4 pool)

## Rebuild (suitable environment, not Actions)

```sh
# Alpine / PRoot (aarch64) — same as the analysis sandbox
apk add binutils ripgrep python3 py3-pip
pip install androguard capstone

# readelf -sida + objdump -d + Dart pool
./scripts/rebuild_readelf_logs.sh path/to/Snake_Engine_2.2.6.apk
```

`rebuild_readelf_logs.sh` writes the same `logs/readelf/*` + `logs/ghidra/*` + `logs/dex/*` + `logs/dart/*` reproduced above. Commit the rebuilt `logs/` — the workflow only packages them.

## ilil String Table (static — plaintext requires runtime)

7 call sites in `vx` (`VirtualApp OAuth Bridge`), 6 constants `15799041` (`0xF11301`), `15799553`, `15865089`, `15930625`, `15799584`, `15799585` — high byte `F1/F2/F3` = table id. Plaintext is AES/XOR-encrypted in `libengine.so .text` (decrypted by `JNI_OnLoad @ 0xF3FA0` via `mmap/mprotect` vector loop `0xF40B0`); dump with Frida:

```js
// frida -U -f com.snake --no-pause -l dump.js
Java.perform(()=>{const N=Java.use("com.snake.helper.Native");
  N.ilil.overload('int').implementation=function(k){const r=this.ilil(k);console.log(`[ilil] ${k} 0x${k.toString(16)} => ${r}`);return r;};
  [15799041,15799553,15865089,15930625,15799584,15799585].forEach(k=>console.log(N.ilil(k)));});
```

See `logs/dex/ilil-call-sites.log` + `logs/ghidra/libengine-jni_onload-capstone.log` + `docs/SnakeEngine_DeepDive_ilil_Dart.md` §1.

## Workflow

`.github/workflows/logs.yml` — `workflow_dispatch` — runs on `ubuntu-latest` with `binutils` + `python3` + `androguard`/`capstone`, re-reads the APK committed as a release asset (never committed as binary), regenerates `readelf -sida` / `objdump -d` / `capstone` / `androguard` logs, uploads them as `snake-engine-logs-<sha>` artifact. No APK is committed.
