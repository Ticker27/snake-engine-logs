#!/bin/bash
# rebuild_readelf_logs.sh — suitable environment (Alpine / PRoot)
# Rebuilds the same readelf -sida / objdump -d / Ghidra-capstone / androguard logs
# Usage: ./scripts/rebuild_readelf_logs.sh path/to/Snake_Engine_2.2.6.apk
set -euo pipefail
APK="${1:-}"
if [ -z "$APK" ]; then echo "Usage: $0 <apk>" >&2; exit 1; fi
if [ ! -f "$APK" ]; then echo "APK not found: $APK" >&2; exit 1; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(TMPDIR=/tmp mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
echo "Unzipping $APK ..."
unzip -q "$APK" -d "$TMPDIR/unzipped"
SO_ENGINE="$TMPDIR/unzipped/lib/arm64-v8a/libengine.so"
SO_APP="$TMPDIR/unzipped/lib/arm64-v8a/libapp.so"
SO_FLUTTER="$TMPDIR/unzipped/lib/arm64-v8a/libflutter.so"
DEX="$TMPDIR/unzipped/classes.dex"
MANIFEST="$TMPDIR/unzipped/AndroidManifest.xml"
mkdir -p "$ROOT/logs/readelf" "$ROOT/logs/ghidra" "$ROOT/logs/dex" "$ROOT/logs/manifest" "$ROOT/logs/dart"
echo "readelf ..."
readelf -h "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-elf-header.log"
readelf -S "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-sections.log"
readelf -s "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-symbols.log"
readelf -d "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-dynamic.log"
readelf -r "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-relocs.log"
readelf -n "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-notes.log"
readelf -l "$SO_ENGINE" > "$ROOT/logs/readelf/libengine-programs.log"
readelf -h "$SO_APP" > "$ROOT/logs/readelf/libapp-elf-header.log"
readelf -S "$SO_APP" > "$ROOT/logs/readelf/libapp-sections.log"
readelf -s "$SO_APP" > "$ROOT/logs/readelf/libapp-symbols.log"
readelf -d "$SO_APP" > "$ROOT/logs/readelf/libapp-dynamic.log"
readelf -l "$SO_APP" > "$ROOT/logs/readelf/libapp-programs.log"
readelf -s "$SO_FLUTTER" | head -n 100 > "$ROOT/logs/readelf/libflutter-symbols-head.log"
echo "objdump -d (trimmed) ..."
if command -v objdump >/dev/null 2>&1; then
  OBJDUMP=objdump
else
  OBJDUMP=llvm-objdump
fi
"$OBJDUMP" -d "$SO_ENGINE" > "$TMPDIR/objdump.log"
python3 - <<PY
lines=open("$TMPDIR/objdump.log",errors="ignore").read().split("\n")
keep=set(range(0,100))
targets=['f3fa0','f3fb','f400','f410','81eeac','81eeb','b01c4','b134c','f4048','f4054']
for i,l in enumerate(lines):
    for t in targets:
        if t in l.lower():
            for j in range(max(0,i-5), min(len(lines), i+300)):
                keep.add(j)
    if 'Disassembly of section' in l:
        keep.add(i)
        for j in range(i+1, min(len(lines), i+5)):
            keep.add(j)
open("$ROOT/logs/ghidra/libengine-objdump-d.log","w").write("\n".join(lines[i] for i in sorted(keep)))
print(f"objdump trimmed: {len(lines)} -> {len(keep)} lines")
PY
echo "capstone ..."
python3 - <<PY
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
cs=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
data=open("$SO_ENGINE","rb").read()
for name,off,size in [("libengine-jni_onload-capstone",0xF3FA0,800),("libengine-mytext-capstone",0x81EEAC,0xF4),("libengine-b01c4-capstone",0xB01C4,200),("libengine-b134c-capstone",0xB134C,200)]:
    chunk=data[off:off+size]
    open(f"$ROOT/logs/ghidra/{name}.log","w").write("\n".join(f"  {ins.address:08x}: {ins.mnemonic:12s} {ins.op_str}" for ins in cs.disasm(chunk, off)))
print("capstone done")
PY
echo "androguard ..."
androguard apkid "$APK" > "$ROOT/logs/dex/apkid.log" 2>&1 || true
androguard sign "$APK" > "$ROOT/logs/dex/sign.log" 2>&1 || true
androguard axml "$MANIFEST" > "$ROOT/logs/manifest/AndroidManifest-decoded.xml" 2>&1 || true
echo "dart snapshot ..."
python3 - <<PY
import re
path="$SO_APP"
data=open(path,"rb").read()
iso=data[0x40c0:0x40c0+0x150700]
strs=re.findall(rb'[\x20-\x7e]{4,}', iso)
open("$ROOT/logs/dart/isolate-strings.log","w").write("\n".join(s.decode(errors="ignore") for s in strs[:10000]))
allstrs=re.findall(rb'[\x20-\x7e]{5,}', data)
open("$ROOT/logs/dart/libapp-all-strings.log","w").write("\n".join(s.decode(errors="ignore") for s in allstrs[:10000]))
print("dart done")
PY
# ilil call-site table is static; keep the committed logs/dex/ilil-call-sites.log
echo "Done — see logs/"
