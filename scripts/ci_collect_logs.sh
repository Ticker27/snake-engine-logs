#!/bin/bash
# ci_collect_logs.sh — collect the 9 missing pieces on Actions (push) — NOT on Alpine
# This is called by .github/workflows/logs.yml on ubuntu-latest.
# It assembles ALL file parts that were NOT yet logged, via suitable-environment-style
# tools that are allowed to run on Actions (heavy Ghidra, full aapt/arsc, dex CFG).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APK="${1:-}"
# APK is optional — repo is logs-only; APK comes from workflow artifact when present.
# When no APK, we verify already-committed logs and (if Ghidra present) re-run headless.

mkdir -p "$ROOT/logs/arsc" "$ROOT/logs/apk-tree" "$ROOT/logs/dex/full" "$ROOT/logs/dart/pool" "$ROOT/logs/manifest/risk" "$ROOT/logs/ghidra/headless"

if [ -n "$APK" ] && [ -f "$APK" ]; then
  echo "[collect] APK provided: $APK"
  TMPDIR="$(TMPDIR=/tmp mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT
  unzip -q "$APK" -d "$TMPDIR/unzipped"
  SO_ENGINE="$TMPDIR/unzipped/lib/arm64-v8a/libengine.so"
  SO_APP="$TMPDIR/unzipped/lib/arm64-v8a/libapp.so"
  SO_FLUTTER="$TMPDIR/unzipped/lib/arm64-v8a/libflutter.so"

  echo "[collect] 1/9 resources.arsc — androguard arsc + aapt2"
  if command -v androguard >/dev/null 2>&1; then
    androguard arsc "$APK" > "$ROOT/logs/arsc/arsc-decoded.log" 2>&1 || true
    androguard arsc "$APK" 2>&1 | head -n 5000 > "$ROOT/logs/arsc/arsc-head.log" || true
  fi

  echo "[collect] 2/9 classes.dex — full class/method CFG (androguard + dex headers)"
  python3 - <<PY
import pathlib
from androguard.core.dex import DEX
dex = DEX(open("$TMPDIR/unzipped/classes.dex","rb").read())
classes = dex.get_classes()
with open("$ROOT/logs/dex/full/classes-summary.log","w") as f:
    f.write(f"Total classes: {len(classes)}\n")
    f.write(f"Total methods: {sum(len(c.get_methods()) for c in classes)}\n")
    f.write(f"Total fields: {sum(len(c.get_fields()) for c in classes)}\n\n")
    for c in sorted(classes, key=lambda x: x.get_name()):
        f.write(f"{c.get_name()} -> {c.get_superclassname()}  methods={len(c.get_methods())} fields={len(c.get_fields())}\n")
print("DEX summary done")
PY
  # Optional: decompile with androguard decompile if available (heavy — skip if missing)
  if python3 -c "import androguard" 2>&1; then
    echo "[collect] DEX CFG — per-class detail via androguard cg (sample)"
    python3 - <<PY 2>&1 | head -n 2000 > "$ROOT/logs/dex/full/entry-C-dispatcher.log" || true
import logging; logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX
dex = DEX(open("$TMPDIR/unzipped/classes.dex","rb").read())
# Dump Entry.C dispatcher + vx bridge detail
def dump(cname, mname):
    for c in dex.get_classes():
        if c.get_name()==cname:
            for m in c.get_methods():
                if m.get_name()==mname:
                    code=m.get_code()
                    if not code:
                        print(f"{cname}->{mname}: no code"); return
                    print(f"=== {cname} -> {mname}{m.get_descriptor()} ===")
                    for ins in code.get_bc().get_instructions():
                        print(f"  {ins.get_name():28s} {ins.get_operands()}")
for cname,mname in [("Lcom/Entry;","C"),("Landroidx/appcompat/view/menu/vx;","b"),("Landroidx/appcompat/view/menu/vx;","c"),("Landroidx/appcompat/view/menu/vx;","f")]:
    dump(cname,mname)
PY
  fi

  echo "[collect] 3/9 libflutter.so — full readelf + strings"
  readelf -h "$SO_FLUTTER" > "$ROOT/logs/readelf/libflutter-elf-header.log" 2>&1 || true
  readelf -S "$SO_FLUTTER" > "$ROOT/logs/readelf/libflutter-sections.log" 2>&1 || true
  readelf -s "$SO_FLUTTER" > "$ROOT/logs/readelf/libflutter-symbols.log" 2>&1 || true
  readelf -d "$SO_FLUTTER" > "$ROOT/logs/readelf/libflutter-dynamic.log" 2>&1 || true
  readelf -l "$SO_FLUTTER" > "$ROOT/logs/readelf/libflutter-programs.log" 2>&1 || true
  # strings head already exists; ensure full is not committed (too large) — log counts
  echo "libflutter symbols: $(wc -l < "$ROOT/logs/readelf/libflutter-symbols.log") lines" > "$ROOT/logs/readelf/libflutter-meta.log"

  echo "[collect] 4/9 Dart pool deep decode — class/API/route pools"
  python3 - <<PY
import re, pathlib
so = pathlib.Path("$SO_APP")
data = so.read_bytes()
iso = data[0x40c0:0x40c0+0x150700]
strs = [s.decode(errors="ignore") for s in re.findall(rb'[\x20-\x7e]{4,}', iso)]
# Write pools
pool_dir = pathlib.Path("$ROOT/logs/dart/pool")
pool_dir.mkdir(parents=True, exist_ok=True)
# 1. Packages
pkgs = sorted({s for s in strs if s.startswith("package:") or s.startswith("dart:")})
(pool_dir/"packages.log").write_text("\n".join(pkgs)+"\n")
# 2. API/URLs
apis = sorted({s for s in strs if any(k in s for k in ["rest.", "api/", "topup", "snakeengine", "snakeseller", "flagsapi", "apkpure", "discord", "telegram", "https://"])})
(pool_dir/"apis.log").write_text("\n".join(apis)+"\n")
# 3. Snake/license strings
snake = sorted({s for s in strs if any(k in s.lower() for k in ["snake","seller","subscription","license","device","token","login","oauth"]) and len(s)<120})
(pool_dir/"snake-license.log").write_text("\n".join(snake)+"\n")
# 4. Routes (strings starting with / and short)
routes = sorted({s for s in strs if s.startswith("/") and 2<len(s)<40 and not s.startswith("//")})
(pool_dir/"routes.log").write_text("\n".join(routes[:200])+"\n")
# 5. Game controller strings
game = sorted({s for s in strs if "GameButton" in s or "PlaySpeed" in s})
(pool_dir/"game-buttons.log").write_text("\n".join(game)+"\n")
print(f"pools: packages={len(pkgs)} apis={len(apis)} snake={len(snake)} routes={len(routes)} game={len(game)}")
PY

  echo "[collect] 5/9 Manifest risk — per-permission + component export"
  python3 - <<PY
import re, pathlib
xml = pathlib.Path("$ROOT/logs/manifest/AndroidManifest-decoded.xml").read_text(errors="ignore")
# Count exported
exported = len(re.findall(r'android:exported="true"', xml))
# Permissions
perms = re.findall(r'uses-permission android:name="([^"]+)"', xml)
risk = {'high': ['QUERY_ALL_PACKAGES','MANAGE_EXTERNAL_STORAGE','BIND_VPN_SERVICE','CAMERA','RECORD_AUDIO','READ_CONTACTS','SEND_SMS','CALL_PHONE','REQUEST_INSTALL_PACKAGES','PACKAGE_USAGE_STATS','SYSTEM_ALERT_WINDOW'],
        'medium': ['POST_NOTIFICATIONS','FOREGROUND_SERVICE','ACCESS_FINE_LOCATION','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE']}
out = pathlib.Path("$ROOT/logs/manifest/risk/permissions-risk.log")
out.parent.mkdir(parents=True, exist_ok=True)
with open(out, 'w') as f:
    f.write(f"Exported components: {exported}\nTotal permissions: {len(perms)}\n\n")
    for tier in ['high','medium']:
        f.write(f"[{tier}]\n")
        for p in perms:
            short = p.split('.')[-1]
            if any(k in p for k in risk[tier]):
                f.write(f"  {p}\n")
    f.write("\n[all]\n")
    for p in sorted(set(perms)):
        f.write(f"  {p}\n")
print("manifest risk logged")
PY

  echo "[collect] 6/9 APK file tree + size manifest"
  {
    echo "# APK file tree — $(basename "$APK") ($(du -h "$APK" | cut -f1))"
    echo "## File list (unzip -l)"
    unzip -l "$APK" | head -n 200
    echo "## Size by top entry"
    unzip -l "$APK" | awk '{print $1, $4}' | sort -rn | head -n 40
  } > "$ROOT/logs/apk-tree/apk-file-tree.log"

  echo "[collect] 7/9 libengine full disasm — already trimmed to JNI_OnLoad + mytext in logs/ghidra/"
  echo "Full .text disasm is too large for repo; capstone for 4 offsets is committed. Heavy Ghidra headless below."

  echo "[collect] 8/9 Frida scripts — see scripts/frida/ (committed)"
  echo "[collect] 9/9 Ghidra headless — see below"

fi  # end APK-provided branch

# 9/9 Ghidra headless — runs ONLY here (Actions, ubuntu-latest + JDK 21), never Alpine
if [ "${RUN_GHIDRA:-true}" = "true" ] && [ -d "/tmp/ghidra/ghidra_11.3.2_PUBLIC" ]; then
  echo "[collect] Ghidra headless — analyzing SO if present"
  for so in "$TMPDIR/unzipped/lib/arm64-v8a/libengine.so" "$TMPDIR/unzipped/lib/arm64-v8a/libapp.so"; do
    if [ -f "$so" ]; then
      echo " Ghidra: $so"
      python3 "$ROOT/scripts/ghidra/ghidra_headless.py" --ghidra /tmp/ghidra/ghidra_11.3.2_PUBLIC --so "$so" --out "$ROOT/logs/ghidra/headless" || true
    fi
  done
else
  echo "[collect] Ghidra headless skipped (no /tmp/ghidra or RUN_GHIDRA=false) — capstone/objdump logs are committed fallback"
fi

echo "[collect] done — see logs/"
ls -lh "$ROOT/logs/" 2>&1 | head -30 || true
ls -R "$ROOT/logs" 2>&1 | head -80 || true
