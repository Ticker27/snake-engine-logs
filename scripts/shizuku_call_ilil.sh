#!/bin/bash
# shizuku_call_ilil.sh — Live dump ilil/djp table via Shizuku app_process (No Frida, No debuggable)
#
# Why this works while com.snake is running:
#   libengine.so already did JNI_OnLoad (7 mmap + NEON decrypt @ 0xF3FA0 + q0 @ 0x104A70)
#   So Native.ilil(int) table is live in process. We spawn a tiny APK-classpath child
#   via `app_process /system/bin --nice-name=snake-ilil` with base.apk on CLASSPATH,
#   which loads libengine.so again and calls ilil/djp directly.
#   Shizuku (uid=0 root, KSU) runs this as shell/root, not as app user — no debuggable needed.
#
# Usage (this sandbox, Shizuku READY uid=0):
#   bash scripts/shizuku_call_ilil.sh
#   # or override APK: APK=/data/app/.../base.apk bash scripts/shizuku_call_ilil.sh
#
# Output:
#   logs/runtime/shizuku-ilil-live.log   — stdout from device
#   logs/runtime/shizuku-ilil-live.json  — extracted strings
#
# Requires on device: /system/bin/app_process64 (exists: sdk 37), /data/app/.../base.apk
# Requires on host: javac 17 (available), shizuku (READY)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APK_DEVICE="/data/app/~~a0wmsQ5noq8Ui7wejPnOCg==/com.snake-3MlU-xL0AJCdJaYulx3x9Q==/base.apk"
APK_HOST="/var/minis/attachments/uploads/Snake_Engine_2.2.6.apk"
OUT_DIR="$ROOT/logs/runtime"
OUT_LOG="$OUT_DIR/shizuku-ilil-live.log"
OUT_JSON="$OUT_DIR/shizuku-ilil-live.json"
TMP="/tmp/shizuku-ilil"

# --- 0. check shizuku READY ---
if ! android-shizuku-cli service ping >/dev/null 2>&1; then
  echo "[error] Shizuku not READY" >&2
  exit 1
fi

# --- 1. pull APK to host for classpath build (if not already) ---
mkdir -p "$TMP" "$OUT_DIR"
if [ ! -f "/tmp/base.apk" ]; then
  echo "[pull] base.apk from device via shizuku"
  android-shizuku-cli exec "cat $APK_DEVICE" > /tmp/base.apk 2>/dev/null || cp "$APK_HOST" /tmp/base.apk || true
  ls -lh /tmp/base.apk 2>&1 | head -1
fi
APK_PULL="/tmp/base.apk"
if [ ! -f "$APK_PULL" ]; then APK_PULL="$APK_HOST"; fi
# Extract libengine.so path for native load
unzip -l "$APK_PULL" 2>&1 | grep libengine | head -1 || true

# --- 2. write Java caller (loads via app_process with base.apk on classpath) ---
# We use --classpath semantics of app_process: CLASSPATH env + app_process /system/bin <class>
cat > "$TMP/IlilDump.java" <<'JAVA'
import dalvik.system.PathClassLoader;
import java.lang.reflect.Method;

public class IlilDump {
    public static void main(String[] args) throws Exception {
        String apk = args.length > 0 ? args[0] : "/data/app/~~a0wmsQ5noq8Ui7wejPnOCg==/com.snake-3MlU-xL0AJCdJaYulx3x9Q==/base.apk";
        String libDir = "/data/app/~~a0wmsQ5noq8Ui7wejPnOCg==/com.snake-3MlU-xL0AJCdJaYulx3x9Q==/lib/arm64";
        // Some devices use lib/arm64, some use split. Try to discover.
        java.io.File f = new java.io.File(apk);
        System.out.println("[shizuku-ilil] apk=" + apk + " exists=" + f.exists() + " size=" + f.length());
        System.out.println("[shizuku-ilil] libDir=" + libDir);

        // Load DEX via PathClassLoader (needs apk)
        ClassLoader parent = ClassLoader.getSystemClassLoader();
        PathClassLoader pcl = new PathClassLoader(apk, libDir, parent);

        // Pre-load native library from apk's lib dir if needed
        try {
            // Try to load via System.loadLibrary with libDir already on native path
            // Set java.library.path via reflection hack not needed — PathClassLoader handles it
            System.out.println("[shizuku-ilil] loading com.snake.helper.Native via PathClassLoader");
        } catch (Exception e) { e.printStackTrace(); }

        Class<?> Native = null;
        try {
            Native = pcl.loadClass("com.snake.helper.Native");
            System.out.println("[shizuku-ilil] Native class=" + Native + " loader=" + Native.getClassLoader());
        } catch (Throwable t) {
            System.out.println("[shizuku-ilil] load Native failed: " + t);
            t.printStackTrace();
            // Fallback: list classes in apk via DexFile
            try {
                dalvik.system.DexFile df = new dalvik.system.DexFile(apk);
                int c=0;
                for (java.util.Enumeration<String> e=df.entries(); e.hasMoreElements() && c<20; c++) {
                    System.out.println("  dex: " + e.nextElement());
                }
                // Also try vx
                for (java.util.Enumeration<String> e2=df.entries(); e2.hasMoreElements();) {
                    String n=e2.nextElement();
                    if (n.contains("androidx.appcompat.view.menu.vx") || n.contains("com.snake.helper.Native")) {
                        System.out.println("  candidate: " + n);
                    }
                }
            } catch (Throwable tt) { tt.printStackTrace(); }
            System.exit(2);
        }

        // Dump methods
        System.out.println("[shizuku-ilil] Native methods:");
        for (Method m : Native.getDeclaredMethods()) {
            System.out.println("  " + m);
        }

        // Call ilil for known keys (F1/F2/F3) + brute tiny range
        int[] probes = {15799041, 15799553, 15865089, 15930625, 15799584, 15799585, 0, 1, 61, 2, 3, 4, 5, 100, 1000};
        Method ilil = null;
        Method djp = null;
        try { ilil = Native.getDeclaredMethod("ilil", int.class); ilil.setAccessible(true); } catch (Throwable t) { System.out.println("no ilil(int): " + t); }
        try { djp = Native.getDeclaredMethod("djp", int.class); djp.setAccessible(true); } catch (Throwable t) { System.out.println("no djp(int): " + t); }

        java.util.LinkedHashMap<String,String> out = new java.util.LinkedHashMap<>();
        if (ilil != null) {
            for (int k : probes) {
                try {
                    Object r = ilil.invoke(null, k);
                    String s = String.valueOf(r);
                    String esc = s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n");
                    System.out.println("[ilil] " + k + " 0x" + Integer.toHexString(k) + " => \"" + esc + "\" (" + (r==null?0:s.length()) + ")");
                    out.put("ilil:" + k, s);
                } catch (Throwable t) {
                    System.out.println("[ilil] " + k + " ERROR: " + t.getCause());
                }
            }
            // Brute small window around known constants to find string table density
            System.out.println("[shizuku-ilil] brute 0xF11300..0xF11310 + 0xF11500..0xF11530 (quiet)");
            for (int base : new int[]{0xF11300, 0xF11500, 0xF21500, 0xF31500}) {
                for (int delta=0; delta<0x30; delta++) {
                    int k = base + delta;
                    boolean isProbe=false;
                    for(int p:probes) if(p==k) isProbe=true;
                    if(isProbe) continue;
                    try {
                        Object r = ilil.invoke(null, k);
                        String s = String.valueOf(r);
                        if (s!=null && !s.equals("null") && s.length()>=2 && s.length()<80) {
                            System.out.println("  [brute] " + k + " 0x" + Integer.toHexString(k) + " => \"" + s + "\"");
                        }
                    } catch (Throwable t) { /* ignore */ }
                }
            }
        }
        if (djp != null) {
            for (int k : new int[]{0,1,2,3,4,5,10}) {
                try {
                    Object r = djp.invoke(null, k);
                    byte[] b = (byte[])r;
                    String hx = b==null?"<null>":(b.length + "B " + bytesToHex(b, 64));
                    System.out.println("[djp] " + k + " => " + hx);
                    if (b!=null && b.length>0 && b.length<200) {
                        try { System.out.println("  utf: " + new String(b, "UTF-8").substring(0, Math.min(120, new String(b,"UTF-8").length()))); } catch (Throwable tt) {}
                    }
                } catch (Throwable t) { System.out.println("[djp] " + k + " ERROR: " + t.getCause()); }
            }
        }
        // Also try to call vx bridge reflectively to show decoded class name
        try {
            Class<?> vx = pcl.loadClass("androidx.appcompat.view.menu.vx");
            System.out.println("[shizuku-ilil] vx class=" + vx);
            for (Method m : vx.getDeclaredMethods()) System.out.println("  vx." + m.getName() + m);
        } catch (Throwable t) { System.out.println("[shizuku-ilil] vx not found: " + t); }

        System.out.println("[shizuku-ilil] done");
    }
    static String bytesToHex(byte[] b, int max) {
        StringBuilder sb=new StringBuilder();
        for(int i=0;i<Math.min(b.length,max);i++) { sb.append(String.format("%02x", b[i]&0xFF)); if(i%16==15) sb.append(" "); }
        if(b.length>max) sb.append("...");
        return sb.toString();
    }
}
JAVA

echo "[compile] javac IlilDump.java"
javac -cp /tmp/base.apk 2>&1 | head -1 || true
javac -d "$TMP" "$TMP/IlilDump.java" 2>&1 | head -n 40
echo "[compile] dex"
# Compile to dex: use d8 (Android SDK) or dx
if command -v d8 >/dev/null 2>&1; then
  d8 --output "$TMP" "$TMP/IlilDump.class" 2>&1 | tail -n 20
elif command -v dx >/dev/null 2>&1; then
  dx --dex --output="$TMP/classes.dex" "$TMP/IlilDump.class" 2>&1 | tail -n 20
else
  # Fallback: use android's dex2oat? Try ecj + manual
  echo "[warn] d8/dx not found — will push class file and run via dalvikvm directly"
fi
ls -lh "$TMP" 2>&1 | head -n 30

# --- 3. push to device and run via app_process ---
echo "[push] to /data/local/tmp"
android-shizuku-cli exec "mkdir -p /data/local/tmp/shizuku-ilil 2>&1 | head" >/dev/null 2>&1 || true
# Push the dex/class via shizuku file push if available, else via exec cat
# We have the host files in /tmp/shizuku-ilil — push via android-shizuku-cli file push or exec+base64
if android-shizuku-cli file push --help 2>&1 | grep -q push 2>&1; then
  echo "[push] via file push"
  android-shizuku-cli file push "$TMP/IlilDump.class" /data/local/tmp/shizuku-ilil/IlilDump.class 2>&1 | tail -n 20 || true
  [ -f "$TMP/classes.dex" ] && android-shizuku-cli file push "$TMP/classes.dex" /data/local/tmp/shizuku-ilil/classes.dex 2>&1 | tail -n 20 || true
else
  echo "[push] via exec base64"
  # Fallback: encode and write
  for f in IlilDump.class classes.dex; do
    [ -f "$TMP/$f" ] || continue
    b64=$(base64 -w 0 "$TMP/$f" 2>&1 | head -c 2000000)
    android-shizuku-cli exec "base64 -d > /data/local/tmp/shizuku-ilil/$f <<'B64'
$b64
B64
ls -lh /data/local/tmp/shizuku-ilil/$f 2>&1 | head -1" 2>&1 | tail -n 20
  done
fi
android-shizuku-cli exec "ls -lh /data/local/tmp/shizuku-ilil/ 2>&1 | head -n 30" 2>&1 | tail -n 30

# --- 4. run ---
echo "[run] app_process via shizuku (shell user, CLASSPATH=$APK_DEVICE:/data/local/tmp/shizuku-ilil/classes.dex)"
# app_process needs CLASSPATH to include base.apk + our dex, and LD_LIBRARY_PATH for libengine
RUN_CMD="CLASSPATH=$APK_DEVICE:/data/local/tmp/shizuku-ilil/classes.dex app_process /system/bin --nice-name=snake-ilil IlilDump $APK_DEVICE 2>&1"
echo "  $RUN_CMD"
android-shizuku-cli exec "$RUN_CMD" 2>&1 | tee /tmp/shizuku-ilil-raw.log | head -n 200
# Also capture combined output
android-shizuku-cli exec "$RUN_CMD" 2>&1 > "$OUT_LOG" || true
cat "$OUT_LOG" 2>&1 | head -n 300 | tail -n 200

# --- 5. extract json ---
python3 - <<PY 2>&1 | head -n 80
import pathlib, re, json
log=pathlib.Path("$OUT_LOG")
text=log.read_text(errors="ignore") if log.exists() else ""
out={}
for line in text.splitlines():
    m=re.match(r'\[ilil\] (\d+) 0x([0-9a-fA-F]+) => "(.*)" \((\d+)\)', line)
    if m:
        k=int(m.group(1)); hexk=m.group(2); val=m.group(3); length=m.group(4)
        out[f"ilil:{k}:0x{hexk}"]=val
    m2=re.match(r'\[djp\] (\d+) =>', line)
    if m2:
        out[f"djp:{m2.group(1)}"]=line.split("=>")[1].strip()[:200] if "=>" in line else line
    m3=re.match(r'\s+\[brute\] (\d+) 0x([0-9a-fA-F]+) => "(.*)"', line)
    if m3:
        k=int(m3.group(1)); hexk=m3.group(2); val=m3.group(3)
        out[f"brute:{k}:0x{hexk}"]=val
# also capture vx
data=pathlib.Path("$OUT_JSON")
data.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"extracted {len(out)} entries -> {data}")
for k,v in list(out.items())[:12]:
    print(f"  {k} => {v[:80]}")
PY
ls -lh "$OUT_LOG" "$OUT_JSON" 2>&1 | head -n 20
echo "[done] shizuku_call_ilil.sh — logs at $OUT_LOG and $OUT_JSON"
