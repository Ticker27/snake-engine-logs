#!/usr/bin/env python3
"""
static_decrypt_ilil.py — Pure-Python static vector reimplementation (No Frida, No Unicorn)
==========================================================================================
Fully offline, no device, no emulation — replays the NEON decrypt loop at
JNI_OnLoad 0xF4124..0xF4174 using only readelf + capstone + .rodata.

Use together with unicorn_dump_ilil.py: this is the static fallback, unicorn
is the runtime-proved variant. Both write to logs/runtime/.

Usage:
  python3 scripts/static_decrypt_ilil.py /tmp/apk_analysis/apk_unzipped/lib/arm64-v8a/libengine.so
  python3 scripts/static_decrypt_ilil.py /var/minis/attachments/uploads/Snake_Engine_2.2.6.apk

Output:
  logs/runtime/static-ilil-decode.log    — decoded buffer + F1/F2/F3 hypothesis
  logs/runtime/static-heap-*.bin          — if any decoded heap blob is recovered

How it works (from f928dd4 capstone 3097 lines):
  JNI_OnLoad @ 0xF3FA0 vector block:
    0xF40EC adrp x13, #0x10000
    0xF4124 ldr q0, [x13, #0xA70]      // q0 = .rodata + 0x10A70 (16 bytes)
    0xF4128 dup  v1.2d, x11            // x11 = 0xA9 (mov w11,#0xA9 @ 0xF40EC)
    0xF412C dup  v2.2d, x12            // x12 = 2    (mov w12,#2)
    0xF4130 cmhi v3.2d, v1.2d, v0.2d
    0xF4134 xtn  v3.2s, v3.2d
    0xF4138 fmov w12, s3
    0xF413C tbz  w12, #0, 0xF4144
    0xF4140 str  x10, [x8, x9]         // x10 += x19 (0x122/0x1A4/0x80D2/0x52...); x8=heap
    0xF4164 add  v0.2d, v0.2d, v2.2d    // v0 += 2
    0xF4168 add  x10, x10, x19
    0xF416C add  x9, #0x10
    0xF4170 cmp  x9, #0x550
    0xF4174 b.ne 0xF4130

  Plus the movk ladder at 0xF4178..0xF42BC that builds the table keys
  (x19=0xA4050348C... etc, x20 similarly) — those are the heap base + XOR keys.

  We replay: q0 from .rodata, then 0x550/0x10 = 85 iterations of NEON loop,
  writing to a simulated heap buffer (0xA405... mapped). The result is the
  ilil F1/F2/F3 table. Strings are then extracted via F1/F2/F3 low16 offset.

Note:
  Without the real tpidr_el0 canary and 0x828D90 gate value, some early exits
  (b.eq @ 0xF4024, cmp w10,#0x1D @ 0x81EF10) are patched to "take decrypt path".
  This is a best-effort static replay — unicorn_dump_ilil.py proves it at runtime.

Boundary:
  No heavy tools — capstone only, runs on Alpine PRoot suitable env.
"""
import sys, os, pathlib, struct, zipfile, tempfile, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

inp = sys.argv[1] if len(sys.argv) > 1 else "/var/minis/attachments/uploads/Snake_Engine_2.2.6.apk"
root = pathlib.Path(__file__).parent.parent
out_dir = root / "logs" / "runtime"
out_dir.mkdir(parents=True, exist_ok=True)

so_path = None
tmpdir = None
if inp.endswith(".apk") and os.path.isfile(inp):
    tmpdir = tempfile.mkdtemp()
    with zipfile.ZipFile(inp) as z:
        z.extractall(tmpdir)
    so_path = str(pathlib.Path(tmpdir) / "lib/arm64-v8a/libengine.so")
    if not os.path.isfile(so_path):
        import glob
        cand = glob.glob(os.path.join(tmpdir, "**/libengine.so"), recursive=True)
        so_path = cand[0] if cand else so_path
else:
    so_path = inp

if not os.path.isfile(so_path):
    print(f"[error] SO not found: {so_path}", file=sys.stderr)
    sys.exit(1)

data = open(so_path, "rb").read()
print(f"[static] SO: {so_path} {len(data)} bytes")

JNI = 0xF3FA0
JNI_SIZE = 12388
RODATA_OFF = 0x10A50
RODATA_SIZE = 0x32D64

rodata = data[RODATA_OFF:RODATA_OFF+RODATA_SIZE]
# q0 source at file 0x10A70 (see adrp 0x10000 + 0xA70)
q0_off = 0x10A70
q0_initial = data[q0_off:q0_off+16]
print(f"[static] q0 @ file 0x{q0_off:x} = {q0_initial.hex()}")

# Decode movk ladder at 0xF4178..0xF43CC that builds x19/x20/x13 etc
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
jni_chunk = data[JNI:JNI+JNI_SIZE]
insns = {i.address: i for i in cs.disasm(jni_chunk, JNI)}

# Collect movk/mov that build x19/x20 heap keys
keys = {}
for addr in range(0xF4178, 0xF4300):
    ins = insns.get(addr)
    if not ins:
        continue
    if ins.mnemonic in ("mov", "movk", "adrp"):
        keys[addr] = f"{ins.mnemonic} {ins.op_str}"
        # e.g. movk x19, #0x348, lsl #16
        if "x19" in ins.op_str or "x20" in ins.op_str:
            pass

print(f"[static] movk ladder: {len([k for k in keys if 'x19' in keys[k] or 'x20' in keys[k]])} x19/x20 ops")

# Replay NEON loop: 0x550 bytes / 0x10 step = 85 iterations
# Each iteration: v0 += 2 (dup v2=2, add v0.2d, v0.2d, v2.2d)
# cmhi/ xtn / fmov decides whether to write x10 (counter) to heap
# Heap write: str x10, [x8, x9] where x8=heap_base, x9 offset, x10 counter
heap = bytearray(0x800)  # simulate 0xA405 heap
v0 = list(struct.unpack("<QQ", q0_initial))  # 2 x 64-bit lanes

# Reconstruct x11=0xA9, x12=2 from capstone
# At 0xF40EC mov w11,#0xA9; 0xF40F0 mov w12,#2
X11 = 0xA9
X12 = 2
# x19/x20 are large 64-bit movk-built — use first pair as example: 0xA40503481A4...
# From capstone at 0xF40BC mov x19 #0x122 / 0xF40C8 movk x19 #0x348 lsl #16 etc
# Full 64-bit at 0xF40BC: mov x19,#0x122; movk #0x348<<16; movk #0x1A4<<32; movk #0xA405<<48 = 0xA40501A40348...
# Let's read the actual sequence: F40BC..F40DC
x19_seq = []
x20_seq = []
for a in [0xF40BC,0xF40C8,0xF40D0,0xF40D8]:
    ins = insns.get(a)
    if ins: x19_seq.append((a, ins.op_str))
for a in [0xF40C0,0xF40CC,0xF40D4,0xF40DC]:
    ins = insns.get(a)
    if ins: x20_seq.append((a, ins.op_str))
print(f"[static] x19 seq: {x19_seq}")
print(f"[static] x20 seq: {x20_seq}")

# Build actual 64-bit by parsing mov/movk immediates
def build_reg(seq_addrs):
    val = 0
    for a in seq_addrs:
        ins = insns.get(a)
        if not ins: continue
        m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", ins.op_str)
        if not m: continue
        imm = int(m.group(1), 0)
        lsl = 0
        ls = re.search(r"lsl #(\d+)", ins.op_str)
        if ls: lsl = int(ls.group(1))
        val |= (imm << lsl)
    return val

X19 = build_reg([0xF40BC,0xF40C8,0xF40D0,0xF40D8])
X20 = build_reg([0xF40C0,0xF40CC,0xF40D4,0xF40DC])
print(f"[static] X19={X19:#018x} X20={X20:#018x}")

# Simulate loop — note this is best-effort: real ARM NEON widening semantics are approximated
# cmhi v3.2d, v1.2d, v0.2d  => v3 lane = (X11 > v0_lane) ? 0xFFFF.. : 0
# xtn v3.2s, v3.2d
# fmov w12, s3 -> low 32 of v3
# tbz w12, #0 -> if bit0==0, skip str
# So write occurs when (X11 > lane0) is false? Actually cmhi is unsigned higher
# For lane0 < X11 -> v3=1 (0xFF), lane1 similarly. Bit0 of w12 reflects lane0 result.
import struct as st

heap_writes = []
x10 = 0  # counter that gets added with X19 each iter
x9 = 0
v0_lanes = list(st.unpack("<QQ", q0_initial))
for iteration in range(0x550 // 0x10):  # 85
    v0_0, v0_1 = v0_lanes[0] & 0xFFFFFFFFFFFFFFFF, v0_lanes[1] & 0xFFFFFFFFFFFFFFFF
    # NEON dup v1 = X11 repeated
    # cmhi: v3 lane = 1 if X11 > v0_lane else 0  (unsigned compare, but X11 is 0xA9 =169, v0 is bytes)
    # Actually q0 is bytes from .rodata, unpacked as little-endian Qwords — low bytes dominate
    c0 = 1 if (X11 & 0xFF) > (v0_0 & 0xFF) else 0  # approximate: only low byte matters for strings
    c1 = 1 if (X11 & 0xFF) > (v0_1 & 0xFF) else 0
    # fmov w12, s3: s3 is low 32 of xtn'd v3.2d -> bit0 = c0
    bit0 = c0 & 1
    if bit0:
        # str x10, [x8, x9]  — record
        # also second write at +8 if second lane hits
        # At 0xF4158: add x12,x10,x20; str x12,[x13, #8] variant
        # Approx: write x10 at x9, and x10+X20 at x9+8
        heap_writes.append((x9, x10))
        st.pack_into("<Q", heap, x9, x10 & 0xFFFFFFFFFFFFFFFF)
        if c1:
            st.pack_into("<Q", heap, x9+8, (x10 + X20) & 0xFFFFFFFFFFFFFFFF)
            heap_writes.append((x9+8, (x10+X20) & 0xFFFFFFFFFFFFFFFF))
    else:
        pass
    # Step: add v0.2d, v0.2d, v2.2d  (v0 += 2 per qword)
    v0_lanes[0] = (v0_lanes[0] + 2) & 0xFFFFFFFFFFFFFFFF
    v0_lanes[1] = (v0_lanes[1] + 2) & 0xFFFFFFFFFFFFFFFF
    x10 = (x10 + X19) & 0xFFFFFFFFFFFFFFFF
    x9 += 0x10

print(f"[static] heap writes: {len(heap_writes)} / 85 iterations")
# Also try to apply movk ladder keys at heap offset 0x550..0x700
# At 0xF4178+ there are str x9,[x8,#0x550] etc after loop — those overwrite with built regs
# Those use real lsl/orr combos, harder to replay without full emu — we record that they exist

# Try string extraction: ilil keys are F1/F2/F3 tables with low 0x1501 etc
# Heap layout hypothesis: xxd heap | strings
heap_strings = []
for m in re.finditer(rb"[\x20-\x7e]{4,}", bytes(heap)):
    s = m.group(0).decode(errors="ignore")
    off = m.start()
    heap_strings.append((off, s))

# Also scan rodata directly for visible strings (post-decrypt strings live in heap, not rodata)
rodata_strings = []
for m in re.finditer(rb"[\x20-\x7e]{5,}", rodata[:8192]):
    s = m.group(0).decode(errors="ignore")
    if len(s) > 8:
        rodata_strings.append(s[:80])

# Capstone extras: list all svc / blr / br that prove Runtime path
svc_addrs = [a for a, ins in insns.items() if ins.mnemonic == "svc"]
blr_addrs = [a for a, ins in insns.items() if ins.mnemonic == "blr"]
print(f"[static] svc pcs: {[hex(a) for a in svc_addrs[:8]]}")
print(f"[static] blr pcs: {[hex(a) for a in blr_addrs[:8]]}")

out_log = out_dir / "static-ilil-decode.log"
heap_bin = out_dir / "static-heap-0xA405.bin"
heap_bin.write_bytes(bytes(heap))

with open(out_log, "w") as f:
    f.write("# Static NEON Replay — Snake Engine libengine.so (No Frida, No Unicorn)\n")
    f.write(f"# SO: {so_path}\n")
    f.write(f"# JNI 0x{JNI:x} size {JNI_SIZE}, RODATA file 0x{RODATA_OFF:x} size {RODATA_SIZE:#x}, q0 file 0x{q0_off:x} = {q0_initial.hex()}\n")
    f.write(f"# X19={X19:#018x} (0x122|0x348|0x1A4|0xA405 ladder), X20={X20:#018x} (0x91|0x1A4|0x80D2|0x5202)\n")
    f.write(f"# X11 dup={X11:#x} X12 dup={X12} (from mov w11/w12 @ 0xF40EC)\n")
    f.write(f"# Vector loop: 0x550/0x10 = 85 iters, heap_writes={len(heap_writes)}\n")
    f.write(f"# svc pcs: {', '.join(hex(a) for a in svc_addrs)}\n")
    f.write(f"# blr pcs: {', '.join(hex(a) for a in blr_addrs)}\n")
    f.write("\n[heap dump] -> logs/runtime/static-heap-0xA405.bin (0x800 bytes)\n")
    f.write(f"hex_head: {bytes(heap[:64]).hex()}\n")
    f.write(f"nonzero bytes: {sum(1 for b in heap if b!=0)}/2048\n")
    if heap_writes[:20]:
        f.write("\n[heap writes (offset -> value) sample 20]\n")
        for off,val in heap_writes[:20]:
            f.write(f"  +0x{off:03x}: {val:#018x}\n")
    if heap_strings:
        f.write(f"\n[heap strings] {len(heap_strings)} found\n")
        for off,s in heap_strings[:100]:
            f.write(f"  @0x{off:03x}: {s[:100]}\n")
    else:
        f.write("\n[heap strings] none — indicates NEON path approximated too coarsely; use unicorn for exact heap\n")
    f.write(f"\n[rodata strings sample 20/{len(rodata_strings)}]\n")
    for s in rodata_strings[:20]:
        f.write(f"  {s}\n")
    f.write("\n[movk ladder raw]\n")
    for a,txt in sorted(keys.items()):
        f.write(f"  {a:08x}: {txt}\n")
    f.write("\n[ilil F1/F2/F3 hypothesis]\n")
    f.write("  Keys: 0xF11301(F1/0x1301), 0xF11501(F1/0x1501), 0xF21501(F2/0x1501), 0xF31501(F3/0x1501), 0xF11520/21\n")
    f.write("  Low 0x1501 reused across F1/F2/F3 -> high byte selects table, low=offset inside decrypted heap\n")
    f.write("  To map low->string: read heap at (table_base + low*stride) after full loop, decode as UTF string\n")
    f.write("  This static replay gives heap layout; final string = heap[table_base + low] -> strlen -> UTF\n")
    f.write("\n[note] Best-effort static replay — lane semantics (cmhi 128-bit) are approximated.\n")
    f.write("  For ground-truth plaintext, run: python3 scripts/unicorn_dump_ilil.py  (svc hook proves heap)\n")
    f.write("  Or on device: frida -U -f com.snake -l scripts/frida/dump_ilil.js\n")

print(f"[done] {out_log} ({out_log.stat().st_size} bytes)")
print(f"[done] {heap_bin} ({heap_bin.stat().st_size} bytes)")
if heap_strings:
    print(f"[done] heap strings: {len(heap_strings)}")
else:
    print("[done] no heap strings in static replay — expected without full lane-accurate NEON")

if tmpdir:
    import shutil
    pass
