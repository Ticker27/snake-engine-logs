#!/usr/bin/env python3
"""
unicorn_dump_ilil.py — Hook-log runtime without Frida or device (v2 — working)
==========================================================================
Fixes v1: correct load base (0), proper PLT stub via UC_HOOK_CODE+UC_HOOK_INTR,
correct q0 address (0x104A70 inside .text embedded table, not 0x10A70).

Usage:
  python3 scripts/unicorn_dump_ilil.py [apk_or_so]
  python3 scripts/unicorn_dump_ilil.py /var/minis/attachments/uploads/Snake_Engine_2.2.6.apk

Output:
  logs/runtime/unicorn-ilil-dump.log
  logs/runtime/hook-log.json
  logs/runtime/unicorn-heap-*.bin

No Frida, no device — Unicorn emulation on Alpine PRoot (aarch64) or Actions.
Unicorn is lightweight (pip) — allowed per SOUL.md (Ghidra stays on Actions).
"""
import sys, os, pathlib, struct, json, zipfile, tempfile, re

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
    cand = list((pathlib.Path(tmpdir).rglob("libengine.so")))
    so_path = str(cand[0]) if cand else None
else:
    so_path = inp

if not so_path or not os.path.isfile(so_path):
    print(f"[error] SO not found: {so_path}", file=sys.stderr)
    sys.exit(1)

data = open(so_path, "rb").read()
print(f"[unicorn] SO: {so_path} {len(data)} bytes")

JNI = 0xF3FA0
JNI_SIZE = 12388
MYTEXT = 0x81EEAC

# Log structure
hook_log = {
    "so": so_path,
    "jni_onload_offset": hex(JNI),
    "jni_size": JNI_SIZE,
    "load_base": "0x0 (file_off = VA)",
    "note": "Unicorn emulation of JNI_OnLoad mmap/vector decrypt + ilil heap (No Frida)",
    "events": [],
    "heaps": []
}

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X8, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_W0, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5
    has_unicorn = True
except Exception as e:
    has_unicorn = False
    print(f"[unicorn] not available: {e}")
    hook_log["events"].append({"type": "no_unicorn", "error": str(e)})

if has_unicorn:
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(0x0, 12*1024*1024)
    mu.mem_write(0x0, data[:9000000])

    STACK = 0xA0000000
    mu.mem_map(STACK, 0x20000)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x1F000)

    TPIDR = 0x0FFD0000
    mu.mem_map(TPIDR, 0x1000)
    mu.mem_write(TPIDR + 0x28, struct.pack("<Q", 0xDEADBEEF))

    heap_base = 0xB0000000
    mapped = {}
    # Also map the heap region for q0 source at 0x104A70 — it's inside the already-mapped 0x0..C00000
    # So no extra map needed; q0 is readable as part of data at 0

    def hook_code(uc, addr, size, user):
        # PLT stubs: hijack before PLT executes by jumping to LR
        if addr in (0x81F110, 0x81F120, 0x81AD58, 0x81EFF0):
            w0 = uc.reg_read(UC_ARM64_REG_W0)
            if addr == 0x81F110:
                ret = 4096  # sysconf page size / any value works for mmap length
                uc.reg_write(UC_ARM64_REG_X0, ret)
            elif addr == 0x81F120:
                uc.reg_write(UC_ARM64_REG_X0, 0x12345678)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            lr = uc.reg_read(UC_ARM64_REG_X30)
            uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook_intr(uc, intno, size):
        # All svc #0 land here
        w8 = uc.reg_read(UC_ARM64_REG_X8)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        # PC is next insn, so svc was at PC-4
        pc_svc = uc.reg_read(UC_ARM64_REG_PC) - 4
        if w8 == 0xDE:  # mmap
            length = (x1 + 0xFFF) & ~0xFFF if x1 else 0x2000
            a = heap_base + len(mapped) * 0x4000
            try:
                uc.mem_map(a, length)
            except:
                pass
            uc.reg_write(UC_ARM64_REG_X0, a)
            mapped[a] = length
            hook_log["events"].append({"type": "mmap(svc 0xDE)", "pc": hex(pc_svc), "len": hex(length), "addr": hex(a)})
            print(f"[svc] mmap @ {pc_svc:08x} len {length:#x} -> {a:#x}")
        else:
            hook_log["events"].append({"type": "svc", "w8": hex(w8), "pc": hex(pc_svc), "x0": hex(x0), "x1": hex(x1)})
            uc.reg_write(UC_ARM64_REG_X0, 0)
            print(f"[svc] other w8={w8:#x} @ {pc_svc:08x}")

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_INTR, hook_intr)

    # Emulate JNI_OnLoad up to after the 7 mmap loops + vector decrypt
    # Stop at 0xF4300 (inside movk ladder after vector loop) — far enough to capture all 7 mmaps
    try:
        mu.emu_start(JNI, 0xF4300, timeout=0, count=0)
        hook_log["events"].append({"type": "emu_stop", "pc": hex(mu.reg_read(UC_ARM64_REG_PC)), "mapped": len(mapped)})
        print(f"[emu] stopped at {mu.reg_read(UC_ARM64_REG_PC):08x} mapped={len(mapped)}")
    except Exception as e:
        hook_log["events"].append({"type": "emu_error", "error": str(e), "pc": hex(mu.reg_read(UC_ARM64_REG_PC) if has_unicorn else 0)})
        print(f"[emu] error: {e}")
        # Try to continue reading heaps anyway
        import traceback; traceback.print_exc()

    # Also try to continue emulation a bit more to hit vector decrypt stores
    # The vector loop writes to heap via str x10,[x8,x9] — so heap content depends on that loop running
    # Our hook mapped heaps but the loop's str will write to those heaps — check if nonzero
    for a, sz in list(mapped.items()):
        try:
            blob = bytes(mu.mem_read(a, min(sz, 0x1000)))
            nonzero = sum(1 for b in blob if b != 0)
            head = blob[:64].hex()
            # Also try to extract strings
            strs = []
            for m in re.finditer(rb"[\x20-\x7e]{4,}", blob):
                strs.append(m.group(0).decode(errors="ignore")[:60])
            hook_log["heaps"].append({"addr": hex(a), "size": sz, "nonzero": nonzero, "head": head, "strings_sample": strs[:10]})
            p = out_dir / f"unicorn-heap-{a:08x}.bin"
            p.write_bytes(blob[:sz] if sz <= 0x2000 else blob)
            print(f"[heap] {a:#x} nonzero {nonzero}/{sz} strings {len(strs)} head {head[:80]}")
        except Exception as e:
            print(f"[heap] read err {a:#x}: {e}")
            hook_log["events"].append({"type": "heap_read_err", "addr": hex(a), "error": str(e)})

    # Also dump the live .text area at 0x104A70 to show q0 source
    try:
        q0_live = bytes(mu.mem_read(0x104A70, 64))
        hook_log["q0_live"] = q0_live.hex()
        print(f"[q0] live @ 0x104A70 = {q0_live[:32].hex()}")
    except Exception as e:
        q0_live = data[0x104A70:0x104A70+64]
        hook_log["q0_live"] = q0_live.hex()
        print(f"[q0] file @ 0x104A70 = {q0_live[:32].hex()}")

else:
    print("[unicorn] skipped — pip install unicorn")

# Always also record static q0 from file for comparison
q0_file = data[0x104A70:0x104A70+32].hex() if len(data) > 0x104A70+32 else ""
hook_log["q0_file"] = q0_file

# Mytext gate
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
mytext = data[MYTEXT:MYTEXT+0xF4]
gate = []
for ins in cs.disasm(mytext, MYTEXT):
    if "828" in ins.op_str or "0xd90" in ins.op_str:
        gate.append(f"{ins.address:08x}: {ins.mnemonic} {ins.op_str}")
hook_log["mytext_gate"] = gate

# Write outputs
log_path = out_dir / "unicorn-ilil-dump.log"
json_path = out_dir / "hook-log.json"

with open(log_path, "w") as f:
    f.write("# Unicorn Hook-Log Runtime (No Frida, No Device) — Snake Engine libengine.so\n")
    f.write(f"# SO: {so_path}\n")
    f.write(f"# JNI_OnLoad: 0x{JNI:x} size {JNI_SIZE}, load_base 0x0, q0 file head {q0_file[:64]}\n")
    f.write(f"# Has unicorn: {has_unicorn}, mapped heaps: {len(hook_log.get('heaps',[]))}\n")
    for h in hook_log.get("heaps", []):
        f.write(f"# heap {h['addr']} size {h['size']} nonzero {h['nonzero']} head {h['head'][:80]}\n")
        if h.get("strings_sample"):
            for s in h["strings_sample"][:5]:
                f.write(f"#   str: {s}\n")
    f.write("\n[svc trace]\n")
    for e in hook_log["events"]:
        f.write(f"  {e}\n")
    f.write("\n[mytext gate]\n")
    for g in gate:
        f.write(f"  {g}\n")
    f.write(f"\n[q0] file={q0_file[:64]} live={hook_log.get('q0_live','')[:64]}\n")
    f.write("\n[note] Heap writes come from NEON vector loop at 0xF4124..0xF4170 (cmhi/xtn/fmov/tbz/str).\n")
    f.write("  Each mmap corresponds to one of 7 pages of the encrypted ilil table (see DeepDive §1.4).\n")
    f.write("  For ground-truth plaintext strings, also try static_decrypt_ilil.py or Frida dump_ilil.js.\n")

with open(json_path, "w") as f:
    json.dump(hook_log, f, indent=2)

print(f"[done] {log_path} ({log_path.stat().st_size} bytes)")
print(f"[done] {json_path} ({json_path.stat().st_size} bytes)")
for p in out_dir.glob("unicorn-heap-*.bin"):
    print(f"[done] {p} ({p.stat().st_size} bytes)")
