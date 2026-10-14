#!/usr/bin/env python3
"""
ghidra_headless.py — run Ghidra headless on libengine.so / libapp.so
HEAVY — runs ONLY on GitHub Actions (ubuntu-latest + JDK 21), NEVER Alpine PRoot.

Usage (Actions):
  python3 scripts/ghidra/ghidra_headless.py --ghidra /tmp/ghidra/ghidra_11.3.2_PUBLIC \
    --so /tmp/libengine.so --out logs/ghidra/headless/

Alpine (suitable env): do NOT run this — use scripts/rebuild_readelf_logs.sh (capstone/objdump)
"""
import argparse, pathlib, subprocess, shlex, sys

def run(ghidra_root: pathlib.Path, so: pathlib.Path, out: pathlib.Path):
    out.mkdir(parents=True, exist_ok=True)
    proj_dir = out / "_ghidra_proj"
    proj_dir.mkdir(exist_ok=True)
    proj_name = "snake"
    ghidraRun = ghidra_root / "support" / "analyzeHeadless"
    if not ghidraRun.exists():
        sys.exit(f"ghidraRun not found at {ghidraRun}")

    # Clean previous project if any
    subprocess.run([str(ghidraRun), str(proj_dir), proj_name, "-deleteProject"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = [
        str(ghidraRun), str(proj_dir), proj_name,
        "-import", str(so),
        "-processor", "AARCH64:LE:64:v8",
        "-cspec", "default",
        "-analysisTimeoutPerFile", "180",
        "-scriptPath", str(pathlib.Path(__file__).parent),
        # Optional: export disassembly + decompile via scripts if present
    ]
    print("Running:", " ".join(shlex.quote(c) for c in cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    (out / "ghidra.stdout.log").write_text(r.stdout[-200_000:])
    (out / "ghidra.stderr.log").write_text(r.stderr[-200_000:])
    if r.returncode != 0:
        print(r.stdout[-4000:], file=sys.stderr)
        print(r.stderr[-4000:], file=sys.stderr)
        sys.exit(r.returncode)
    print("Ghidra headless done — check", out)

    # Try to export via Ghidra's Dump: use ghidra's -postScript if available
    # Fallback is capstone logs already in logs/ghidra/

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", required=True, help="Ghidra root (e.g. /tmp/ghidra/ghidra_11.3.2_PUBLIC)")
    ap.add_argument("--so", required=True, help=".so to analyze")
    ap.add_argument("--out", required=True, help="output dir for headless logs")
    args = ap.parse_args()
    run(pathlib.Path(args.ghidra), pathlib.Path(args.so), pathlib.Path(args.out))
