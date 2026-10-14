import sys, re
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeDex
sid, d, dx = AnalyzeDex("/tmp/live/classes.dex")
print("classes:", len(list(d.get_classes())), "methods:", len(list(d.get_methods())))
pat = re.compile(r"(framework|PackageManager|PackageSetting|UserState|Token|License|helper)", re.I)
cands = sorted({c.get_name() for c in d.get_classes() if pat.search(c.get_name() or "")})
print("\n=== candidate classes:", len(cands))
for c in cands[:80]: print("  ", c)
print("\n=== const-string xrefs for package.conf / packages.list / overrides.txt")
for s in ["package.conf", "packages.list", "overrides.txt"]:
    found = False
    for m in d.get_methods():
        try: code = m.get_code()
        except Exception: code = None
        if code is None: continue
        try: bc = code.get_bc().get_instructions()
        except Exception: continue
        for ins in bc:
            if "const-string" in ins.get_name() and s in str(ins.get_output()):
                print("   %s <- %s %s%s [%s]" % (s, m.get_class_name(), m.get_name(), m.get_descriptor(), ins.get_name()))
                found = True
    if not found: print("   %s <- (none)" % s)
print("\n=== callers of Native.<method>")
for m in d.get_methods():
    cn = m.get_class_name() or ""
    if "com/snake/helper/Native" not in cn: continue
    if m.get_name() not in ("ilil","djp","chl","ic","ac","aior","awl","eio","i","pjowqpxe","update","gcuid","getApplicationInfo"): continue
    print("\n  -- %s->%s%s" % (cn, m.get_name(), m.get_descriptor()))
    try: xr = dx.get_xref_from(m)
    except Exception: xr = []
    n = 0
    for c, meth, off in xr:
        print("     from %s %s%s @0x%x" % (c.get_name(), meth.get_name(), meth.get_descriptor(), off))
        n += 1
        if n > 12: print("     ..."); break
    if n == 0: print("     (no xrefs)")

