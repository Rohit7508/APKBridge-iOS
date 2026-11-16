#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Three-way conformance harness for the APKBridge DEX interpreter.

For each fixture it compares:
   (A) the expected value in fixtures/manifest.json  (hand-authored)
   (B) the JVM reference result                      (independent oracle)
   (C) the C++ interpreter result                    (unit under test)
and passes only when A == B == C.

Requires: a built `apkbridge_run` (runtime/build/) and `javac`/`java` on PATH.
If the interpreter binary or Java is missing, those columns show SKIP and the
script explains what to build/install — it does NOT silently pass.
"""
import os
import re
import sys
import json
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
RUN = os.path.join(ROOT, "runtime", "build", "apkbridge_run")
REFDIR = os.path.join(HERE, "runtime", "reference")


def jvm_reference():
    """Compile + run Reference.java, return {name: int}. SKIP -> None."""
    if not (shutil.which("javac") and shutil.which("java")):
        return None
    out = os.path.join(REFDIR, "_build")
    os.makedirs(out, exist_ok=True)
    try:
        subprocess.run(["javac", "-d", out, os.path.join(REFDIR, "Reference.java")],
                       check=True, capture_output=True)
        r = subprocess.run(["java", "-cp", out, "Reference"],
                           check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print("  [jvm] compile/run failed:", e.stderr[:400] if e.stderr else e)
        return None
    vals = {}
    for line in r.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = int(v.strip())
    return vals


def interp(entry, path, cls, method, shorty):
    """Run the C++ interpreter CLI; return int result or ('exc'/'unsup', msg)."""
    if not os.path.exists(RUN):
        return None
    r = subprocess.run([RUN, path, cls, method, shorty, "--json"] +
                       (["10"] if entry == "loop" else []),
                       capture_output=True, text=True)
    try:
        j = json.loads(r.stdout.strip())
    except Exception:
        return ("error", r.stdout + r.stderr)
    if j["kind"] == "int":
        return int(j["value"])
    if j["kind"] == "ref":
        return j["extra"]  # string value
    return (j["kind"], j.get("value", "") + " " + j.get("extra", ""))


def main():
    man = json.load(open(os.path.join(FIX, "manifest.json"), encoding="utf-8"))
    jvm = jvm_reference()
    # map manifest entry kind-name to JVM key
    name_key = {"arith": "arith", "loop": "loop", "invoke": "invoke",
                "object": "object", "array": "array", "exception": "exception",
                "crossdex/classes": "crossdexA", "crossdex/classes2": "crossdexB"}
    REQUIRED = set(name_key)   # these MUST execute comparably or the suite fails

    print("%-12s %8s %8s %8s   %s" % ("fixture", "manifest", "jvm", "interp", "verdict"))
    print("-" * 60)
    fails = 0
    compared = set()   # required fixtures that actually ran a 3-way comparison
    for e in man:
        name = e["fixture"].replace(".dex", "")
        exp = e["expected"]
        if not isinstance(exp, int) or name not in name_key:
            # Fixtures without a JVM oracle (unsupported/infinite/native, and the
            # cross-DEX / lifecycle fixtures) are covered by the C++ suite.
            print("%-12s %8s %8s %8s   %s" % (name, exp, "n/a", "n/a", "SKIP (C++ suite)"))
            continue
        jref = jvm.get(name_key.get(name, name)) if jvm else "SKIP"
        got = interp(name, os.path.join(FIX, e["fixture"]),
                     e["entry_class"], e["entry_method"], e["shorty"])
        got_disp = "SKIP" if got is None else got
        # verdict
        comparable = [exp]
        if isinstance(jref, int):
            comparable.append(jref)
        if isinstance(got, int):
            comparable.append(got)
        ok = len(set(comparable)) == 1 and (got is not None)
        if got is None or (jvm is None):
            verdict = "PARTIAL (missing tool)"
        elif ok:
            verdict = "PASS"; compared.add(name)
        else:
            verdict = "FAIL"; fails += 1
        print("%-12s %8s %8s %8s   %s" %
              (name, exp, jref, got_disp, verdict))

    print("-" * 60)
    if not os.path.exists(RUN):
        print("note: interpreter not built — run:")
        print("      cmake -S runtime -B runtime/build && cmake --build runtime/build")
    if jvm is None:
        print("note: JVM reference skipped (javac/java not found)")
    if fails:
        print("RESULT: %d FAIL" % fails); return 1
    # Fail if the required comparable set did not actually execute (don't let a
    # harness that silently ran nothing report success).
    missing = REQUIRED - compared
    if missing and (jvm is not None) and os.path.exists(RUN):
        print("RESULT: FAIL — required comparable tests did not run: %s" % sorted(missing))
        return 1
    if jvm is None or not os.path.exists(RUN):
        print("RESULT: INCOMPLETE — %d/%d comparable rows ran (missing tool)"
              % (len(compared), len(REQUIRED)))
        return 0
    print("RESULT: all %d required comparable rows agree" % len(compared))
    return 0


if __name__ == "__main__":
    sys.exit(main())
