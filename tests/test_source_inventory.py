#!/usr/bin/env python3
"""Fail packaging/CI when a source file required by APKBridge is missing."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
REQUIRED = [
    ".github/workflows/ci.yml",
    ".gitignore",
    "README.md",
    "run_all_tests.sh",
    "analyzer/apk_analyzer.py",
    "runtime/CMakeLists.txt",
    "runtime/include/apkbridge_runtime.h",
    "runtime/include/install.hpp",
    "runtime/include/interp.hpp",
    "runtime/src/bridge.cpp",
    "runtime/src/main.cpp",
    "ios/project.yml",
    "ios/APKBridgeRuntimeBridge/APKBridge-Bridging-Header.h",
    "ios/APKBridge/APKBridgeApp.swift",
    "ios/APKBridge/AppModel.swift",
    "ios/APKBridge/ContentView.swift",
    "ios/APKBridge/RuntimeBridge.swift",
    "tests/analyzer/test_apk_analyzer.py",
    "tests/runtime/runtime_tests.cpp",
    "tests/dexgen/make_fixtures.py",
    "tests/run_conformance.py",
    "tests/fixtures/arith.dex",
    "tests/fixtures/crossdex/classes.dex",
    "tests/fixtures/crossdex/classes2.dex",
]


def main() -> int:
    missing = [name for name in REQUIRED if not (ROOT / name).is_file()]
    forbidden = [
        str(path.relative_to(ROOT))
        for pattern in ("*.apk", "*.aab", "*.p12", "*.mobileprovision", ".env")
        for path in ROOT.rglob(pattern)
        if ".git" not in path.parts and "build" not in path.parts
    ]
    if missing:
        print("FAIL source inventory: missing " + ", ".join(missing))
    if forbidden:
        print("FAIL public-source safety: forbidden files " + ", ".join(forbidden))
    if missing or forbidden:
        return 1
    print("PASS source inventory: %d required files present; no private package/signing files" % len(REQUIRED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
