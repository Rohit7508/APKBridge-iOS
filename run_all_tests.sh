#!/usr/bin/env bash
# Build + run every portable test. Fails loudly on any error.
set -e
cd "$(dirname "$0")"
echo "== verify complete public-safe source inventory =="
python3 tests/test_source_inventory.py
echo "== build C++ runtime (needs zlib) =="
cmake -S runtime -B runtime/build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build runtime/build -j >/dev/null
echo "== generate fixtures =="
python3 tests/dexgen/make_fixtures.py >/dev/null
DCR="work/dcr_apk/DCR.apk"
echo "== C++ runtime suite =="
if [ -f "$DCR" ]; then APKBRIDGE_DCR="$PWD/$DCR" ./runtime/build/runtime_tests tests/fixtures
else ./runtime/build/runtime_tests tests/fixtures; fi
echo "== analyzer tests =="
python3 tests/analyzer/test_apk_analyzer.py
echo "== three-way conformance =="
python3 tests/run_conformance.py
