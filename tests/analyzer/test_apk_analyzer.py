#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyzer tests: byte-level units, untrusted-input safety, and a regression
test against the real DCR.apk.

SKIP semantics: a test may return the sentinel SKIP (DCR not present, etc.).
The runner tallies PASS / FAIL / SKIP separately — a SKIP is never counted
as a PASS. Exit code is non-zero only on real FAILs.

Run:
    python tests/analyzer/test_apk_analyzer.py
    python -m pytest tests/analyzer/test_apk_analyzer.py   (pytest skips via SkipTest)
"""
import os
import io
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "analyzer"))
import apk_analyzer as A  # noqa: E402

DCR = os.environ.get(
    "APKBRIDGE_DCR", os.path.join(ROOT, "work", "dcr_apk", "DCR.apk")
)


class SKIP(Exception):
    """Raised to mark a test skipped (distinct from pass/fail)."""


# --- byte-level unit tests -------------------------------------------------
def test_elf_arm64():
    hdr = b"\x7fELF" + bytes([2, 1]) + b"\x00" * 10 + struct.pack("<HH", 3, 0xB7)
    r = A.parse_elf_header(hdr + b"\x00" * 8)
    assert r["valid"] and r["bits"] == 64 and r["machine"].startswith("AArch64")


def test_elf_arm32():
    hdr = b"\x7fELF" + bytes([1, 1]) + b"\x00" * 10 + struct.pack("<HH", 3, 0x28)
    r = A.parse_elf_header(hdr + b"\x00" * 8)
    assert r["valid"] and r["bits"] == 32 and "ARM" in r["machine"]


def test_elf_rejects_nonelf():
    assert A.parse_elf_header(b"NOTELF__________") == {"valid": False}


def test_dex_header_minimal():
    b = bytearray(112)
    b[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", b, 32, 112)
    struct.pack_into("<I", b, 36, 112)
    struct.pack_into("<I", b, 40, 0x12345678)
    struct.pack_into("<I", b, 88, 4242)
    struct.pack_into("<I", b, 96, 77)
    r = A.parse_dex_header(bytes(b))
    assert r["valid"] and r["method_ids"] == 4242 and r["class_defs"] == 77


# --- NEW: malformed / untrusted input tests --------------------------------
def test_malformed_dex_bad_magic():
    assert A.parse_dex_header(b"PK\x03\x04" + b"\x00" * 200)["valid"] is False

def test_malformed_dex_truncated():
    # 'dex\n' magic but far too short to hold a header -> rejected, no crash
    r = A.parse_dex_header(b"dex\n035\x00" + b"\x00" * 10)
    assert r["valid"] is False

def test_corrupt_zip_random_bytes():
    # Not a ZIP at all -> analyze must report zip_valid False, not raise.
    p = os.path.join(HERE, "_corrupt.bin")
    with open(p, "wb") as f:
        f.write(os.urandom(5000))
    try:
        r = A.analyze(p)
        assert r["zip_valid"] is False
    finally:
        os.remove(p)

def test_zip_bomb_guard():
    # A single entry whose declared size exceeds the per-entry cap must be
    # refused by safe_read rather than decompressed into memory.
    p = os.path.join(HERE, "_bomb.apk")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")  # tiny stub
        z.writestr("big.bin", b"\x00" * (2 * 1024 * 1024))      # 2 MB of zeros
    with open(p, "wb") as f:
        f.write(buf.getvalue())
    try:
        # Lower the cap to force the guard to trigger on 'big.bin'.
        saved = A.MAX_ENTRY_BYTES
        A.MAX_ENTRY_BYTES = 1024
        try:
            A.safe_read(zipfile.ZipFile(p), "big.bin")
            raise AssertionError("safe_read should have refused oversized entry")
        except A.ApkSafetyError:
            pass
        finally:
            A.MAX_ENTRY_BYTES = saved
    finally:
        os.remove(p)

def test_xml_parser_rejects_garbage():
    # Feed non-AXML bytes: parser must raise AXMLParseError, not hang/crash.
    try:
        A.AXML(b"\x00\x01\x02\x03" + os.urandom(64))
        raise AssertionError("expected AXMLParseError")
    except A.AXMLParseError:
        pass

def test_xml_parser_rejects_absurd_stringpool():
    # Valid XML chunk header, string pool claims a huge string_count.
    data = struct.pack("<HHI", A.RES_XML_TYPE, 8, 28)       # xml header
    data += struct.pack("<HHI", A.RES_STRING_POOL_TYPE, 28, 20)
    data += struct.pack("<IIIII", 0x7FFFFFFF, 0, 0, 0, 0)   # absurd count
    try:
        A.AXML(data)
        raise AssertionError("expected AXMLParseError for absurd string_count")
    except A.AXMLParseError:
        pass


# --- regression vs real DCR (SKIP if absent) -------------------------------
def test_dcr_regression():
    if not os.path.exists(DCR):
        raise SKIP("DCR.apk not present at %s" % DCR)
    r = A.analyze(DCR)
    m = r["manifest"]
    assert r["zip_integrity_ok"] and r["entry_count"] == 1991
    assert m["package"] == "com.transsion.im" and m["versionName"] == "V7.9.1"
    assert m["versionCode"] == 109 and m["minSdk"] == 21 and m["targetSdk"] == 29
    assert r["dex"]["count"] == 2 and r["dex"]["total_methods"] == 113300
    assert r["native_libs"]["total_count"] == 56
    assert r["native_libs"]["abis"]["arm64-v8a"]["count"] == 28
    rn = [a for a in r["notable_assets"] if a.endswith((".bundle", ".jsbundle", ".hbc"))]
    assert rn == []
    assert r["safety"]["possible_zip_bomb"] is False


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    p = f = s = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__); p += 1
        except SKIP as e:
            print("SKIP", fn.__name__, "->", e); s += 1
        except AssertionError as e:
            print("FAIL", fn.__name__, "->", e); f += 1
        except Exception as e:  # noqa
            print("ERROR", fn.__name__, "->", repr(e)); f += 1
    print("\n%d passed, %d failed, %d skipped (of %d)" % (p, f, s, len(fns)))
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(_run())
