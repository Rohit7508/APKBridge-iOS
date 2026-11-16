#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APKBridge :: Module A :: Portable APK Analyzer
================================================
Pure-Python, dependency-free APK inspection. Runs identically on Windows and
Linux (stdlib only). Produces a structured, machine-readable compatibility
report for any APK, without hardcoding anything app-specific.

Capabilities implemented and tested here:
  - ZIP integrity + APK structure validation
  - Binary AndroidManifest.xml (AXML) decoding:
      package name, versionCode, versionName, min/target/compile SDK,
      uses-permission list, application/activity/service/receiver inventory
  - DEX discovery + DEX header parsing (magic, version, counts)
  - Native library enumeration grouped by ABI, with ELF header verification
  - Asset / resource inventory and framework fingerprinting (heuristic)

Design note: every number this tool reports is read from the actual bytes of
the archive. Heuristic inferences (e.g. "looks like React Native") are tagged
as such in the output so they are never confused with verified facts.

Usage:
    python apk_analyzer.py <path-to.apk> [--json out.json] [--quiet]
"""

import sys
import os
import io
import json
import struct
import zipfile
import hashlib
import argparse

# --- untrusted-input safety limits ----------------------------------------
# APKs are untrusted. Every decompression is bounded so a crafted/zip-bomb
# archive cannot exhaust memory. Limits are generous for real apps but finite.
MAX_ENTRY_BYTES = 128 * 1024 * 1024    # cap on any single decompressed entry
MAX_MANIFEST_BYTES = 16 * 1024 * 1024  # AndroidManifest.xml is small in practice
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # cap on sum of declared sizes
MAX_ENTRIES = 200000                   # cap on archive entry count
ZIP_BOMB_RATIO = 300                   # declared-uncompressed / file-size flag


class ApkSafetyError(Exception):
    pass


def safe_read(z, name, cap=None):
    """Read a ZIP entry with a hard decompressed-size cap (reads cap+1 and
    rejects if exceeded) so a zip bomb cannot blow up memory. cap defaults to
    the current MAX_ENTRY_BYTES (read at call time, so limits stay adjustable)."""
    if cap is None:
        cap = MAX_ENTRY_BYTES
    info = z.getinfo(name)
    if info.file_size > cap:
        raise ApkSafetyError("entry %r declared %d bytes exceeds cap %d"
                             % (name, info.file_size, cap))
    with z.open(name) as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ApkSafetyError("entry %r expanded past cap %d" % (name, cap))
    return data

# ---------------------------------------------------------------------------
# AXML (binary AndroidManifest.xml) decoder
# ---------------------------------------------------------------------------
# Chunk type constants (from AOSP ResourceTypes.h)
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Typed value data types
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOL = 0x12


class AXMLParseError(Exception):
    pass


class StringPool:
    """Decodes a RES_STRING_POOL chunk (UTF-8 or UTF-16)."""

    FLAG_UTF8 = 1 << 8

    def __init__(self, data, chunk_off):
        self.strings = []
        self._parse(data, chunk_off)

    def _parse(self, data, off):
        (ctype, header_size, chunk_size) = struct.unpack_from("<HHI", data, off)
        if ctype != RES_STRING_POOL_TYPE:
            raise AXMLParseError("expected string pool, got 0x%04x" % ctype)
        (string_count, style_count, flags, strings_start, styles_start) = \
            struct.unpack_from("<IIIII", data, off + 8)
        # Guard against a crafted pool claiming more strings than could fit.
        if string_count > len(data) // 4:
            raise AXMLParseError("string_count %d implausible for %d bytes"
                                 % (string_count, len(data)))
        is_utf8 = bool(flags & self.FLAG_UTF8)
        offsets = struct.unpack_from("<%dI" % string_count, data, off + 28)
        base = off + strings_start
        for so in offsets:
            p = base + so
            if is_utf8:
                # [u16-len-in-chars][u16-len-in-bytes] (each may be 1 or 2 bytes)
                n, p = self._decode_len8(data, p)       # char count (ignored)
                blen, p = self._decode_len8(data, p)    # byte count
                raw = data[p:p + blen]
                self.strings.append(raw.decode("utf-8", "replace"))
            else:
                n, p = self._decode_len16(data, p)
                raw = data[p:p + n * 2]
                self.strings.append(raw.decode("utf-16-le", "replace"))

    @staticmethod
    def _decode_len8(data, p):
        v = data[p]; p += 1
        if v & 0x80:
            v = ((v & 0x7F) << 8) | data[p]; p += 1
        return v, p

    @staticmethod
    def _decode_len16(data, p):
        v = struct.unpack_from("<H", data, p)[0]; p += 2
        if v & 0x8000:
            hi = v & 0x7FFF
            lo = struct.unpack_from("<H", data, p)[0]; p += 2
            v = (hi << 16) | lo
        return v, p

    def get(self, idx):
        if idx == 0xFFFFFFFF or idx < 0 or idx >= len(self.strings):
            return None
        return self.strings[idx]


class AXML:
    """Minimal AXML -> element tree with attributes. Enough for manifests."""

    ANDROID_NS = "http://schemas.android.com/apk/res/android"

    def __init__(self, data):
        self.data = data
        self.pool = None
        self.events = []  # (kind, name, attrs{})
        self._parse()

    def _parse(self):
        data = self.data
        (ctype, header_size, total) = struct.unpack_from("<HHI", data, 0)
        if ctype != RES_XML_TYPE:
            raise AXMLParseError("not an AXML file (type 0x%04x)" % ctype)
        off = header_size
        end = min(total, len(data))
        while off + 8 <= end:
            (ct, hs, cs) = struct.unpack_from("<HHI", data, off)
            if cs == 0:
                break
            if ct == RES_STRING_POOL_TYPE:
                self.pool = StringPool(data, off)
            elif ct == RES_XML_START_ELEMENT_TYPE:
                self._read_start(data, off)
            elif ct == RES_XML_END_ELEMENT_TYPE:
                (ns_i, name_i) = struct.unpack_from("<II", data, off + 8 + 8)
                self.events.append(("end", self.pool.get(name_i), None))
            off += cs

    def _read_start(self, data, off):
        base = off + 8
        # 2 ints line/comment skipped; ns, name
        (ns_i, name_i) = struct.unpack_from("<II", data, base + 8)
        (attr_start, attr_size, attr_count) = struct.unpack_from("<HHH", data, base + 16)
        name = self.pool.get(name_i)
        attrs = {}
        # attr_start is relative to the start of the attrExt struct, which
        # begins 8 bytes after `base` (after lineNumber + comment).
        ab = base + 8 + attr_start
        for i in range(attr_count):
            a = ab + i * 20
            (a_ns, a_name, a_rawval, a_typedval_size, a_res0, a_type, a_data) = \
                struct.unpack_from("<IIiHBBi", data, a)
            key = self.pool.get(a_name)
            val = self._typed_value(a_type >> 0, a_data, a_rawval)
            attrs[key] = val
        self.events.append(("start", name, attrs))

    def _typed_value(self, vtype, vdata, rawval):
        if vtype == TYPE_STRING:
            s = self.pool.get(rawval & 0xFFFFFFFF) if rawval != -1 else None
            if s is None:
                s = self.pool.get(vdata)
            return s
        if vtype == TYPE_INT_BOOL:
            return bool(vdata)
        if vtype in (TYPE_INT_DEC, TYPE_INT_HEX):
            return vdata
        # Any other type (references, dimensions...) -> keep raw int
        return vdata

    # -- high level extraction -------------------------------------------
    def manifest_info(self):
        info = {
            "package": None, "versionCode": None, "versionName": None,
            "minSdk": None, "targetSdk": None, "compileSdk": None,
            "permissions": [], "activities": [], "services": [],
            "receivers": [], "providers": [], "application_attrs": {},
        }
        for kind, name, attrs in self.events:
            if kind != "start":
                continue
            if name == "manifest":
                info["package"] = attrs.get("package")
                info["versionCode"] = attrs.get("versionCode")
                info["versionName"] = attrs.get("versionName")
                info["compileSdk"] = attrs.get("compileSdkVersion")
            elif name == "uses-sdk":
                info["minSdk"] = attrs.get("minSdkVersion")
                info["targetSdk"] = attrs.get("targetSdkVersion")
            elif name == "uses-permission":
                p = attrs.get("name")
                if p:
                    info["permissions"].append(p)
            elif name == "application":
                info["application_attrs"] = {
                    k: v for k, v in attrs.items()
                    if k in ("label", "theme", "name", "debuggable",
                             "allowBackup", "usesCleartextTraffic",
                             "extractNativeLibs", "requestLegacyExternalStorage")
                }
            elif name == "activity":
                nm = attrs.get("name")
                if nm:
                    info["activities"].append(nm)
            elif name == "service":
                nm = attrs.get("name")
                if nm:
                    info["services"].append(nm)
            elif name == "receiver":
                nm = attrs.get("name")
                if nm:
                    info["receivers"].append(nm)
            elif name == "provider":
                nm = attrs.get("name")
                if nm:
                    info["providers"].append(nm)
        return info


# ---------------------------------------------------------------------------
# DEX header parsing
# ---------------------------------------------------------------------------
def parse_dex_header(blob):
    """Read a .dex header. Returns dict of verified counts, or error."""
    if len(blob) < 112 or blob[:3] != b"dex":
        return {"valid": False, "reason": "bad magic"}
    version = blob[4:7].decode("ascii", "replace")
    (checksum,) = struct.unpack_from("<I", blob, 8)
    (file_size,) = struct.unpack_from("<I", blob, 32)
    (header_size,) = struct.unpack_from("<I", blob, 36)
    (endian,) = struct.unpack_from("<I", blob, 40)
    (string_ids_size,) = struct.unpack_from("<I", blob, 56)
    (type_ids_size,) = struct.unpack_from("<I", blob, 64)
    (proto_ids_size,) = struct.unpack_from("<I", blob, 72)
    (field_ids_size,) = struct.unpack_from("<I", blob, 80)
    (method_ids_size,) = struct.unpack_from("<I", blob, 88)
    (class_defs_size,) = struct.unpack_from("<I", blob, 96)
    return {
        "valid": True,
        "dex_version": version,
        "declared_file_size": file_size,
        "actual_size": len(blob),
        "size_matches": file_size == len(blob),
        "endian_little": endian == 0x12345678,
        "string_ids": string_ids_size,
        "type_ids": type_ids_size,
        "proto_ids": proto_ids_size,
        "field_ids": field_ids_size,
        "method_ids": method_ids_size,
        "class_defs": class_defs_size,
    }


# ---------------------------------------------------------------------------
# ELF header parsing (native .so verification)
# ---------------------------------------------------------------------------
ELF_MACHINE = {
    0x28: "ARM (32-bit, EABI)",
    0xB7: "AArch64 (ARM64)",
    0x03: "x86",
    0x3E: "x86-64",
}


def parse_elf_header(blob):
    if len(blob) < 20 or blob[:4] != b"\x7fELF":
        return {"valid": False}
    ei_class = blob[4]      # 1=32bit 2=64bit
    ei_data = blob[5]       # 1=LE 2=BE
    (e_type,) = struct.unpack_from("<H", blob, 16)
    (e_machine,) = struct.unpack_from("<H", blob, 18)
    return {
        "valid": True,
        "bits": 64 if ei_class == 2 else 32,
        "little_endian": ei_data == 1,
        "machine": ELF_MACHINE.get(e_machine, "0x%02x" % e_machine),
        "is_shared_object": e_type == 3,
    }


# ---------------------------------------------------------------------------
# Framework fingerprinting (HEURISTIC — explicitly tagged in output)
# ---------------------------------------------------------------------------
FRAMEWORK_SIGNS = {
    "React Native": [
        "lib/*/libreactnativejni.so", "lib/*/libreactnative.so",
        "assets/index.android.bundle", "lib/*/libjsc.so",
        "lib/*/libhermes.so",
    ],
    "Flutter": ["lib/*/libflutter.so", "assets/flutter_assets/"],
    "Unity": ["lib/*/libunity.so", "assets/bin/Data/"],
    "Xamarin": ["assets/assemblies/", "lib/*/libmonodroid.so"],
    "Cordova/Ionic": ["assets/www/index.html", "assets/www/cordova.js"],
}


def fingerprint_frameworks(names):
    hits = {}
    joined = "\n".join(names)
    for fw, patterns in FRAMEWORK_SIGNS.items():
        matched = []
        for pat in patterns:
            if "*" in pat:
                pre, post = pat.split("*", 1)
                for n in names:
                    if n.startswith(pre) and n.endswith(post):
                        matched.append(n)
                        break
            else:
                for n in names:
                    if n == pat or n.startswith(pat):
                        matched.append(n)
                        break
        if matched:
            hits[fw] = matched
    return hits


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------
def analyze(apk_path):
    report = {"apk_path": os.path.abspath(apk_path)}
    with open(apk_path, "rb") as f:
        raw = f.read()
    report["file_size_bytes"] = len(raw)
    report["sha256"] = hashlib.sha256(raw).hexdigest()

    if not zipfile.is_zipfile(apk_path):
        report["zip_valid"] = False
        return report
    report["zip_valid"] = True

    z = zipfile.ZipFile(apk_path)
    bad = z.testzip()
    report["zip_integrity_ok"] = bad is None
    report["zip_first_bad_entry"] = bad

    names = z.namelist()
    report["entry_count"] = len(names)

    # --- untrusted-input safety assessment ----------------------------
    declared_total = sum(i.file_size for i in z.infolist())
    ratio = (declared_total / len(raw)) if raw else 0
    oversized = [i.filename for i in z.infolist() if i.file_size > MAX_ENTRY_BYTES]
    report["safety"] = {
        "entry_count_ok": len(names) <= MAX_ENTRIES,
        "declared_uncompressed_total": declared_total,
        "expansion_ratio": round(ratio, 1),
        "possible_zip_bomb": ratio > ZIP_BOMB_RATIO or declared_total > MAX_TOTAL_BYTES,
        "oversized_entries": oversized,
    }
    if len(names) > MAX_ENTRIES:
        report["safety"]["aborted"] = "too many entries"
        return report

    # --- categorise entries -------------------------------------------
    dex_files, so_by_abi, assets, resources, meta = [], {}, [], [], []
    total_uncompressed = 0
    for info in z.infolist():
        total_uncompressed += info.file_size
        n = info.filename
        if n.endswith(".dex"):
            dex_files.append(n)
        elif n.startswith("lib/") and n.endswith(".so"):
            parts = n.split("/")
            if len(parts) >= 3:
                so_by_abi.setdefault(parts[1], []).append(n)
        elif n.startswith("assets/"):
            assets.append(n)
        elif n.startswith("res/"):
            resources.append(n)
        elif n.startswith("META-INF/"):
            meta.append(n)
    report["total_uncompressed_bytes"] = total_uncompressed

    # --- manifest ------------------------------------------------------
    report["manifest"] = {}
    if "AndroidManifest.xml" in names:
        try:
            axml = AXML(safe_read(z, "AndroidManifest.xml", MAX_MANIFEST_BYTES))
            report["manifest"] = axml.manifest_info()
            report["manifest"]["_decoded"] = True
        except Exception as e:  # noqa
            report["manifest"] = {"_decoded": False, "error": repr(e)}
    else:
        report["manifest"] = {"_decoded": False, "error": "no AndroidManifest.xml"}

    # --- dex -----------------------------------------------------------
    report["dex"] = {"count": len(dex_files), "files": []}
    for d in sorted(dex_files):
        blob = safe_read(z, d)
        hdr = parse_dex_header(blob)
        hdr["name"] = d
        report["dex"]["files"].append(hdr)
    report["dex"]["total_methods"] = sum(
        d.get("method_ids", 0) for d in report["dex"]["files"] if d.get("valid"))
    report["dex"]["total_classes"] = sum(
        d.get("class_defs", 0) for d in report["dex"]["files"] if d.get("valid"))

    # --- native libs ---------------------------------------------------
    report["native_libs"] = {"abis": {}, "total_count": 0}
    for abi, libs in sorted(so_by_abi.items()):
        sample_hdr = parse_elf_header(safe_read(z, libs[0])) if libs else {}
        report["native_libs"]["abis"][abi] = {
            "count": len(libs),
            "sample_elf": sample_hdr,
            "libs": sorted(os.path.basename(x) for x in libs),
        }
        report["native_libs"]["total_count"] += len(libs)

    # --- assets / resources -------------------------------------------
    report["assets_count"] = len(assets)
    report["resources_count"] = len(resources)
    report["signing_present"] = any(
        m.endswith((".RSA", ".DSA", ".EC")) for m in meta)
    # notable asset bundles (JS bundles etc.)
    report["notable_assets"] = [
        a for a in assets
        if a.endswith((".bundle", ".js", ".jsbundle", ".hbc"))
        or "bundle" in os.path.basename(a).lower()
    ][:50]

    # --- framework fingerprint (HEURISTIC) ----------------------------
    report["frameworks_heuristic"] = fingerprint_frameworks(names)

    return report


def print_summary(r):
    m = r.get("manifest", {})
    print("=" * 68)
    print("APKBridge APK Analyzer — summary")
    print("=" * 68)
    print("File            : %s" % r["apk_path"])
    print("Size            : %.2f MB" % (r["file_size_bytes"] / 1048576.0))
    print("SHA-256         : %s" % r["sha256"])
    print("ZIP valid/intact: %s / %s" % (r["zip_valid"], r.get("zip_integrity_ok")))
    print("Entries         : %d" % r["entry_count"])
    print("-" * 68)
    print("Package         : %s" % m.get("package"))
    print("versionName     : %s" % m.get("versionName"))
    print("versionCode     : %s" % m.get("versionCode"))
    print("minSdk/targetSdk: %s / %s" % (m.get("minSdk"), m.get("targetSdk")))
    print("Permissions     : %d" % len(m.get("permissions", []) or []))
    print("Activities      : %d" % len(m.get("activities", []) or []))
    print("Services        : %d" % len(m.get("services", []) or []))
    print("-" * 68)
    dx = r.get("dex", {})
    print("DEX files       : %d  (methods=%s  classes=%s)" % (
        dx.get("count"), dx.get("total_methods"), dx.get("total_classes")))
    nl = r.get("native_libs", {})
    print("Native .so total: %d" % nl.get("total_count", 0))
    for abi, d in nl.get("abis", {}).items():
        print("   %-14s %3d libs  [%s]" % (
            abi, d["count"], d["sample_elf"].get("machine", "?")))
    print("Assets / res    : %d / %d" % (r["assets_count"], r["resources_count"]))
    print("APK signed      : %s" % r["signing_present"])
    fw = r.get("frameworks_heuristic", {})
    print("Framework (guess): %s" % (", ".join(fw.keys()) if fw else "none detected"))
    print("=" * 68)


def main():
    ap = argparse.ArgumentParser(description="Portable APK analyzer")
    ap.add_argument("apk")
    ap.add_argument("--json", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    r = analyze(args.apk)
    if not args.quiet:
        print_summary(r)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2, ensure_ascii=False)
        if not args.quiet:
            print("JSON written -> %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
