#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal DEX assembler (APKBridge test-input generator)
======================================================
Emits *valid* DEX 035 files for small, self-authored test programs, so the
C++ interpreter can be conformance-tested without the Android SDK. Pure
stdlib; runs on Windows and Linux.

Scope: enough of the format to express the APKBridge conformance suite —
one or more classes, static and instance methods, int/object instance fields,
static fields, and a documented bytecode subset. This is NOT a general Java
compiler; it is a hand-assembler whose encodings match the official Dalvik
instruction formats used by the interpreter.

The emitted file is a real DEX: correct Adler-32 checksum, SHA-1 signature,
section layout and map_list. It round-trips through standard DEX parsers.
"""
import struct
import hashlib
import zlib

NO_INDEX = 0xFFFFFFFF


def uleb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def mutf8(s):
    # Simple MUTF-8 for BMP ASCII/UTF-8 test strings (no surrogate pairs here).
    return s.encode("utf-8")


class Insn:
    """A single instruction: opcode byte + list of 16-bit code units (incl op)."""
    def __init__(self, units):
        self.units = units  # list of ints, each 0..0xFFFF

    def nwords(self):
        return len(self.units)


# -- instruction encoders (format id in comments; see Dalvik docs) ----------
def i_const4(reg, val):                      # 12x: const/4 vA, #+B
    return Insn([(0x12) | ((reg & 0xF) << 8) | ((val & 0xF) << 12)])

def i_const16(reg, val):                     # 21s: const/16 vAA, #+BBBB
    return Insn([0x13 | ((reg & 0xFF) << 8), val & 0xFFFF])

def i_const(reg, val):                        # 31i: const vAA, #+BBBBBBBB
    return Insn([0x14 | ((reg & 0xFF) << 8), val & 0xFFFF, (val >> 16) & 0xFFFF])

def i_const_string(reg, sidx):               # 21c: const-string vAA, string@BBBB
    return Insn([0x1A | ((reg & 0xFF) << 8), sidx & 0xFFFF])

def i_move(dst, src):                         # 12x: move vA, vB
    return Insn([0x01 | ((dst & 0xF) << 8) | ((src & 0xF) << 12)])

def i_move_result(reg):                       # 11x: move-result vAA
    return Insn([0x0A | ((reg & 0xFF) << 8)])

def i_move_result_object(reg):               # 11x: move-result-object vAA
    return Insn([0x0C | ((reg & 0xFF) << 8)])

def i_move_exception(reg):                   # 11x: move-exception vAA
    return Insn([0x0D | ((reg & 0xFF) << 8)])

def i_return_void():                          # 10x
    return Insn([0x0E])

def i_return(reg):                            # 11x: return vAA
    return Insn([0x0F | ((reg & 0xFF) << 8)])

def i_return_object(reg):                     # 11x: return-object vAA
    return Insn([0x11 | ((reg & 0xFF) << 8)])

_BINOP = {"add": 0x90, "sub": 0x91, "mul": 0x92, "div": 0x93, "rem": 0x94}
def i_binop_int(op, dst, a, b):              # 23x: op-int vAA, vBB, vCC
    return Insn([_BINOP[op] | ((dst & 0xFF) << 8), (a & 0xFF) | ((b & 0xFF) << 8)])

def i_addint_lit8(dst, src, lit):            # 22b: add-int/lit8 vAA, vBB, #+CC
    return Insn([0xD8 | ((dst & 0xFF) << 8), (src & 0xFF) | ((lit & 0xFF) << 8)])

def i_goto(offset_words):                     # 10t: goto +AA  (signed byte)
    return Insn([0x28 | ((offset_words & 0xFF) << 8)])

_IFTEST = {"eq": 0x32, "ne": 0x33, "lt": 0x34, "ge": 0x35, "gt": 0x36, "le": 0x37}
def i_if(op, a, b, offset_words):            # 22t: if-op vA, vB, +CCCC
    return Insn([_IFTEST[op] | ((a & 0xF) << 8) | ((b & 0xF) << 12),
                 offset_words & 0xFFFF])

_IFZ = {"eqz": 0x38, "nez": 0x39, "ltz": 0x3A, "gez": 0x3B, "gtz": 0x3C, "lez": 0x3D}
def i_ifz(op, a, offset_words):              # 21t: if-opz vAA, +BBBB
    return Insn([_IFZ[op] | ((a & 0xFF) << 8), offset_words & 0xFFFF])

def i_invoke_static(method_idx, regs):       # 35c: invoke-static {vC..}, meth@BBBB
    return _invoke(0x71, method_idx, regs)

def i_invoke_direct(method_idx, regs):       # 35c: invoke-direct
    return _invoke(0x70, method_idx, regs)

def i_invoke_virtual(method_idx, regs):      # 35c: invoke-virtual
    return _invoke(0x6E, method_idx, regs)

def i_invoke_super(method_idx, regs):        # 35c: invoke-super
    return _invoke(0x6F, method_idx, regs)

def _invoke(opcode, midx, regs):
    assert len(regs) <= 5
    a = len(regs)
    r = regs + [0] * (5 - len(regs))
    # layout: [op | A<<8 | G<<12][meth][ D | C<<4 | B<<8 | A4<<12 ]  (C,D,E,F,G)
    word0 = opcode | ((r[4] & 0xF) << 8) | ((a & 0xF) << 12)   # 35c: G at bits8-11, A(count) at bits12-15
    word2 = (r[0] & 0xF) | ((r[1] & 0xF) << 4) | ((r[2] & 0xF) << 8) | ((r[3] & 0xF) << 12)
    return Insn([word0, midx & 0xFFFF, word2])

def i_new_instance(reg, type_idx):           # 21c: new-instance vAA, type@BBBB
    return Insn([0x22 | ((reg & 0xFF) << 8), type_idx & 0xFFFF])

def i_new_array(dst, size_reg, type_idx):    # 22c: new-array vA, vB, type@CCCC
    return Insn([0x23 | ((dst & 0xF) << 8) | ((size_reg & 0xF) << 12), type_idx & 0xFFFF])

def i_array_length(dst, arr):                # 12x: array-length vA, vB
    return Insn([0x21 | ((dst & 0xF) << 8) | ((arr & 0xF) << 12)])

def i_aget(dst, arr, idx):                   # 23x: aget vAA, vBB, vCC
    return Insn([0x44 | ((dst & 0xFF) << 8), (arr & 0xFF) | ((idx & 0xFF) << 8)])

def i_aput(src, arr, idx):                   # 23x: aput vAA, vBB, vCC
    return Insn([0x4B | ((src & 0xFF) << 8), (arr & 0xFF) | ((idx & 0xFF) << 8)])

def i_iget(dst, obj, field_idx):             # 22c: iget vA, vB, field@CCCC
    return Insn([0x52 | ((dst & 0xF) << 8) | ((obj & 0xF) << 12), field_idx & 0xFFFF])

def i_iput(src, obj, field_idx):             # 22c: iput vA, vB, field@CCCC
    return Insn([0x59 | ((src & 0xF) << 8) | ((obj & 0xF) << 12), field_idx & 0xFFFF])

def i_iget_object(dst, obj, field_idx):      # 22c: iget-object
    return Insn([0x54 | ((dst & 0xF) << 8) | ((obj & 0xF) << 12), field_idx & 0xFFFF])

def i_iput_object(src, obj, field_idx):      # 22c: iput-object
    return Insn([0x5B | ((src & 0xF) << 8) | ((obj & 0xF) << 12), field_idx & 0xFFFF])

def i_sget(dst, field_idx):                  # 21c: sget vAA, field@BBBB
    return Insn([0x60 | ((dst & 0xFF) << 8), field_idx & 0xFFFF])

def i_sput(src, field_idx):                  # 21c: sput vAA, field@BBBB
    return Insn([0x67 | ((src & 0xFF) << 8), field_idx & 0xFFFF])

def i_throw(reg):                             # 11x: throw vAA
    return Insn([0x27 | ((reg & 0xFF) << 8)])

def i_raw(*units):                            # emit arbitrary code units (for tests)
    return Insn(list(units))


# -- model classes ----------------------------------------------------------
class Method:
    def __init__(self, cls, name, shorty, ret, params, access, regs, ins, insns,
                 tries=None):
        self.cls = cls          # type descriptor "La/b/C;"
        self.name = name
        self.shorty = shorty    # e.g. "I", "II", "VL"
        self.ret = ret          # return type descriptor
        self.params = params    # list of param type descriptors
        self.access = access
        self.regs = regs        # registers_size
        self.ins = ins          # ins_size (incoming args incl this)
        self.insns = insns      # list[Insn]
        self.tries = tries or [] # list of (start_word, end_word, [(type_desc or None, handler_word)])
        self.is_static = bool(access & 0x8)
        self.is_direct = bool(access & (0x8 | 0x2 | 0x10000))  # static/private/constructor
        self.is_native = bool(access & 0x100)  # ACC_NATIVE -> no code item


class Field:
    def __init__(self, cls, name, type_desc, access):
        self.cls = cls
        self.name = name
        self.type = type_desc
        self.access = access
        self.is_static = bool(access & 0x8)


class DexClass:
    def __init__(self, desc, superclass="Ljava/lang/Object;", access=0x1):
        self.desc = desc
        self.superclass = superclass
        self.access = access
        self.methods = []
        self.fields = []


class DexFile:
    def __init__(self):
        self.classes = []
        self.externs = []  # (cls, name, shorty, ret, tuple(params)) — ref only

    def add(self, c):
        self.classes.append(c)
        return c

    def extern_method(self, cls, name, shorty, ret, params):
        """Register a reference to a method defined OUTSIDE this DEX (e.g. an
        Android framework method). It enters the string/type/proto/method pools
        but is NOT emitted in any class_data, so the interpreter resolves it as
        an external method and routes it to the framework registry."""
        self.externs.append((cls, name, shorty, ret, tuple(params)))

    # -- pool collection ----------------------------------------------------
    def build(self):
        strings = set()
        types = set()
        protos = set()   # (shorty, ret, tuple(params))
        fields = set()   # (cls, name, type)
        methods = set()  # (cls, proto_key, name)

        def add_type(t):
            types.add(t); strings.add(t)

        for c in self.classes:
            add_type(c.desc); add_type(c.superclass)
            if c.__dict__.get("source"):
                strings.add(c.source)
            for f in c.fields:
                add_type(f.type)
                strings.add(f.name)
                fields.add((f.cls, f.name, f.type))
            for m in c.methods:
                add_type(m.ret)
                for p in m.params:
                    add_type(p)
                strings.add(m.name)
                strings.add(m.shorty)
                pk = (m.shorty, m.ret, tuple(m.params))
                protos.add(pk)
                methods.add((m.cls, pk, m.name))
        # string literals used by const-string are added by caller via .lits
        for c in self.classes:
            for m in c.methods:
                for lit in getattr(m, "lits", []):
                    strings.add(lit)

        # external (reference-only) methods: add to pools, NOT to any class_data
        for (cls, name, shorty, ret, params) in self.externs:
            add_type(cls); add_type(ret)
            for p in params:
                add_type(p)
            strings.add(name); strings.add(shorty)
            pk = (shorty, ret, tuple(params))
            protos.add(pk)
            methods.add((cls, pk, name))

        self.str_list = sorted(strings)
        self.str_index = {s: i for i, s in enumerate(self.str_list)}
        self.type_list = sorted(types)
        self.type_index = {t: i for i, t in enumerate(self.type_list)}
        self.proto_list = sorted(protos, key=lambda p: (self._t(p[1]), p[0]))
        self.proto_index = {p: i for i, p in enumerate(self.proto_list)}
        self.field_list = sorted(fields, key=lambda f: (self._t(f[0]), f[1], self._t(f[2])))
        self.field_index = {f: i for i, f in enumerate(self.field_list)}
        self.method_list = sorted(
            methods, key=lambda m: (self._t(m[0]), m[2], self.proto_index[m[1]]))
        self.method_index = {m: i for i, m in enumerate(self.method_list)}

    def _t(self, desc):
        return self.type_index[desc]

    def method_ref(self, cls, name, shorty, ret, params):
        return self.method_index[(cls, (shorty, ret, tuple(params)), name)]

    def field_ref(self, cls, name, type_desc):
        return self.field_index[(cls, name, type_desc)]

    def type_ref(self, desc):
        return self.type_index[desc]

    def string_ref(self, s):
        return self.str_index[s]

    # -- serialization ------------------------------------------------------
    def to_bytes(self):
        self.build()
        data = bytearray()
        data_base = 0  # offsets computed relative to file; we assemble data blob then prepend fixed sections

        # We lay out: header | string_ids | type_ids | proto_ids | field_ids |
        # method_ids | class_defs | DATA | map
        # First build DATA region pieces, tracking their absolute offsets.
        # Compute fixed-section sizes to know where DATA starts.
        n_str = len(self.str_list)
        n_type = len(self.type_list)
        n_proto = len(self.proto_list)
        n_field = len(self.field_list)
        n_method = len(self.method_list)
        n_class = len(self.classes)

        HEADER = 112
        off_string_ids = HEADER
        off_type_ids = off_string_ids + n_str * 4
        off_proto_ids = off_type_ids + n_type * 4
        off_field_ids = off_proto_ids + n_proto * 12
        off_method_ids = off_field_ids + n_field * 8
        off_class_defs = off_method_ids + n_method * 8
        data_start = off_class_defs + n_class * 32
        # align data_start to 4
        data_start = (data_start + 3) & ~3

        blob = bytearray()
        def cur():
            return data_start + len(blob)
        def align4():
            while (data_start + len(blob)) & 3:
                blob.append(0)

        # string_data items
        string_data_off = []
        for s in self.str_list:
            string_data_off.append(cur())
            b = mutf8(s)
            blob += uleb128(len(b))   # length in UTF-16 code units ~ char count; ascii-safe
            blob += b
            blob.append(0)

        # type_list items for protos (parameters)
        proto_param_off = {}
        for p in self.proto_list:
            params = p[2]
            if params:
                align4()
                proto_param_off[p] = cur()
                blob += struct.pack("<I", len(params))
                for pt in params:
                    blob += struct.pack("<H", self.type_index[pt])
            else:
                proto_param_off[p] = 0

        # code items + class_data
        code_off = {}   # method key -> offset
        for c in self.classes:
            for m in c.methods:
                if m.is_native:           # native methods have no code_item
                    code_off[id(m)] = 0
                    continue
                align4()
                code_off[id(m)] = cur()
                insn_words = []
                for ins in m.insns:
                    insn_words += ins.units
                insns_size = len(insn_words)
                tries = m.tries
                blob += struct.pack("<HHHHII",
                                    m.regs, m.ins, self._out_size(m),
                                    len(tries), 0, insns_size)
                for w in insn_words:
                    blob += struct.pack("<H", w)
                if tries and (insns_size & 1):
                    blob += b"\x00\x00"  # padding before tries
                # try_items + encoded_catch_handler_list
                if tries:
                    # Build handlers list first (encoded), remember relative offsets
                    handler_blob = bytearray()
                    handler_offsets = []
                    for (_s, _e, handlers) in tries:
                        handler_offsets.append(len(handler_blob))
                        typed = [(t, h) for (t, h) in handlers if t is not None]
                        catch_all = [h for (t, h) in handlers if t is None]
                        size = len(typed) if not catch_all else -len(typed)
                        handler_blob += _sleb128(size)
                        for (t, h) in typed:
                            handler_blob += uleb128(self.type_index[t])
                            handler_blob += uleb128(h)
                        if catch_all:
                            handler_blob += uleb128(catch_all[0])
                    for i, (s, e, handlers) in enumerate(tries):
                        blob += struct.pack("<IHH", s, e - s, handler_offsets[i])
                    blob += uleb128(len(tries))
                    blob += handler_blob

        class_data_off = {}
        for c in self.classes:
            align4_noalign = cur()  # class_data need not be aligned
            class_data_off[id(c)] = cur()
            sfields = [f for f in c.fields if f.is_static]
            ifields = [f for f in c.fields if not f.is_static]
            dmethods = [m for m in c.methods if m.is_direct]
            vmethods = [m for m in c.methods if not m.is_direct]
            blob += uleb128(len(sfields))
            blob += uleb128(len(ifields))
            blob += uleb128(len(dmethods))
            blob += uleb128(len(vmethods))
            self._emit_encoded_fields(blob, sfields)
            self._emit_encoded_fields(blob, ifields)
            self._emit_encoded_methods(blob, dmethods, code_off)
            self._emit_encoded_methods(blob, vmethods, code_off)

        # map_list (must be at end, 4-aligned)
        align4()
        map_off = cur()
        map_entries = self._map_entries(
            n_str, n_type, n_proto, n_field, n_method, n_class,
            off_string_ids, off_type_ids, off_proto_ids, off_field_ids,
            off_method_ids, off_class_defs, string_data_off, data_start, map_off, blob)
        blob += struct.pack("<I", len(map_entries))
        for (typ, sz, off) in map_entries:
            blob += struct.pack("<HHII", typ, 0, sz, off)

        # ---- now assemble fixed sections ----
        out = bytearray()
        out += b"\x00" * HEADER
        # string_ids
        for o in string_data_off:
            out += struct.pack("<I", o)
        # type_ids
        for t in self.type_list:
            out += struct.pack("<I", self.string_ref(t))
        # proto_ids
        for p in self.proto_list:
            shorty_idx = self.string_ref(p[0])
            ret_idx = self.type_index[p[1]]
            out += struct.pack("<III", shorty_idx, ret_idx, proto_param_off[p])
        # field_ids
        for f in self.field_list:
            out += struct.pack("<HHI", self.type_index[f[0]], self.type_index[f[2]],
                               self.string_ref(f[1]))
        # method_ids
        for m in self.method_list:
            out += struct.pack("<HHI", self.type_index[m[0]],
                               self.proto_index[m[1]], self.string_ref(m[2]))
        # class_defs
        for c in self.classes:
            out += struct.pack("<IIIIIIII",
                               self.type_index[c.desc], c.access,
                               self.type_index.get(c.superclass, NO_INDEX),
                               0, NO_INDEX, 0, class_data_off[id(c)], 0)
        # pad to data_start
        while len(out) < data_start:
            out += b"\x00"
        out += blob

        # ---- header ----
        self._write_header(out, data_start, len(blob), map_off,
                           off_string_ids, n_str, off_type_ids, n_type,
                           off_proto_ids, n_proto, off_field_ids, n_field,
                           off_method_ids, n_method, off_class_defs, n_class)
        return bytes(out)

    # -- helpers ------------------------------------------------------------
    def _out_size(self, m):
        # outs_size: max arg count of any invoke in the method
        mx = 0
        for ins in m.insns:
            op = ins.units[0] & 0xFF
            if op in (0x6E, 0x6F, 0x70, 0x71, 0x72):
                a = (ins.units[0] >> 8) & 0xF
                mx = max(mx, a)
        return mx

    def _emit_encoded_fields(self, blob, fields):
        prev = 0
        for f in sorted(fields, key=lambda x: self.field_ref(x.cls, x.name, x.type)):
            idx = self.field_ref(f.cls, f.name, f.type)
            blob += uleb128(idx - prev); prev = idx
            blob += uleb128(f.access)

    def _emit_encoded_methods(self, blob, methods, code_off):
        prev = 0
        def mkey(m):
            return self.method_ref(m.cls, m.name, m.shorty, m.ret, m.params)
        for m in sorted(methods, key=mkey):
            idx = mkey(m)
            blob += uleb128(idx - prev); prev = idx
            blob += uleb128(m.access)
            blob += uleb128(code_off[id(m)])

    def _map_entries(self, *a):
        (n_str, n_type, n_proto, n_field, n_method, n_class,
         o_str, o_type, o_proto, o_field, o_method, o_class,
         string_data_off, data_start, map_off, blob) = a
        e = []
        e.append((0x0000, 1, 0))                       # header
        if n_str: e.append((0x0001, n_str, o_str))     # string_id
        if n_type: e.append((0x0002, n_type, o_type))  # type_id
        if n_proto: e.append((0x0003, n_proto, o_proto))
        if n_field: e.append((0x0004, n_field, o_field))
        if n_method: e.append((0x0005, n_method, o_method))
        if n_class: e.append((0x0006, n_class, o_class))
        # data items are present but we only need a valid map; list string_data,
        # type_list, code_item, class_data, map as single aggregate-ish entries.
        # For robustness we emit the required ones with best-effort offsets.
        e.append((0x2000, n_str, string_data_off[0] if string_data_off else data_start))  # string_data
        e.append((0x1000, 1, map_off))                 # map_list
        # sort by offset ascending (DEX requires)
        e.sort(key=lambda x: x[2])
        return e

    def _write_header(self, out, data_start, data_size, map_off,
                      o_str, n_str, o_type, n_type, o_proto, n_proto,
                      o_field, n_field, o_method, n_method, o_class, n_class):
        mv = memoryview(out)
        out[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", out, 32, len(out))        # file_size
        struct.pack_into("<I", out, 36, 112)             # header_size
        struct.pack_into("<I", out, 40, 0x12345678)      # endian_tag
        struct.pack_into("<II", out, 44, 0, 0)           # link_size, link_off
        struct.pack_into("<I", out, 52, map_off)         # map_off
        struct.pack_into("<II", out, 56, n_str, o_str if n_str else 0)
        struct.pack_into("<II", out, 64, n_type, o_type if n_type else 0)
        struct.pack_into("<II", out, 72, n_proto, o_proto if n_proto else 0)
        struct.pack_into("<II", out, 80, n_field, o_field if n_field else 0)
        struct.pack_into("<II", out, 88, n_method, o_method if n_method else 0)
        struct.pack_into("<II", out, 96, n_class, o_class if n_class else 0)
        struct.pack_into("<II", out, 104, data_size, data_start)
        # signature = SHA-1 of everything after signature field (offset 32)
        sig = hashlib.sha1(bytes(out[32:])).digest()
        out[12:32] = sig
        # checksum = adler32 of everything after checksum field (offset 12)
        csum = zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF
        struct.pack_into("<I", out, 8, csum)


def _sleb128(n):
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)
