#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the APKBridge conformance DEX fixtures + an expectations manifest.

Each fixture is a self-authored DEX exercising part of the interpreter.
The manifest records, per fixture, the entry method and the expected result
(computed by hand AND cross-checked by the JVM reference harness in Java).
"""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dexasm as D  # noqa

OUT = os.path.join(HERE, "..", "fixtures")
os.makedirs(OUT, exist_ok=True)

MANIFEST = []


def emit(name, dex, entry_class, entry_method, shorty, expected, kind, note):
    path = os.path.join(OUT, name + ".dex")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(dex.to_bytes())
    MANIFEST.append({
        "fixture": name + ".dex", "entry_class": entry_class,
        "entry_method": entry_method, "shorty": shorty,
        "expected": expected, "kind": kind, "note": note,
    })
    print("  emitted %-16s (%d bytes)" % (name + ".dex", os.path.getsize(path)))


# ---- 1. arithmetic: (7+5)*3 - 6/2 = 33 ------------------------------------
def build_arith():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LArith;"))
    insns = [
        D.i_const16(0, 7), D.i_const16(1, 5), D.i_binop_int("add", 0, 0, 1),
        D.i_const16(1, 3), D.i_binop_int("mul", 0, 0, 1),
        D.i_const16(1, 6), D.i_const16(2, 2), D.i_binop_int("div", 1, 1, 2),
        D.i_binop_int("sub", 0, 0, 1),
        D.i_return(0),
    ]
    c.methods.append(D.Method("LArith;", "compute", "I", "I", [], 0x9, 3, 0, insns))
    return dx


# ---- 2. loop: sum 1..n via branch + goto ----------------------------------
def build_loop(n=10):
    # static int sumTo(int n): acc=0; i=1; while(i<=n){acc+=i; i++;} return acc
    dx = D.DexFile()
    c = dx.add(D.DexClass("LLoop;"))
    # regs: v0=acc v1=i v2=n(arg)  ins=1 -> arg in last reg (v2)
    insns = [
        D.i_const4(0, 0),            # word 0 : acc=0
        D.i_const4(1, 1),            # word 1 : i=1
        # loop top is word 2:
        D.i_if("gt", 1, 2, 7),       # word 2-3 : if i>n jump +7 -> word 9 (return)
        D.i_binop_int("add", 0, 0, 1),  # word 4-5 : acc+=i
        D.i_addint_lit8(1, 1, 1),    # word 6-7 : i = i+1
        D.i_goto((-6) & 0xFF),       # word 8 : goto -6 -> back to word 2
        D.i_return(0),               # word 9 : return acc
    ]
    c.methods.append(D.Method("LLoop;", "sumTo", "II", "I", ["I"], 0x9, 3, 1, insns))
    return dx


# ---- 3. invoke-static + move-result: add(20,22)=42 ------------------------
def build_invoke():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LMain;"))
    # Declare ALL methods first (empty bodies), build pools, THEN fill bodies,
    # so baked method indices match the final numbering.
    add = D.Method("LMain;", "add", "III", "I", ["I", "I"], 0x9, 2, 2, [])
    main = D.Method("LMain;", "main", "I", "I", [], 0x9, 2, 0, [])
    c.methods += [add, main]
    dx.build()
    add_ref = dx.method_ref("LMain;", "add", "III", "I", ["I", "I"])
    add.insns = [D.i_binop_int("add", 0, 0, 1), D.i_return(0)]
    main.insns = [
        D.i_const16(0, 20), D.i_const16(1, 22),
        D.i_invoke_static(add_ref, [0, 1]),
        D.i_move_result(0), D.i_return(0),
    ]
    return dx


# ---- 4. objects + instance fields: Point.x = 7 ----------------------------
def build_object():
    dx = D.DexFile()
    pt = dx.add(D.DexClass("LPoint;"))
    pt.fields.append(D.Field("LPoint;", "x", "I", 0x1))  # public int x
    init = D.Method("LPoint;", "<init>", "V", "V", [], 0x10001, 1, 1, [])  # minimal ctor
    pt.methods.append(init)
    main = dx.add(D.DexClass("LObjMain;"))
    make = D.Method("LObjMain;", "make", "I", "I", [], 0x9, 2, 0, [])
    main.methods.append(make)
    # all methods/fields declared -> build pools -> bake refs -> fill bodies
    dx.build()
    init_ref = dx.method_ref("LPoint;", "<init>", "V", "V", [])
    x_ref = dx.field_ref("LPoint;", "x", "I")
    pt_type = dx.type_ref("LPoint;")
    init.insns = [D.i_return_void()]
    make.insns = [
        D.i_new_instance(0, pt_type),
        D.i_invoke_direct(init_ref, [0]),
        D.i_const16(1, 7),
        D.i_iput(1, 0, x_ref),
        D.i_const4(1, 0),
        D.i_iget(1, 0, x_ref),
        D.i_return(1),
    ]
    return dx


# ---- 5. arrays: int[3]={10,20,12}; return a[0]+a[1]+a[2]+len = 45 ----------
def build_array():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LArr;"))
    # register "[I" as a type up front via a field, then build the pools
    c.fields.append(D.Field("LArr;", "unused", "[I", 0x8))
    dx.build()
    int_arr = dx.type_ref("[I")
    insns = [
        D.i_const4(0, 3),
        D.i_new_array(1, 0, int_arr),     # v1 = new int[3]
        D.i_const4(2, 0), D.i_const16(3, 10), D.i_aput(3, 1, 2),
        D.i_const4(2, 1), D.i_const16(3, 20), D.i_aput(3, 1, 2),
        D.i_const4(2, 2), D.i_const16(3, 12), D.i_aput(3, 1, 2),
        D.i_const4(0, 0),                 # acc
        D.i_const4(2, 0), D.i_aget(3, 1, 2), D.i_binop_int("add", 0, 0, 3),
        D.i_const4(2, 1), D.i_aget(3, 1, 2), D.i_binop_int("add", 0, 0, 3),
        D.i_const4(2, 2), D.i_aget(3, 1, 2), D.i_binop_int("add", 0, 0, 3),
        D.i_array_length(3, 1), D.i_binop_int("add", 0, 0, 3),
        D.i_return(0),
    ]
    # need [I in types: reference it
    c.methods.append(D.Method("LArr;", "run", "I", "I", [], 0x9, 4, 0, insns))
    return dx


# ---- 6. exceptions: try{ throw }catch{ return 99 } ------------------------
def build_exception():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LExc;"))
    c.fields.append(D.Field("LExc;", "_t", "Ljava/lang/RuntimeException;", 0x8))
    dx.build()
    rte = "Ljava/lang/RuntimeException;"
    init_ref = None  # we won't construct; instead throw a pre-made null-ish object
    # Simpler: new-instance RuntimeException, throw, catch-all -> return 99.
    exc_type = dx.type_ref(rte)
    insns = [
        D.i_new_instance(0, exc_type),   # word 0..1
        D.i_throw(0),                    # word 2
        D.i_const16(0, 1), D.i_return(0),# words 3..5 (not reached)
        D.i_const16(0, 99),              # word 6 (handler)
        D.i_return(0),                   # word 8
    ]
    # try covers words [0,3); catch-all handler at word 6
    tries = [(0, 3, [(None, 6)])]
    c.methods.append(D.Method("LExc;", "run", "I", "I", [], 0x9, 1, 0, insns, tries))
    return dx


# ---- 7. unsupported opcode: const then an unimplemented opcode -------------
def build_unsupported():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LUnsup;"))
    # 0x7b = neg-int (not implemented) -> interpreter must report 'unsupported'
    insns = [D.i_const16(0, 1), D.i_raw(0x007B), D.i_return(0)]
    c.methods.append(D.Method("LUnsup;", "run", "I", "I", [], 0x9, 1, 0, insns))
    return dx


# ---- 8. infinite loop: goto self -> must hit the instruction budget --------
def build_infinite():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LInf;"))
    insns = [D.i_const4(0, 0), D.i_goto(0)]   # goto +0 -> branches to itself
    c.methods.append(D.Method("LInf;", "run", "I", "I", [], 0x9, 1, 0, insns))
    return dx


# ---- 9. Android lifecycle: Application subclass with real framework calls --
def build_lifecycle():
    """LTestApp extends Application. boot() news the app, runs <init> + onCreate;
    onCreate calls super.onCreate, Log.d, getApplicationContext, sets an instance
    field and copies it to a static observable. modeProbe() calls an analysis-only
    method so the two execution modes differ."""
    dx = D.DexFile()
    app = dx.add(D.DexClass("LTestApp;", superclass="Landroid/app/Application;"))
    app.fields.append(D.Field("LTestApp;", "mState", "I", 0x1))      # instance
    app.fields.append(D.Field("LTestApp;", "sObserved", "I", 0x9))   # static
    init = D.Method("LTestApp;", "<init>", "V", "V", [], 0x10001, 1, 1, [])
    onCreate = D.Method("LTestApp;", "onCreate", "V", "V", [], 0x1, 4, 1, [])
    onCreate.lits = ["APKBridge", "onCreate ran"]
    boot = D.Method("LTestApp;", "boot", "I", "I", [], 0x9, 2, 0, [])
    probe = D.Method("LTestApp;", "modeProbe", "I", "I", [], 0x9, 2, 0, [])
    app.methods += [init, onCreate, boot, probe]
    # external framework refs (resolved by the registry, not in this DEX)
    dx.extern_method("Landroid/app/Application;", "<init>", "V", "V", [])
    dx.extern_method("Landroid/app/Application;", "onCreate", "V", "V", [])
    dx.extern_method("Landroid/app/Application;", "getApplicationContext", "L",
                     "Landroid/content/Context;", [])
    dx.extern_method("Landroid/util/Log;", "d", "ILL", "I",
                     ["Ljava/lang/String;", "Ljava/lang/String;"])
    dx.extern_method("Landroid/app/Application;", "registerActivityLifecycleCallbacks",
                     "VL", "V", ["Ljava/lang/Object;"])
    dx.build()
    app_init = dx.method_ref("Landroid/app/Application;", "<init>", "V", "V", [])
    app_oncreate = dx.method_ref("Landroid/app/Application;", "onCreate", "V", "V", [])
    getctx = dx.method_ref("Landroid/app/Application;", "getApplicationContext", "L",
                           "Landroid/content/Context;", [])
    logd = dx.method_ref("Landroid/util/Log;", "d", "ILL", "I",
                         ["Ljava/lang/String;", "Ljava/lang/String;"])
    regcb = dx.method_ref("Landroid/app/Application;", "registerActivityLifecycleCallbacks",
                          "VL", "V", ["Ljava/lang/Object;"])
    this_init = dx.method_ref("LTestApp;", "<init>", "V", "V", [])
    this_oncreate = dx.method_ref("LTestApp;", "onCreate", "V", "V", [])
    tapp = dx.type_ref("LTestApp;")
    mState = dx.field_ref("LTestApp;", "mState", "I")
    sObserved = dx.field_ref("LTestApp;", "sObserved", "I")
    s_tag = dx.string_ref("APKBridge")
    s_msg = dx.string_ref("onCreate ran")

    init.insns = [D.i_invoke_direct(app_init, [0]), D.i_return_void()]
    onCreate.insns = [
        D.i_invoke_super(app_oncreate, [3]),            # super.onCreate()
        D.i_const16(0, 7), D.i_iput(0, 3, mState),      # mState = 7
        D.i_const_string(1, s_tag), D.i_const_string(2, s_msg),
        D.i_invoke_static(logd, [1, 2]),                # Log.d(tag,msg)
        D.i_invoke_virtual(getctx, [3]), D.i_move_result_object(0),  # getApplicationContext()
        D.i_iget(0, 3, mState), D.i_sput(0, sObserved), # sObserved = mState
        D.i_return_void(),
    ]
    boot.insns = [
        D.i_new_instance(0, tapp),
        D.i_invoke_direct(this_init, [0]),
        D.i_invoke_virtual(this_oncreate, [0]),
        D.i_sget(1, sObserved), D.i_return(1),
    ]
    probe.insns = [
        D.i_new_instance(0, tapp),
        D.i_invoke_direct(this_init, [0]),
        D.i_const4(1, 0),                               # null callback
        D.i_invoke_virtual(regcb, [0, 1]),              # analysis-only method
        D.i_const16(1, 5), D.i_return(1),
    ]
    return dx


# ---- 10. native method: must be rejected, never silent-success ------------
def build_native():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LNative;"))
    # static native int nyi() — ACC_STATIC|ACC_NATIVE, no code
    c.methods.append(D.Method("LNative;", "nyi", "I", "I", [], 0x9 | 0x100, 0, 0, []))
    return dx


# ---- 11/12. cross-DEX: LMainB (dexB) calls LLibA.addA (dexA) ---------------
def build_crossdex_a():
    dx = D.DexFile()
    a = dx.add(D.DexClass("LLibA;"))
    add = D.Method("LLibA;", "addA", "II", "I", ["I"], 0x9, 2, 1, [])
    a.methods.append(add)
    dx.build()
    add.insns = [D.i_addint_lit8(0, 1, 100), D.i_return(0)]  # arg(v1)+100
    return dx

def build_crossdex_b():
    dx = D.DexFile()
    b = dx.add(D.DexClass("LMainB;"))
    run = D.Method("LMainB;", "run", "I", "I", [], 0x9, 2, 0, [])
    b.methods.append(run)
    dx.extern_method("LLibA;", "addA", "II", "I", ["I"])   # resolved at load time from dexA
    dx.build()
    addA = dx.method_ref("LLibA;", "addA", "II", "I", ["I"])
    run.insns = [D.i_const16(0, 5), D.i_invoke_static(addA, [0]),
                 D.i_move_result(0), D.i_return(0)]          # addA(5) -> 105
    return dx


# ---- 13. class init: <clinit> must run before first use -------------------
def build_clinit():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LClinit;"))
    c.fields.append(D.Field("LClinit;", "sVal", "I", 0x9))  # static
    clinit = D.Method("LClinit;", "<clinit>", "V", "V", [], 0x10008, 1, 0, [])
    getVal = D.Method("LClinit;", "getVal", "I", "I", [], 0x9, 1, 0, [])
    c.methods += [clinit, getVal]
    dx.build()
    sVal = dx.field_ref("LClinit;", "sVal", "I")
    clinit.insns = [D.i_const16(0, 42), D.i_sput(0, sVal), D.i_return_void()]
    getVal.insns = [D.i_sget(0, sVal), D.i_return(0)]   # 42 iff <clinit> ran
    return dx


# ---- 14. storage + SharedPreferences round-trip ---------------------------
def build_storage():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LStore;", superclass="Landroid/app/Application;"))
    init = D.Method("LStore;", "<init>", "V", "V", [], 0x10001, 1, 1, [])
    boot = D.Method("LStore;", "boot", "I", "I", [], 0x9, 6, 0, [])
    readback = D.Method("LStore;", "readback", "I", "I", [], 0x9, 6, 0, [])
    boot.lits = ["prefs", "k"]; readback.lits = ["prefs", "k"]
    c.methods += [init, boot, readback]
    SP = "Landroid/content/SharedPreferences;"; ED = "Landroid/content/SharedPreferences$Editor;"
    dx.extern_method("Landroid/app/Application;", "<init>", "V", "V", [])
    dx.extern_method("Landroid/app/Application;", "getCacheDir", "L", "Ljava/io/File;", [])
    dx.extern_method("Ljava/io/File;", "mkdirs", "Z", "Z", [])
    dx.extern_method("Landroid/app/Application;", "getSharedPreferences", "LLI", SP,
                     ["Ljava/lang/String;", "I"])
    dx.extern_method(SP, "edit", "L", ED, [])
    dx.extern_method(ED, "putInt", "LLI", ED, ["Ljava/lang/String;", "I"])
    dx.extern_method(ED, "commit", "Z", "Z", [])
    dx.extern_method(SP, "getInt", "ILI", "I", ["Ljava/lang/String;", "I"])
    dx.build()
    appInit = dx.method_ref("Landroid/app/Application;", "<init>", "V", "V", [])
    getCache = dx.method_ref("Landroid/app/Application;", "getCacheDir", "L", "Ljava/io/File;", [])
    mkdirs = dx.method_ref("Ljava/io/File;", "mkdirs", "Z", "Z", [])
    getSP = dx.method_ref("Landroid/app/Application;", "getSharedPreferences", "LLI", SP, ["Ljava/lang/String;", "I"])
    edit = dx.method_ref(SP, "edit", "L", ED, [])
    putInt = dx.method_ref(ED, "putInt", "LLI", ED, ["Ljava/lang/String;", "I"])
    commit = dx.method_ref(ED, "commit", "Z", "Z", [])
    getInt = dx.method_ref(SP, "getInt", "ILI", "I", ["Ljava/lang/String;", "I"])
    tStore = dx.type_ref("LStore;")
    sPrefs = dx.string_ref("prefs"); sKey = dx.string_ref("k")
    init.insns = [D.i_invoke_direct(appInit, [0]), D.i_return_void()]
    boot.insns = [
        D.i_new_instance(0, tStore), D.i_invoke_direct(appInit, [0]),  # (ctor is Application.<init> via super; direct here ok)
        D.i_invoke_virtual(getCache, [0]), D.i_move_result_object(1),
        D.i_invoke_virtual(mkdirs, [1]), D.i_move_result(2),
        D.i_const_string(3, sPrefs), D.i_const4(4, 0),
        D.i_invoke_virtual(getSP, [0, 3, 4]), D.i_move_result_object(1),
        D.i_invoke_virtual(edit, [1]), D.i_move_result_object(2),
        D.i_const_string(3, sKey), D.i_const16(4, 7),
        D.i_invoke_virtual(putInt, [2, 3, 4]), D.i_move_result_object(2),
        D.i_invoke_virtual(commit, [2]), D.i_move_result(5),
        D.i_const4(4, 0),
        D.i_invoke_virtual(getInt, [1, 3, 4]), D.i_move_result(0),
        D.i_return(0),
    ]
    readback.insns = [
        D.i_new_instance(0, tStore), D.i_invoke_direct(appInit, [0]),
        D.i_const_string(3, sPrefs), D.i_const4(4, 0),
        D.i_invoke_virtual(getSP, [0, 3, 4]), D.i_move_result_object(1),
        D.i_const_string(3, sKey), D.i_const4(4, 0),
        D.i_invoke_virtual(getInt, [1, 3, 4]), D.i_move_result(0),
        D.i_return(0),
    ]
    return dx


# ---- 15. recursive <clinit>: must complete (reentry allowed) --------------
def build_clinit_recursive():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LClinitRec;"))
    c.fields.append(D.Field("LClinitRec;", "sV", "I", 0x9))
    clinit = D.Method("LClinitRec;", "<clinit>", "V", "V", [], 0x10008, 1, 0, [])
    helper = D.Method("LClinitRec;", "helper", "I", "I", [], 0x9, 1, 0, [])
    getV = D.Method("LClinitRec;", "getV", "I", "I", [], 0x9, 1, 0, [])
    c.methods += [clinit, helper, getV]
    dx.build()
    sV = dx.field_ref("LClinitRec;", "sV", "I")
    helpRef = dx.method_ref("LClinitRec;", "helper", "I", "I", [])
    # <clinit> calls helper() (re-entrant use of the same class) then stores it
    clinit.insns = [D.i_invoke_static(helpRef, []), D.i_move_result(0), D.i_sput(0, sV), D.i_return_void()]
    helper.insns = [D.i_const16(0, 5), D.i_return(0)]
    getV.insns = [D.i_sget(0, sV), D.i_return(0)]   # 5 if init completed
    return dx


# ---- 16. failed <clinit>: class must become FAILED, never silent success --
def build_clinit_fail():
    dx = D.DexFile()
    c = dx.add(D.DexClass("LClinitFail;"))
    c.fields.append(D.Field("LClinitFail;", "sV", "I", 0x9))
    clinit = D.Method("LClinitFail;", "<clinit>", "V", "V", [], 0x10008, 1, 0, [])
    getV = D.Method("LClinitFail;", "getV", "I", "I", [], 0x9, 1, 0, [])
    c.methods += [clinit, getV]
    dx.build()
    sV = dx.field_ref("LClinitFail;", "sV", "I")
    clinit.insns = [D.i_raw(0x007B), D.i_return_void()]   # neg-int: unsupported -> clinit fails
    getV.insns = [D.i_sget(0, sV), D.i_return(0)]
    return dx


def main():
    print("Generating conformance fixtures:")
    emit("arith", build_arith(), "LArith;", "compute", "I", 33, "int-arith",
         "(7+5)*3 - 6/2")
    emit("loop", build_loop(10), "LLoop;", "sumTo", "II", 55, "control-flow",
         "sum 1..10 (arg n=10)")
    emit("invoke", build_invoke(), "LMain;", "main", "I", 42, "invoke-static",
         "add(20,22)")
    emit("object", build_object(), "LObjMain;", "make", "I", 7, "objects-fields",
         "Point.x set/get")
    emit("array", build_array(), "LArr;", "run", "I", 45, "arrays",
         "sum of int[3]+length")
    emit("exception", build_exception(), "LExc;", "run", "I", 99, "exceptions",
         "throw + catch-all")
    emit("unsupported", build_unsupported(), "LUnsup;", "run", "I", "UNSUPPORTED",
         "unsupported-opcode", "const then check-cast (unimplemented)")
    emit("infinite", build_infinite(), "LInf;", "run", "I", "BUDGET",
         "exec-limit", "goto self -> instruction budget")
    emit("lifecycle", build_lifecycle(), "LTestApp;", "boot", "I", 7, "lifecycle",
         "Application.onCreate via framework registry")
    emit("native", build_native(), "LNative;", "nyi", "I", "UNSUPPORTED", "native",
         "native method must be rejected explicitly")
    # Real two-DEX path: classes.dex (LLibA) + classes2.dex (LMainB) in one dir,
    # so the sibling loader resolves across them exactly like a real APK.
    emit("crossdex/classes", build_crossdex_a(), "LLibA;", "addA", "II", 100, "cross-dex",
         "standalone addA(0)=100 (no arg); library for classes2")
    emit("crossdex/classes2", build_crossdex_b(), "LMainB;", "run", "I", 105, "cross-dex",
         "addA(5)=105 resolved across DEX via sibling classes.dex")
    emit("clinit", build_clinit(), "LClinit;", "getVal", "I", 42, "class-init",
         "<clinit> sets static before first use")
    emit("storage", build_storage(), "LStore;", "boot", "I", 7, "storage",
         "getCacheDir+mkdirs+SharedPreferences round-trip")
    emit("clinit_rec", build_clinit_recursive(), "LClinitRec;", "getV", "I", 5, "class-init",
         "recursive <clinit> completes (reentry)")
    emit("clinit_fail", build_clinit_fail(), "LClinitFail;", "getV", "I", "UNSUPPORTED", "class-init",
         "failed <clinit> -> class FAILED, propagated")
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(MANIFEST, f, indent=2)
    print("manifest.json written with %d fixtures" % len(MANIFEST))


if __name__ == "__main__":
    main()
