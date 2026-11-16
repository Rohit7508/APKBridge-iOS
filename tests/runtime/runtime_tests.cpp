// APKBridge runtime :: C++ test suite (PASS / FAIL / SKIP reported separately).
// Covers: conformance fixtures, unsupported-opcode + execution-limit detection,
// malformed/truncated DEX handling, ZIP safety, and (when APKBRIDGE_DCR points
// at the real APK) multi-DEX parsing + a manifest regression.
//
// Fixtures are cross-checked independently by the JVM harness
// (tests/run_conformance.py). A SKIP never counts as a PASS.
#include "dex.hpp"
#include "interp.hpp"
#include "zip.hpp"
#include "axml.hpp"
#include "apkbridge_runtime.h"
#include "install.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <filesystem>

using namespace apkbridge;

static int pass = 0, fail = 0, skip = 0;
static std::string FDIR;

static void PASS(const std::string& n, const std::string& d="") { std::cout<<"PASS "<<n<<(d.empty()?"":" -> "+d)<<"\n"; ++pass; }
static void FAIL(const std::string& n, const std::string& d) { std::cout<<"FAIL "<<n<<" -> "<<d<<"\n"; ++fail; }
static void SKIP(const std::string& n, const std::string& d) { std::cout<<"SKIP "<<n<<" -> "<<d<<"\n"; ++skip; }

static std::string fx(const std::string& n){ return FDIR + "/" + n; }

static void expectInt(const std::string& file, const std::string& cls,
                      const std::string& m, const std::string& shorty,
                      std::vector<int32_t> args, int32_t want) {
    try {
        Runtime rt; rt.addDexPath(fx(file));
        Interpreter vm(rt);
        RunResult r = vm.run(cls, m, shorty, args);
        if (r.kind == RunResult::INT && r.i == want) PASS(file, std::to_string(r.i));
        else FAIL(file, "want " + std::to_string(want) + " got kind=" + std::to_string(r.kind) +
                        " i=" + std::to_string(r.i) + " " + r.message);
    } catch (const std::exception& e) { FAIL(file, e.what()); }
}

static void expectKind(const std::string& file, const std::string& cls,
                       const std::string& m, const std::string& shorty,
                       RunResult::Kind wantKind, const std::string& msgContains) {
    try {
        Runtime rt; rt.addDexPath(fx(file));
        Interpreter vm(rt);
        RunResult r = vm.run(cls, m, shorty, {});
        if (r.kind == wantKind && r.message.find(msgContains) != std::string::npos)
            PASS(file, r.message);
        else FAIL(file, "want kind=" + std::to_string(wantKind) + " msg~'" + msgContains +
                        "' got kind=" + std::to_string(r.kind) + " msg='" + r.message + "'");
    } catch (const std::exception& e) { FAIL(file, e.what()); }
}

static void malformedDexTests() {
    // bad magic
    try { DexFile d(std::vector<uint8_t>(200, 0x41)); FAIL("malformed_bad_magic","parsed bad magic"); }
    catch (const DexError&) { PASS("malformed_bad_magic"); }
    catch (const std::exception& e) { FAIL("malformed_bad_magic", e.what()); }
    // truncated (valid magic, too short for header)
    try { std::vector<uint8_t> b = {'d','e','x','\n','0','3','5',0,1,2,3};
          DexFile d(b); FAIL("malformed_truncated","parsed truncated"); }
    catch (const DexError&) { PASS("malformed_truncated"); }
    catch (const std::exception& e) { FAIL("malformed_truncated", e.what()); }
    // declared counts point out of bounds
    try { std::vector<uint8_t> b(112, 0); b[0]='d';b[1]='e';b[2]='x';b[3]='\n';
          b[4]='0';b[5]='3';b[6]='5';b[7]=0;
          // string_ids_size huge at offset 56, offset 60 points past EOF
          *reinterpret_cast<uint32_t*>(&b[56]) = 0xFFFFFF; *reinterpret_cast<uint32_t*>(&b[60]) = 100000;
          DexFile d(b); FAIL("malformed_oob_counts","parsed oob counts"); }
    catch (const std::exception&) { PASS("malformed_oob_counts"); }
}

static void zipSafetyTests() {
    // sanitizer rejects traversal/absolute; accepts normal
    if (ZipArchive::sanitizeRelPath("../x").empty() &&
        ZipArchive::sanitizeRelPath("/etc/passwd").empty() &&
        ZipArchive::sanitizeRelPath("a/../../b").empty() &&
        ZipArchive::sanitizeRelPath("C:\\x").empty() &&
        ZipArchive::sanitizeRelPath("ok/f.dex") == "ok/f.dex")
        PASS("zip_path_traversal_guard");
    else FAIL("zip_path_traversal_guard", "sanitizer wrong");

    // malformed/oversized ZIP inputs (independent of DCR)
    try { ZipArchive z(std::vector<uint8_t>(100, 0x41)); (void)z; FAIL("zip_garbage_rejected","parsed garbage"); }
    catch (const ZipError&) { PASS("zip_garbage_rejected"); }
    catch (const std::exception& e) { FAIL("zip_garbage_rejected", e.what()); }
    try { ZipLimits lim; lim.maxCompressedBytes = 512;
          ZipArchive z(std::vector<uint8_t>(2048, 0), lim); (void)z; FAIL("zip_oversize_rejected","accepted oversize"); }
    catch (const ZipError&) { PASS("zip_oversize_rejected"); }
    catch (const std::exception& e) { FAIL("zip_oversize_rejected", e.what()); }

    // maxTotalBytes: enforced cumulatively across reads (gated on DCR apk)
    const char* apk = std::getenv("APKBRIDGE_DCR");
    if (!apk) { SKIP("zip_max_total_bytes", "set APKBRIDGE_DCR to run"); return; }
    try {
        ZipLimits lim; lim.maxTotalBytes = 1 * 1024 * 1024; // 1 MB cumulative cap
        ZipArchive z = ZipArchive::fromPath(apk, lim);
        bool threw = false;                      // classes.dex is >1MB
        try { z.read("classes.dex"); } catch (const ZipError&) { threw = true; }
        threw ? PASS("zip_max_total_bytes", "cumulative cap enforced")
              : FAIL("zip_max_total_bytes", "cap not enforced");
    } catch (const std::exception& e) { FAIL("zip_max_total_bytes", e.what()); }
}

static void dcrTests() {
    const char* apk = std::getenv("APKBRIDGE_DCR");
    if (!apk) { SKIP("dcr_manifest_regression", "set APKBRIDGE_DCR=<DCR.apk> to run");
                SKIP("dcr_multidex_parse", "set APKBRIDGE_DCR=<DCR.apk> to run"); return; }
    try {
        ZipArchive zip = ZipArchive::fromPath(apk);
        Axml ax(zip.read("AndroidManifest.xml"));
        const auto& mi = ax.info();
        if (mi.package == "com.transsion.im" && mi.versionName == "V7.9.1" &&
            mi.versionCode == 109 && mi.permissions.size() == 48)
            PASS("dcr_manifest_regression", mi.package + " " + mi.versionName);
        else FAIL("dcr_manifest_regression", "pkg=" + mi.package + " ver=" + mi.versionName +
                  " code=" + std::to_string(mi.versionCode) + " perms=" + std::to_string(mi.permissions.size()));
        // multi-DEX: parse both from the archive and sum class defs
        DexFile d1(zip.read("classes.dex"));
        DexFile d2(zip.read("classes2.dex"));
        size_t classes = d1.classes().size() + d2.classes().size();
        uint32_t methods = d1.methodCount() + d2.methodCount();
        if (classes == 18440 && methods == 113300)
            PASS("dcr_multidex_parse", std::to_string(classes) + " classes / " + std::to_string(methods) + " methods");
        else FAIL("dcr_multidex_parse", "classes=" + std::to_string(classes) + " methods=" + std::to_string(methods));
    } catch (const std::exception& e) { FAIL("dcr_tests", e.what()); }
}

static void lifecycleTests() {
    // Milestone B: Application.onCreate executes through the framework registry.
    try {
        Runtime rt; rt.addDexPath(fx("lifecycle.dex"));
        Interpreter vm(rt);
        RunResult r = vm.run("LTestApp;", "boot", "I", {}, ExecutionMode::FUNCTIONAL);
        bool logged = false;
        for (auto& l : vm.trace().logcat) if (l.find("onCreate ran") != std::string::npos) logged = true;
        if (r.kind == RunResult::INT && r.i == 7 && logged)
            PASS("lifecycle_functional", "boot=7, Log.d captured");
        else FAIL("lifecycle_functional", "kind=" + std::to_string(r.kind) +
                  " i=" + std::to_string(r.i) + " logged=" + (logged?"1":"0"));
    } catch (const std::exception& e) { FAIL("lifecycle_functional", e.what()); }

    // Milestone D: the two modes produce distinguishable results.
    try {
        Runtime rt; rt.addDexPath(fx("lifecycle.dex"));
        Interpreter a(rt), b(rt);
        RunResult ra = a.run("LTestApp;", "modeProbe", "I", {}, ExecutionMode::ANALYSIS);
        RunResult rb = b.run("LTestApp;", "modeProbe", "I", {}, ExecutionMode::FUNCTIONAL);
        if (ra.kind == RunResult::INT && ra.i == 5 && rb.kind == RunResult::UNSUPPORTED)
            PASS("mode_distinguish", "analysis=5, functional=unsupported");
        else FAIL("mode_distinguish", "analysis kind=" + std::to_string(ra.kind) +
                  " functional kind=" + std::to_string(rb.kind));
    } catch (const std::exception& e) { FAIL("mode_distinguish", e.what()); }
}

static void frameworkUnitTests() {
    // Direct registry checks for each handler category.
    FrameworkRegistry reg;
    struct TinyHeap : HostHeap {
        std::vector<HeapObj> h{{}};
        uint32_t newObject(const std::string& k, const std::string& nk="") override {
            HeapObj o; o.klass=k; o.nativeKind=nk; h.push_back(o); return (uint32_t)h.size()-1; }
        uint32_t newString(const std::string& s) override { HeapObj o; o.isString=true; o.str=s; h.push_back(o); return (uint32_t)h.size()-1; }
        std::string stringOf(uint32_t r) override { return r<h.size()?h[r].str:""; }
        HeapObj* obj(uint32_t r) override { return (r&&r<h.size())?&h[r]:nullptr; }
        uint32_t ctx_=0;
        uint32_t applicationContext() override { if(!ctx_) ctx_=newObject("Landroid/content/Context;","context"); return ctx_; }
        std::string packageName() override { return "test.pkg"; }
        std::string storageRoot() override { return "/tmp/apkbridge-test"; }
        std::unordered_map<std::string,uint32_t> sp_;
        uint32_t sharedPreferences(const std::string& n) override { auto it=sp_.find(n); if(it!=sp_.end()) return it->second; uint32_t r=newObject("Landroid/content/SharedPreferences;","prefs"); h[r].str=n; sp_[n]=r; return r; }
        void prefsPersist(uint32_t) override {}
    } heap;
    ExecutionTrace tr;
    auto hit = [&](const std::string& sig, std::vector<Value> args, ExecutionMode m){
        return reg.dispatch(sig, heap, args, tr, m); };

    // no-op
    auto o1 = hit("Landroid/app/Application;->onCreate(V)", {}, ExecutionMode::FUNCTIONAL);
    (o1.kind==FwOutcome::VOID) ? PASS("fw_onCreate_noop") : FAIL("fw_onCreate_noop","not void");
    // modeled context
    auto o2 = hit("Landroid/app/Application;->getApplicationContext(L)", {}, ExecutionMode::FUNCTIONAL);
    (o2.kind==FwOutcome::REF && heap.obj(o2.ref) && heap.obj(o2.ref)->nativeKind=="context")
        ? PASS("fw_getContext_modeled") : FAIL("fw_getContext_modeled","no context");
    // modeled Bundle round-trip
    uint32_t b = heap.newObject("Landroid/os/Bundle;","bundle");
    uint32_t key = heap.newString("k");
    hit("Landroid/os/Bundle;->putInt(VLI)", {Value::Ref(b),Value::Ref(key),Value::Int(42)}, ExecutionMode::FUNCTIONAL);
    auto o3 = hit("Landroid/os/Bundle;->getInt(IL)", {Value::Ref(b),Value::Ref(key)}, ExecutionMode::FUNCTIONAL);
    (o3.kind==FwOutcome::INT && o3.i==42) ? PASS("fw_bundle_roundtrip") : FAIL("fw_bundle_roundtrip","got "+std::to_string(o3.i));
    // analysis-substitute gated by mode
    auto oa = hit("Landroid/app/Application;->registerActivityLifecycleCallbacks(VL)", {Value::Ref(0)}, ExecutionMode::ANALYSIS);
    auto of = hit("Landroid/app/Application;->registerActivityLifecycleCallbacks(VL)", {Value::Ref(0)}, ExecutionMode::FUNCTIONAL);
    (oa.kind==FwOutcome::VOID && of.kind==FwOutcome::UNHANDLED) ? PASS("fw_mode_gate")
        : FAIL("fw_mode_gate","analysis="+std::to_string(oa.kind)+" functional="+std::to_string(of.kind));
    // unknown -> unhandled (Category C upstream)
    auto ou = hit("Lcom/unknown/X;->nope(V)", {}, ExecutionMode::ANALYSIS);
    (ou.kind==FwOutcome::UNHANDLED) ? PASS("fw_unknown_unhandled") : FAIL("fw_unknown_unhandled","handled?!");
}

static void correctnessTests() {
    // native method must be rejected explicitly (no silent success)
    try {
        Runtime rt; rt.addDexPath(fx("native.dex"));
        Interpreter vm(rt);
        RunResult r = vm.run("LNative;", "nyi", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::UNSUPPORTED && r.message.find("native")!=std::string::npos)
            ? PASS("native_rejected", r.message) : FAIL("native_rejected","kind="+std::to_string(r.kind));
    } catch (const std::exception& e) { FAIL("native_rejected", e.what()); }

    // application context identity: same ref on repeat calls
    try {
        Runtime rt; rt.addDexPath(fx("arith.dex"));
        Interpreter vm(rt);
        uint32_t c1 = vm.applicationContext(), c2 = vm.applicationContext();
        (c1!=0 && c1==c2) ? PASS("context_identity","ref="+std::to_string(c1))
                          : FAIL("context_identity","c1="+std::to_string(c1)+" c2="+std::to_string(c2));
    } catch (const std::exception& e) { FAIL("context_identity", e.what()); }

    // cross-DEX via the real two-DEX layout: classes2(LMainB).run calls
    // classes(LLibA).addA -> 105
    try {
        Runtime rt; rt.addDexPath(fx("crossdex/classes2.dex")); rt.addDexPath(fx("crossdex/classes.dex"));
        Interpreter vm(rt);
        RunResult r = vm.run("LMainB;", "run", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::INT && r.i==105) ? PASS("cross_dex_invoke","105")
            : FAIL("cross_dex_invoke","kind="+std::to_string(r.kind)+" i="+std::to_string(r.i)+" "+r.message);
    } catch (const std::exception& e) { FAIL("cross_dex_invoke", e.what()); }

    // Task 2: both public C-ABI interfaces load siblings and give identical
    // results through the real two-DEX path.
    try {
        std::string dex = fx("crossdex/classes2.dex");
        const char* j1 = apkbridge_run_method(dex.c_str(), "LMainB;", "run", "I", nullptr, 0);
        const char* j2 = apkbridge_run_method_mode(dex.c_str(), "LMainB;", "run", "I", nullptr, 0, "functional");
        std::string s1 = j1?j1:"", s2 = j2?j2:"";
        apkbridge_free(j1); apkbridge_free(j2);
        bool both105 = s1.find("\"value\":\"105\"")!=std::string::npos
                    && s2.find("\"value\":\"105\"")!=std::string::npos;
        both105 ? PASS("bridge_interfaces_parity","both run_method & run_method_mode -> 105")
                : FAIL("bridge_interfaces_parity", "s1="+s1.substr(0,60)+" s2="+s2.substr(0,60));
    } catch (const std::exception& e) { FAIL("bridge_interfaces_parity", e.what()); }
}

static void collectionTests() {
    FrameworkRegistry reg;
    struct TinyHeap : HostHeap {
        std::vector<HeapObj> h{{}}; uint32_t ctx_=0;
        uint32_t newObject(const std::string& k, const std::string& nk="") override { HeapObj o; o.klass=k; o.nativeKind=nk; h.push_back(o); return (uint32_t)h.size()-1; }
        uint32_t newString(const std::string& s) override { HeapObj o; o.isString=true; o.str=s; h.push_back(o); return (uint32_t)h.size()-1; }
        std::string stringOf(uint32_t r) override { return r<h.size()?h[r].str:""; }
        HeapObj* obj(uint32_t r) override { return (r&&r<h.size())?&h[r]:nullptr; }
        uint32_t applicationContext() override { if(!ctx_) ctx_=newObject("Landroid/content/Context;","context"); return ctx_; }
        std::string packageName() override { return "test.pkg"; }
        std::string storageRoot() override { return "/tmp/apkbridge-test"; }
        std::unordered_map<std::string,uint32_t> sp_;
        uint32_t sharedPreferences(const std::string& n) override { auto it=sp_.find(n); if(it!=sp_.end()) return it->second; uint32_t r=newObject("Landroid/content/SharedPreferences;","prefs"); h[r].str=n; sp_[n]=r; return r; }
        void prefsPersist(uint32_t) override {}
    } heap;
    ExecutionTrace tr;
    auto hit=[&](const std::string& s, std::vector<Value> a){ return reg.dispatch(s,heap,a,tr,ExecutionMode::FUNCTIONAL); };

    // LinkedHashMap: insertion order, replace, null value, remove, size
    uint32_t mp=heap.newObject("Ljava/util/LinkedHashMap;","map");
    hit("Ljava/util/LinkedHashMap;-><init>(V)", {Value::Ref(mp)});
    uint32_t kA=heap.newString("a"), kB=heap.newString("b");
    uint32_t vA=heap.newString("A"), vA2=heap.newString("A2");
    hit("Ljava/util/LinkedHashMap;->put(LLL)", {Value::Ref(mp),Value::Ref(kA),Value::Ref(vA)});
    hit("Ljava/util/LinkedHashMap;->put(LLL)", {Value::Ref(mp),Value::Ref(kB),Value::Ref(0)}); // null value
    auto szr=hit("Ljava/util/LinkedHashMap;->size(I)", {Value::Ref(mp)});
    auto getB=hit("Ljava/util/LinkedHashMap;->get(LL)", {Value::Ref(mp),Value::Ref(kB)});
    auto prev=hit("Ljava/util/LinkedHashMap;->put(LLL)", {Value::Ref(mp),Value::Ref(kA),Value::Ref(vA2)}); // replace
    bool orderOK = heap.obj(mp)->mapKeys.size()==2 && heap.obj(mp)->mapKeys[0]=="s:a" && heap.obj(mp)->mapKeys[1]=="s:b";
    auto rem=hit("Ljava/util/LinkedHashMap;->remove(LL)", {Value::Ref(mp),Value::Ref(kA)});
    auto sz2=hit("Ljava/util/LinkedHashMap;->size(I)", {Value::Ref(mp)});
    (szr.i==2 && getB.ref==0 && prev.ref==vA && orderOK && rem.ref==vA2 && sz2.i==1)
        ? PASS("map_linkedhashmap","order/null/replace/remove ok")
        : FAIL("map_linkedhashmap","size="+std::to_string(szr.i)+" getB="+std::to_string(getB.ref)+
               " prev="+std::to_string(prev.ref)+" order="+(orderOK?"1":"0")+" rem="+std::to_string(rem.ref)+" sz2="+std::to_string(sz2.i));

    // StringBuilder: append string + int, toString
    uint32_t sb=heap.newObject("Ljava/lang/StringBuilder;","sb");
    hit("Ljava/lang/StringBuilder;-><init>(V)", {Value::Ref(sb)});
    uint32_t sx=heap.newString("x=");
    hit("Ljava/lang/StringBuilder;->append(LL)", {Value::Ref(sb),Value::Ref(sx)});
    hit("Ljava/lang/StringBuilder;->append(LI)", {Value::Ref(sb),Value::Int(7)});
    auto ts=hit("Ljava/lang/StringBuilder;->toString(L)", {Value::Ref(sb)});
    (ts.kind==FwOutcome::REF && heap.stringOf(ts.ref)=="x=7") ? PASS("stringbuilder","x=7")
        : FAIL("stringbuilder","got "+heap.stringOf(ts.ref));

    // String.equals
    uint32_t s1=heap.newString("hi"), s2=heap.newString("hi"), s3=heap.newString("bye");
    auto e1=hit("Ljava/lang/String;->equals(ZL)", {Value::Ref(s1),Value::Ref(s2)});
    auto e2=hit("Ljava/lang/String;->equals(ZL)", {Value::Ref(s1),Value::Ref(s3)});
    (e1.i==1 && e2.i==0) ? PASS("string_equals") : FAIL("string_equals","e1="+std::to_string(e1.i)+" e2="+std::to_string(e2.i));
}

static void initAndStorageTests() {
    // <clinit> runs before first use: getVal() must see 42, not default 0.
    try {
        Runtime rt; rt.addDexPath(fx("clinit.dex")); Interpreter vm(rt);
        RunResult r = vm.run("LClinit;", "getVal", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::INT && r.i==42) ? PASS("clinit_runs","42")
            : FAIL("clinit_runs","kind="+std::to_string(r.kind)+" i="+std::to_string(r.i)+" "+r.message);
    } catch (const std::exception& e) { FAIL("clinit_runs", e.what()); }

    // storage + SharedPreferences round-trip (getCacheDir, mkdirs, prefs put/get)
    if (system("rm -rf /tmp/apkbridge-appA /tmp/apkbridge-appB") != 0) {}
    try {
        Runtime rt; rt.addDexPath(fx("storage.dex"));
        Interpreter a(rt); a.setStorageRoot("/tmp/apkbridge-appA"); a.setPackage("app.a");
        RunResult r = a.run("LStore;", "boot", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::INT && r.i==7) ? PASS("storage_prefs_roundtrip","put/commit/get=7")
            : FAIL("storage_prefs_roundtrip","kind="+std::to_string(r.kind)+" i="+std::to_string(r.i)+" "+r.message);
    } catch (const std::exception& e) { FAIL("storage_prefs_roundtrip", e.what()); }

    // isolation: a different app (storageRoot) must NOT see app A's key
    try {
        Runtime rt; rt.addDexPath(fx("storage.dex"));
        Interpreter b(rt); b.setStorageRoot("/tmp/apkbridge-appB"); b.setPackage("app.b");
        RunResult r = b.run("LStore;", "readback", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::INT && r.i==0) ? PASS("prefs_isolation","app B sees default 0")
            : FAIL("prefs_isolation","app B leaked value "+std::to_string(r.i));
    } catch (const std::exception& e) { FAIL("prefs_isolation", e.what()); }

    // persistence: a fresh interpreter on app A's root reads the persisted 7
    try {
        Runtime rt; rt.addDexPath(fx("storage.dex"));
        Interpreter c(rt); c.setStorageRoot("/tmp/apkbridge-appA"); c.setPackage("app.a");
        RunResult r = c.run("LStore;", "readback", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::INT && r.i==7) ? PASS("prefs_persist","reloaded 7 from disk")
            : FAIL("prefs_persist","got "+std::to_string(r.i)+" "+r.message);
    } catch (const std::exception& e) { FAIL("prefs_persist", e.what()); }
}

static void securityTests() {
    // Task 1: centralized filesystem containment (the security policy itself).
    std::string out;
    bool t1 = FrameworkRegistry::containedHostPath("/tmp/approot", "/tmp/approot/cache", out);
    bool t2 = FrameworkRegistry::containedHostPath("/tmp/approot", "/etc/passwd", out);
    bool t3 = FrameworkRegistry::containedHostPath("/tmp/approot", "/tmp/approot/../etc", out);
    bool t4 = FrameworkRegistry::containedHostPath("/tmp/approot", "sub/dir/x", out);
    bool t5 = FrameworkRegistry::containedHostPath("/tmp/approot", "/tmp/approot2/secret", out); // sibling app
    (t1 && !t2 && !t3 && t4 && !t5) ? PASS("fs_containment","in ok; escape/sibling rejected")
        : FAIL("fs_containment", std::to_string(t1)+std::to_string(t2)+std::to_string(t3)+std::to_string(t4)+std::to_string(t5));
    // SharedPreferences name validation -> safe single segment
    std::string sn = FrameworkRegistry::safeName("../../evil/../x");
    (sn.find('/')==std::string::npos && sn.find("..")==std::string::npos)
        ? PASS("prefs_name_validation", sn) : FAIL("prefs_name_validation", sn);

    // INJECTIVE prefs names: distinct names must not collide to one file
    (FrameworkRegistry::safeName("a/b") != FrameworkRegistry::safeName("a_b") &&
     FrameworkRegistry::safeName("a.b") != FrameworkRegistry::safeName("a_b") &&
     FrameworkRegistry::safeName("x").find('/')==std::string::npos)
        ? PASS("prefs_name_injective","a/b, a_b, a.b all distinct")
        : FAIL("prefs_name_injective","collision");

    // LONG names: distinctness must survive the length cap. Two names sharing a
    // 300-char prefix but differing only at the end must map to different files
    // (the hashed tail is computed over the FULL name, not the truncated prefix),
    // and every result must stay within a safe filename length.
    {
        std::string base(300, 'q');
        std::string a = base + "ALPHA", b = base + "BETA";
        std::string sa = FrameworkRegistry::safeName(a), sb = FrameworkRegistry::safeName(b);
        std::string sc = FrameworkRegistry::safeName(base + "ALPHA");   // determinism
        bool ok = sa != sb && sa == sc
                  && sa.size() <= 200 && sb.size() <= 200
                  && sa.find('/')==std::string::npos;
        ok ? PASS("prefs_name_long_distinct", "len="+std::to_string(sa.size()))
           : FAIL("prefs_name_long_distinct", sa+" vs "+sb);
    }

    // REAL symlink escape: a symlink inside the root pointing outside must be
    // rejected (TOCTOU-resistant: we canonicalize the resolved target).
    namespace fs = std::filesystem; std::error_code ec;
    std::string root = "/tmp/apkbridge-symtest"; fs::remove_all(root, ec);
    fs::create_directories(root + "/cache", ec);
    fs::create_directory_symlink("/etc", root + "/escape", ec);
    std::string real;
    bool viaSymlink = FrameworkRegistry::containedHostPath(root, root + "/escape/hostname", real);
    bool realInside = FrameworkRegistry::containedHostPath(root, root + "/cache/x", real);
    (!viaSymlink && realInside) ? PASS("fs_symlink_escape_rejected","symlink target outside root blocked")
        : FAIL("fs_symlink_escape_rejected", std::string("viaSymlink=")+(viaSymlink?"1":"0")+" realInside="+(realInside?"1":"0"));
    fs::remove_all(root, ec);
}

static void clinitStateTests() {
    // recursive init completes
    try {
        Runtime rt; rt.addDexPath(fx("clinit_rec.dex")); Interpreter vm(rt);
        RunResult r = vm.run("LClinitRec;", "getV", "I", {}, ExecutionMode::FUNCTIONAL);
        (r.kind==RunResult::INT && r.i==5) ? PASS("clinit_recursive","5")
            : FAIL("clinit_recursive","kind="+std::to_string(r.kind)+" i="+std::to_string(r.i));
    } catch (const std::exception& e) { FAIL("clinit_recursive", e.what()); }
    // failed init -> FAILED, and STICKY on reuse (both calls unsupported, never silent OK)
    try {
        Runtime rt; rt.addDexPath(fx("clinit_fail.dex")); Interpreter vm(rt);
        RunResult r1 = vm.run("LClinitFail;", "getV", "I", {}, ExecutionMode::FUNCTIONAL);
        RunResult r2 = vm.run("LClinitFail;", "getV", "I", {}, ExecutionMode::FUNCTIONAL);
        bool stuck = r2.message.find("previously failed")!=std::string::npos;
        (r1.kind==RunResult::UNSUPPORTED && r2.kind==RunResult::UNSUPPORTED && stuck)
            ? PASS("clinit_failed_sticky","FAILED propagated on reuse")
            : FAIL("clinit_failed_sticky","r1="+std::to_string(r1.kind)+" r2="+std::to_string(r2.kind)+" stuck="+(stuck?"1":"0"));
    } catch (const std::exception& e) { FAIL("clinit_failed_sticky", e.what()); }
}

static void robustnessTests() {
    // Task 6: framework handlers must tolerate invalid/null object refs safely.
    FrameworkRegistry reg;
    struct TinyHeap : HostHeap {
        std::vector<HeapObj> h{{}}; uint32_t ctx_=0;
        uint32_t newObject(const std::string& k, const std::string& nk="") override { HeapObj o; o.klass=k; o.nativeKind=nk; h.push_back(o); return (uint32_t)h.size()-1; }
        uint32_t newString(const std::string& s) override { HeapObj o; o.isString=true; o.str=s; h.push_back(o); return (uint32_t)h.size()-1; }
        std::string stringOf(uint32_t r) override { return r<h.size()?h[r].str:""; }
        HeapObj* obj(uint32_t r) override { return (r&&r<h.size())?&h[r]:nullptr; }
        uint32_t applicationContext() override { if(!ctx_) ctx_=newObject("Landroid/content/Context;","context"); return ctx_; }
        std::string packageName() override { return "t"; }
        std::string storageRoot() override { return "/tmp/apkbridge-rob"; }
        std::unordered_map<std::string,uint32_t> sp_;
        uint32_t sharedPreferences(const std::string& n) override { uint32_t r=newObject("Landroid/content/SharedPreferences;","prefs"); h[r].str=n; return r; }
        void prefsPersist(uint32_t) override {}
    } heap; ExecutionTrace tr;
    bool ok = true;
    try {
        // null receiver + null key -> safe defaults, no crash
        auto g = reg.dispatch("Ljava/util/HashMap;->get(LL)", heap, {Value::Ref(0), Value::Ref(0)}, tr, ExecutionMode::FUNCTIONAL);
        auto s = reg.dispatch("Landroid/os/Bundle;->getInt(IL)", heap, {Value::Ref(0), Value::Ref(0)}, tr, ExecutionMode::FUNCTIONAL);
        // missing args entirely
        auto e = reg.dispatch("Ljava/util/ArrayList;->size(I)", heap, {}, tr, ExecutionMode::FUNCTIONAL);
        ok = (g.kind==FwOutcome::REF && g.ref==0) && (s.kind==FwOutcome::INT && s.i==0) && (e.kind==FwOutcome::INT && e.i==0);
    } catch (...) { ok = false; }
    ok ? PASS("framework_null_safe","null/missing refs -> safe defaults")
       : FAIL("framework_null_safe","handler crashed or wrong default");
}

static void installTxnTests() {
    namespace fs = std::filesystem; std::error_code e;
    // Build a sandbox with live "old" code + user data, and a validated staging "new".
    auto setup = [&](const std::string& box){
        fs::remove_all(box, e);
        fs::create_directories(box + "/dex", e);
        fs::create_directories(box + "/files", e);
        fs::create_directories(box + "/shared_prefs", e);
        { std::ofstream(box + "/dex/classes.dex") << "OLD"; }
        { std::ofstream(box + "/files/userdata.txt") << "KEEPME"; }      // user data
        { std::ofstream(box + "/shared_prefs/settings.xml") << "PREFS"; }
    };
    auto staging = [&](const std::string& s){
        fs::remove_all(s, e); fs::create_directories(s, e);
        { std::ofstream(s + "/classes.dex") << "NEW"; }
        return s;
    };
    auto liveCode = [&](const std::string& box){
        std::ifstream f(box + "/dex/classes.dex"); std::string v; std::getline(f,v); return v; };
    auto dataKept = [&](const std::string& box){
        std::ifstream p(box + "/shared_prefs/settings.xml"); std::string prefs; std::getline(p,prefs);
        return fs::exists(box + "/files/userdata.txt") && prefs=="PREFS";
    };

    // Full commit succeeds: new code live, backup gone, data kept.
    { std::string box="/tmp/apktxn-full", st="/tmp/apktxn-full-st"; setup(box); staging(st);
      InstallTxn::prepare(box, st); auto r=InstallTxn::commit(box, 0);
      bool ok = r.ok && liveCode(box)=="NEW" && !fs::exists(box+"/dex.old") && dataKept(box);
      ok?PASS("txn_commit_full","new live, data kept"):FAIL("txn_commit_full", r.state+" code="+liveCode(box)); }

    // Interrupt AFTER each step, then recover; verify a consistent outcome and
    // that user data is never lost. Steps 1,2 -> previous code; 3,4 -> new code.
    struct Case { int stop; const char* expectCode; const char* name; };
    for (Case c : {Case{1,"OLD","txn_recover_after_begin"},
                   Case{2,"OLD","txn_recover_after_backup"},
                   Case{3,"NEW","txn_recover_after_promote"},
                   Case{4,"NEW","txn_recover_after_done"}}) {
        std::string box=std::string("/tmp/apktxn-")+c.name; setup(box); staging(box+"-st");
        InstallTxn::prepare(box, box+"-st");
        InstallTxn::commit(box, c.stop);          // simulated crash after step c.stop
        InstallResult rec = InstallTxn::recover(box);
        bool ok = rec.ok && liveCode(box)==std::string(c.expectCode) && dataKept(box)
                  && !fs::exists(box+"/dex.old") && !fs::exists(box+"/dex.new");
        ok?PASS(c.name, std::string(rec.state)+" -> "+liveCode(box))
          :FAIL(c.name, std::string("state=")+rec.state+" code="+liveCode(box)+" data="+(dataKept(box)?"1":"0"));
    }
    // Abandoned prepare (crash before any commit step) -> old code kept, new discarded.
    { std::string box="/tmp/apktxn-abandon"; setup(box); staging(box+"-st");
      InstallTxn::prepare(box, box+"-st");         // dex.new exists, no marker
      auto rec=InstallTxn::recover(box);
      bool ok = rec.ok && liveCode(box)=="OLD" && !fs::exists(box+"/dex.new") && dataKept(box);
      ok?PASS("txn_recover_abandoned_prepare","OLD kept"):FAIL("txn_recover_abandoned_prepare", rec.state+" "+liveCode(box)); }

    // Preparation and commit must fail closed without touching live code.
    { std::string box="/tmp/apktxn-missing-stage"; setup(box);
      auto r=InstallTxn::prepare(box, box+"-missing");
      (!r.ok && liveCode(box)=="OLD" && !fs::exists(box+"/dex.new"))
        ?PASS("txn_prepare_missing_staging","live code kept")
        :FAIL("txn_prepare_missing_staging",r.message); }
    { std::string box="/tmp/apktxn-empty-stage"; setup(box); fs::create_directories(box+"-st",e);
      auto r=InstallTxn::prepare(box, box+"-st");
      (!r.ok && liveCode(box)=="OLD")?PASS("txn_prepare_empty_staging","rejected")
        :FAIL("txn_prepare_empty_staging",r.message); }
    { std::string box="/tmp/apktxn-no-prepared"; setup(box);
      auto r=InstallTxn::commit(box,0);
      (!r.ok && liveCode(box)=="OLD" && dataKept(box))?PASS("txn_commit_without_prepare","rejected")
        :FAIL("txn_commit_without_prepare",r.message); }
    { std::string box="/tmp/apktxn-cabi-prepare-fail"; setup(box);
      const char* raw=apkbridge_install_commit(box.c_str(),(box+"-missing").c_str());
      std::string js=raw?raw:""; apkbridge_free(raw);
      (js.find("\"ok\":false")!=std::string::npos && liveCode(box)=="OLD" && dataKept(box))
        ?PASS("txn_cabi_prepare_failure","commit not attempted")
        :FAIL("txn_cabi_prepare_failure",js); }

    // Recovery validates promoted code before accepting it and handles corrupt
    // journal state conservatively.
    auto invalidPromoted = [&](const std::string& box, const std::string& marker){
        setup(box); fs::rename(box+"/dex",box+"/dex.old",e); fs::create_directories(box+"/dex",e);
        { std::ofstream(box+"/.txn") << marker; }
    };
    { std::string box="/tmp/apktxn-invalid-begin"; invalidPromoted(box,"BEGIN");
      auto r=InstallTxn::recover(box);
      (r.ok && r.state=="ROLLED_BACK" && liveCode(box)=="OLD" && dataKept(box))
        ?PASS("txn_recover_invalid_promoted_begin","old code restored")
        :FAIL("txn_recover_invalid_promoted_begin",r.state+" "+r.message); }
    { std::string box="/tmp/apktxn-invalid-done"; invalidPromoted(box,"DONE");
      auto r=InstallTxn::recover(box);
      (r.ok && r.state=="ROLLED_BACK" && liveCode(box)=="OLD" && dataKept(box))
        ?PASS("txn_recover_invalid_promoted_done","old code restored")
        :FAIL("txn_recover_invalid_promoted_done",r.state+" "+r.message); }
    { std::string box="/tmp/apktxn-bad-marker"; setup(box); { std::ofstream(box+"/.txn") << "CORRUPT"; }
      auto r=InstallTxn::recover(box);
      (!r.ok && liveCode(box)=="OLD" && dataKept(box))?PASS("txn_recover_invalid_journal","left intact")
        :FAIL("txn_recover_invalid_journal",r.state+" "+r.message); }
    { std::string box="/tmp/apktxn-prefs"; setup(box); staging(box+"-st");
      auto p=InstallTxn::prepare(box,box+"-st"); auto r=p.ok?InstallTxn::commit(box,0):p;
      (r.ok && liveCode(box)=="NEW" && dataKept(box))?PASS("txn_upgrade_preserves_preferences","PREFS kept")
        :FAIL("txn_upgrade_preserves_preferences",r.state+" "+r.message); }
}

int main(int argc, char** argv) {
    std::vector<std::string> cand = {
        argc > 1 ? std::string(argv[1]) : std::string(),
        "../tests/fixtures", "tests/fixtures", "../../tests/fixtures" };
    for (auto& c : cand) { if (c.empty()) continue;
        FILE* f = std::fopen((c + "/arith.dex").c_str(), "rb");
        if (f) { std::fclose(f); FDIR = c; break; } }
    if (FDIR.empty()) { std::cerr << "cannot find fixtures dir\n"; return 2; }
    std::cout << "fixtures: " << FDIR << "\n";

    // conformance
    expectInt("arith.dex",  "LArith;",   "compute", "I",  {},    33);
    expectInt("loop.dex",   "LLoop;",    "sumTo",   "II", {10},  55);
    expectInt("invoke.dex", "LMain;",    "main",    "I",  {},    42);
    expectInt("object.dex", "LObjMain;", "make",    "I",  {},    7);
    expectInt("array.dex",  "LArr;",     "run",     "I",  {},    45);
    expectInt("exception.dex","LExc;",   "run",     "I",  {},    99);
    // unsupported-op + execution-limit detection
    expectKind("unsupported.dex", "LUnsup;", "run", "I", RunResult::UNSUPPORTED, "unsupported opcode");
    expectKind("infinite.dex",    "LInf;",   "run", "I", RunResult::UNSUPPORTED, "budget");
    // robustness + safety
    malformedDexTests();
    zipSafetyTests();
    // framework registry + Android lifecycle
    frameworkUnitTests();
    lifecycleTests();
    correctnessTests();   // native rejection, context identity, cross-DEX
    collectionTests();    // map/stringbuilder/string
    initAndStorageTests(); // <clinit>, storage, SharedPreferences isolation/persistence
    securityTests();        // filesystem containment + prefs name validation
    robustnessTests();      // null/malformed framework inputs
    installTxnTests();      // crash-safe install transaction + recovery
    clinitStateTests();     // init state machine: recursive + failed(sticky)
    // real-APK gated tests
    dcrTests();

    std::cout << "\n" << pass << " passed, " << fail << " failed, " << skip << " skipped\n";
    return fail ? 1 : 0;
}
