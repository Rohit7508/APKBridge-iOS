// APKBridge runtime :: C ABI implementation (links into the iOS static lib).
#include "apkbridge_runtime.h"
#include "dex.hpp"
#include "interp.hpp"
#include "zip.hpp"
#include "axml.hpp"
#include "install.hpp"
#include <string>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <algorithm>

using namespace apkbridge;
namespace fs = std::filesystem;

// Build a Runtime from a dex path. If loadSiblings, also load every other
// classes*.dex in the same directory (one APK's multi-DEX set) for cross-DEX
// resolution.
// Configure per-app identity + sandboxed storage root from the dex directory.
static void configureApp(Interpreter& vm, const std::string& dexPath) {
    fs::path dir = fs::path(dexPath).parent_path();
    // Installed code lives in <sandbox>/dex. Keep Android application data at
    // the stable sandbox root so replacing dex during an upgrade cannot erase
    // SharedPreferences, files, databases, or cache data.
    fs::path storage = dir.filename() == "dex" ? dir.parent_path() : dir / "appstorage";
    vm.setStorageRoot(storage.string());
    fs::path mf = dir / "AndroidManifest.xml";
    if (fs::exists(mf)) {
        try {
            std::ifstream f(mf, std::ios::binary);
            std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            if (!b.empty()) { Axml ax(b); if (!ax.info().package.empty()) vm.setPackage(ax.info().package); }
        } catch (...) {}
    }
}

static void buildRuntime(Runtime& rt, const std::string& dexPath, bool loadSiblings) {
    rt.addDexPath(dexPath);
    if (!loadSiblings) return;
    fs::path p(dexPath);
    std::regex dexRe("^classes[0-9]*\\.dex$");
    for (const auto& e : fs::directory_iterator(p.parent_path())) {
        std::string n = e.path().filename().string();
        if (n != p.filename().string() && std::regex_match(n, dexRe))
            rt.addDexPath(e.path().string());
    }
}

static const char* dup(const std::string& s) {
    char* p = (char*)std::malloc(s.size() + 1);
    if (!p) return nullptr;
    std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}
static std::string esc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b,sizeof b,"\\u%04x",c); o+=b; }
                else o.push_back(c);
        }
    }
    return o;
}
static std::string q(const std::string& s) { return "\"" + esc(s) + "\""; }

// Validate an Android package id: non-empty, <=255 chars, dot-separated
// segments of [A-Za-z0-9_$], no leading/trailing/empty segment. Prevents
// malformed ids from producing unsafe filesystem paths.
static bool validPackage(const std::string& p) {
    if (p.empty() || p.size() > 255) return false;
    size_t seg = 0;
    for (char c : p) {
        if (c == '.') { if (seg == 0) return false; seg = 0; continue; }
        bool ok = (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='$';
        if (!ok) return false;
        ++seg;
    }
    return seg != 0;  // no trailing dot
}

// ---- import ---------------------------------------------------------------
extern "C" const char* apkbridge_import_apk(const char* apkPath, const char* destDir) {
    try {
        ZipArchive zip = ZipArchive::fromPath(apkPath);

        ManifestInfo mi;
        if (zip.has("AndroidManifest.xml")) { Axml ax(zip.read("AndroidManifest.xml")); mi = ax.info(); }
        if (!mi.package.empty() && !validPackage(mi.package))
            return dup(std::string("{\"ok\":false,\"error\":\"invalid package id: ") + esc(mi.package) + "\"}");

        std::regex dexRe("^classes[0-9]*\\.dex$");
        std::regex libRe("^lib/([^/]+)/([^/]+\\.so)$");
        std::vector<std::string> dexNames;
        std::vector<std::pair<std::string,std::string>> libs;
        for (const auto& e : zip.entries()) {
            if (std::regex_match(e.name, dexRe)) dexNames.push_back(e.name);
            std::smatch m;
            if (std::regex_match(e.name, m, libRe)) libs.emplace_back(m[1], m[2]);
        }

        fs::create_directories(destDir);
        std::vector<std::pair<std::string,std::string>> extracted;
        std::vector<std::string> toExtract = dexNames;
        if (zip.has("AndroidManifest.xml")) toExtract.push_back("AndroidManifest.xml");
        for (const auto& n : toExtract) {
            std::string rel = ZipArchive::sanitizeRelPath(n);
            if (rel.empty()) continue;
            fs::path out = fs::path(destDir) / rel;
            fs::create_directories(out.parent_path());
            auto data = zip.read(n);
            std::ofstream f(out, std::ios::binary);
            f.write((const char*)data.data(), (std::streamsize)data.size());
            if (std::find(dexNames.begin(), dexNames.end(), n) != dexNames.end())
                extracted.emplace_back(n, out.string());
        }

        std::ostringstream js;
        js << "{\"ok\":true"
           << ",\"package\":" << q(mi.package)
           << ",\"applicationClass\":" << q(mi.applicationClass)
           << ",\"versionName\":" << q(mi.versionName)
           << ",\"versionCode\":" << mi.versionCode
           << ",\"minSdk\":" << mi.minSdk
           << ",\"targetSdk\":" << mi.targetSdk
           << ",\"permissions\":[";
        for (size_t i = 0; i < mi.permissions.size(); ++i) js << (i?",":"") << q(mi.permissions[i]);
        js << "],\"dexFiles\":[";
        for (size_t i = 0; i < extracted.size(); ++i)
            js << (i?",":"") << "{\"name\":" << q(extracted[i].first) << ",\"path\":" << q(extracted[i].second) << "}";
        js << "],\"nativeLibs\":[";
        for (size_t i = 0; i < libs.size(); ++i)
            js << (i?",":"") << "{\"abi\":" << q(libs[i].first) << ",\"name\":" << q(libs[i].second) << "}";
        js << "]}";
        return dup(js.str());
    } catch (const std::exception& e) {
        return dup(std::string("{\"ok\":false,\"error\":") + q(e.what()) + "}");
    }
}

// ---- class / method browsing ---------------------------------------------
extern "C" const char* apkbridge_list_classes(const char* dexPath, int offset, int limit) {
    try {
        DexFile dex = DexFile::fromPath(dexPath);
        const auto& cs = dex.classes();
        if (offset < 0) offset = 0;
        if (limit <= 0 || limit > 2000) limit = 500;
        std::ostringstream js;
        js << "{\"total\":" << cs.size() << ",\"offset\":" << offset << ",\"classes\":[";
        int emitted = 0;
        for (size_t i = (size_t)offset; i < cs.size() && emitted < limit; ++i, ++emitted)
            js << (emitted?",":"") << q(cs[i].desc);
        js << "]}";
        return dup(js.str());
    } catch (const std::exception& e) { return dup(std::string("{\"error\":")+q(e.what())+"}"); }
}

static bool runnableShorty(const std::string& shorty, bool isStatic, bool hasCode) {
    if (!isStatic || !hasCode || shorty.empty()) return false;
    for (size_t i = 1; i < shorty.size(); ++i) if (shorty[i] != 'I') return false;
    return true;
}

extern "C" const char* apkbridge_list_methods(const char* dexPath, const char* className) {
    try {
        DexFile dex = DexFile::fromPath(dexPath);
        const Class* c = dex.findClass(className);
        if (!c) return dup(std::string("{\"error\":\"class not found\",\"class\":")+q(className)+"}");
        std::ostringstream js;
        js << "{\"class\":" << q(c->desc) << ",\"methods\":[";
        bool first = true;
        for (const auto* list : {&c->directMethods, &c->virtualMethods})
            for (const auto& m : *list) {
                bool isStatic = (m.accessFlags & 0x8) != 0;
                bool hasCode = m.codeOff != 0;
                js << (first?"":",") << "{\"name\":" << q(m.name)
                   << ",\"shorty\":" << q(m.shorty)
                   << ",\"static\":" << (isStatic?"true":"false")
                   << ",\"hasCode\":" << (hasCode?"true":"false")
                   << ",\"runnable\":" << (runnableShorty(m.shorty, isStatic, hasCode)?"true":"false")
                   << "}";
                first = false;
            }
        js << "]}";
        return dup(js.str());
    } catch (const std::exception& e) { return dup(std::string("{\"error\":")+q(e.what())+"}"); }
}

// ---- execution + inspect --------------------------------------------------
extern "C" const char* apkbridge_run_method(const char* dexPath, const char* cls,
        const char* method, const char* shorty, const int32_t* args, int nargs) {
    try {
        Runtime rt; buildRuntime(rt, dexPath, true);   // unified: load all sibling DEX
        Interpreter vm(rt); configureApp(vm, dexPath);
        std::vector<int32_t> a; for (int i = 0; i < nargs; ++i) a.push_back(args[i]);
        RunResult r = vm.run(cls, method, shorty ? shorty : "", a);
        std::string kind, value, extra;
        switch (r.kind) {
            case RunResult::VOID: kind="void"; break;
            case RunResult::INT: kind="int"; value=std::to_string(r.i); break;
            case RunResult::REF: kind="ref"; value=std::to_string(r.ref); extra=vm.heapString(r.ref); break;
            case RunResult::EXCEPTION: kind="exception"; value=r.exceptionType; extra=r.message; break;
            case RunResult::UNSUPPORTED: kind="unsupported"; value=r.message; break;
        }
        return dup("{\"kind\":"+q(kind)+",\"value\":"+q(value)+",\"extra\":"+q(extra)+"}");
    } catch (const std::exception& e) {
        return dup(std::string("{\"kind\":\"error\",\"value\":")+q(e.what())+",\"extra\":\"\"}");
    }
}

// Run with explicit mode ("analysis"|"functional") and return the execution
// trace + logcat alongside the result.
extern "C" const char* apkbridge_run_method_mode(const char* dexPath, const char* cls,
        const char* method, const char* shorty, const int32_t* args, int nargs,
        const char* mode) {
    try {
        Runtime rt; buildRuntime(rt, dexPath, true);   // load sibling dex too
        Interpreter vm(rt); configureApp(vm, dexPath);
        ExecutionMode m = (mode && std::string(mode) == "analysis")
                          ? ExecutionMode::ANALYSIS : ExecutionMode::FUNCTIONAL;
        std::vector<int32_t> a; for (int i = 0; i < nargs; ++i) a.push_back(args[i]);
        RunResult r = vm.run(cls, method, shorty ? shorty : "", a, m);
        std::string kind, value, extra;
        switch (r.kind) {
            case RunResult::VOID: kind="void"; break;
            case RunResult::INT: kind="int"; value=std::to_string(r.i); break;
            case RunResult::REF: kind="ref"; value=std::to_string(r.ref); extra=vm.heapString(r.ref); break;
            case RunResult::EXCEPTION: kind="exception"; value=r.exceptionType; extra=r.message; break;
            case RunResult::UNSUPPORTED: kind="unsupported"; value=r.message; break;
        }
        return dup("{\"kind\":"+q(kind)+",\"value\":"+q(value)+",\"extra\":"+q(extra)+
                   ",\"mode\":"+q(modeName(m))+",\"trace\":"+vm.trace().toJson()+"}");
    } catch (const std::exception& e) {
        return dup(std::string("{\"kind\":\"error\",\"value\":")+q(e.what())+",\"extra\":\"\"}");
    }
}

// Model framework instantiation + initial lifecycle dispatch for an Application
// subclass (allocates the instance, runs <init> then onCreate with a real this).
extern "C" const char* apkbridge_run_lifecycle(const char* dexPath, const char* appClass,
                                               const char* mode) {
    try {
        Runtime rt; buildRuntime(rt, dexPath, true);   // load all classes*.dex
        Interpreter vm(rt); configureApp(vm, dexPath);
        ExecutionMode m = (mode && std::string(mode) == "analysis")
                          ? ExecutionMode::ANALYSIS : ExecutionMode::FUNCTIONAL;
        RunResult r = vm.runLifecycle(appClass, m);
        std::string kind, value, extra;
        switch (r.kind) {
            case RunResult::VOID: kind="void"; break;
            case RunResult::INT: kind="int"; value=std::to_string(r.i); break;
            case RunResult::REF: kind="ref"; value=std::to_string(r.ref); break;
            case RunResult::EXCEPTION: kind="exception"; value=r.exceptionType; extra=r.message; break;
            case RunResult::UNSUPPORTED: kind="unsupported"; value=r.message; break;
        }
        return dup("{\"kind\":"+q(kind)+",\"value\":"+q(value)+",\"extra\":"+q(extra)+
                   ",\"mode\":"+q(modeName(m))+",\"trace\":"+vm.trace().toJson()+"}");
    } catch (const std::exception& e) {
        return dup(std::string("{\"kind\":\"error\",\"value\":")+q(e.what())+",\"extra\":\"\"}");
    }
}

extern "C" const char* apkbridge_install_commit(const char* sandboxDir, const char* stagingDexDir) {
    if (!sandboxDir || !stagingDexDir)
        return dup("{\"ok\":false,\"state\":\"\",\"error\":\"invalid install path\"}");
    InstallResult prepared = InstallTxn::prepare(sandboxDir, stagingDexDir);
    if (!prepared.ok)
        return dup(std::string("{\"ok\":false,\"state\":")+q(prepared.state)+",\"error\":"+q(prepared.message)+"}");
    InstallResult r = InstallTxn::commit(sandboxDir, 0);
    return dup(std::string("{\"ok\":")+(r.ok?"true":"false")+",\"state\":"+q(r.state)+",\"error\":"+q(r.message)+"}");
}
extern "C" const char* apkbridge_install_recover(const char* sandboxDir) {
    InstallResult r = InstallTxn::recover(sandboxDir);
    return dup(std::string("{\"ok\":")+(r.ok?"true":"false")+",\"state\":"+q(r.state)+",\"note\":"+q(r.message)+"}");
}

extern "C" const char* apkbridge_inspect_dex(const char* dexPath) {
    try {
        DexFile dex = DexFile::fromPath(dexPath);
        return dup("{\"classes\":"+std::to_string(dex.classes().size())+
                   ",\"methods\":"+std::to_string(dex.methodCount())+
                   ",\"strings\":"+std::to_string(dex.stringCount())+"}");
    } catch (const std::exception& e) { return dup(std::string("{\"error\":")+q(e.what())+"}"); }
}

extern "C" void apkbridge_free(const char* s) { std::free((void*)s); }
