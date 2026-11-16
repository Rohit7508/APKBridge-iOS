// APKBridge runtime :: Framework Method Registry + shared value/heap model.
// (header-only, C++17)
//
// The Dalvik dispatcher consults this registry BEFORE reporting an external
// method unsupported. Each registered signature is one of:
//   NO_OP               — a verified no-op correctly models the method
//   MODELED             — real modeled behavior (Context, Log, Bundle, Object)
//   ANALYSIS_SUBSTITUTE — a whitelisted no-op allowed ONLY in Analysis mode
// Anything not registered (or an ANALYSIS_SUBSTITUTE in Functional mode) is
// reported as an explicit Category-C diagnostic by the caller — never a silent
// success. Signature key format matches DexFile::methodRefName:
//   "Lpkg/Class;->name(shorty)"
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <array>
#include <algorithm>
#include <sstream>
#include <filesystem>
#include <system_error>

namespace apkbridge {

// ---- shared value + heap model (used by interpreter and handlers) ---------
struct Value {
    int32_t i = 0; uint32_t ref = 0; bool isRef = false;
    static Value Int(int32_t v){ Value x; x.i=v; return x; }
    static Value Ref(uint32_t r){ Value x; x.ref=r; x.isRef=true; return x; }
};

struct HeapObj {
    uint32_t typeIdx = 0;
    std::string klass;          // descriptor for framework-created objects
    std::string nativeKind;     // "", "context", "bundle"
    bool isArray = false;
    bool isString = false;
    std::vector<int32_t> arr;   // primitive int array
    std::vector<Value> oarr;    // object (reference) array
    std::vector<Value> list;    // java.util.ArrayList elements
    std::string str;            // java.lang.String / StringBuilder buffer
    std::unordered_map<std::string, Value> fields;    // instance fields, keyed "Lcls;->name"
    std::unordered_map<std::string, Value> kv;        // Bundle int/ref values
    std::unordered_map<std::string, std::string> kvs; // Bundle string values
    // ordered map model (HashMap/LinkedHashMap): parallel vectors preserve
    // insertion order; keys stored by their string form (String keys) so
    // lookup/replace/remove are correct for the common case.
    std::vector<std::string> mapKeys;
    std::vector<Value> mapVals;
    std::vector<bool> mapValNull;
};

enum class ExecutionMode { ANALYSIS, FUNCTIONAL };
inline const char* modeName(ExecutionMode m){ return m==ExecutionMode::ANALYSIS?"analysis":"functional"; }

enum class FwCategory { NO_OP, MODELED, ANALYSIS_SUBSTITUTE };
inline const char* catName(FwCategory c){
    switch(c){case FwCategory::NO_OP:return "no-op";
              case FwCategory::MODELED:return "modeled";
              default:return "analysis-substitute";} }

// ---- host heap interface exposed to handlers ------------------------------
struct HostHeap {
    virtual uint32_t newObject(const std::string& klass, const std::string& nativeKind="") = 0;
    virtual uint32_t newString(const std::string& s) = 0;
    virtual std::string stringOf(uint32_t ref) = 0;
    virtual HeapObj* obj(uint32_t ref) = 0;  // nullptr for null/invalid
    // The single modeled application Context — same ref on every call (identity).
    virtual uint32_t applicationContext() = 0;
    // Android storage / app identity (sandboxed per imported app).
    virtual std::string packageName() = 0;
    virtual std::string storageRoot() = 0;              // controlled per-app root
    virtual uint32_t sharedPreferences(const std::string& name) = 0; // cached + loaded
    virtual void prefsPersist(uint32_t prefsRef) = 0;   // flush to disk
    virtual ~HostHeap() = default;
};

// ---- execution trace ------------------------------------------------------
struct TraceEntry {
    std::string kind;      // "framework" | "stop"
    std::string signature;
    std::string category;  // no-op | modeled | analysis-substitute
    bool simulated = false;// true = did not reflect real framework computation
    std::string outcome;   // short result description
    std::string detail;    // extra info / stop reason
};

struct ExecutionTrace {
    std::vector<TraceEntry> entries;
    std::vector<std::string> logcat;   // messages captured by Log.*
    void clear(){ entries.clear(); logcat.clear(); }
    void framework(const std::string& sig, FwCategory cat, bool simulated,
                   const std::string& outcome){
        entries.push_back({"framework", sig, catName(cat), simulated, outcome, ""});
    }
    void stop(const std::string& detail){
        entries.push_back({"stop", "", "", false, "", detail});
    }
    static std::string esc(const std::string& s){
        std::string o; for(char c:s){ if(c=='"'||c=='\\'){o+='\\';o+=c;}
            else if(c=='\n')o+="\\n"; else if((unsigned char)c<0x20){} else o+=c; } return o; }
    std::string toJson() const {
        std::ostringstream js; js<<"{\"entries\":[";
        for(size_t i=0;i<entries.size();++i){ const auto&e=entries[i];
            js<<(i?",":"")<<"{\"kind\":\""<<e.kind<<"\",\"signature\":\""<<esc(e.signature)
              <<"\",\"category\":\""<<e.category<<"\",\"simulated\":"<<(e.simulated?"true":"false")
              <<",\"outcome\":\""<<esc(e.outcome)<<"\",\"detail\":\""<<esc(e.detail)<<"\"}"; }
        js<<"],\"logcat\":[";
        for(size_t i=0;i<logcat.size();++i) js<<(i?",":"")<<"\""<<esc(logcat[i])<<"\"";
        js<<"]}"; return js.str();
    }
};

// ---- registry -------------------------------------------------------------
struct FwOutcome {
    enum K { VOID, INT, REF, UNHANDLED, ERROR } kind = UNHANDLED;
    int32_t i = 0; uint32_t ref = 0; std::string message;
    static FwOutcome Void(){ return {VOID,0,0,""}; }
    static FwOutcome Int(int32_t v){ return {INT,v,0,""}; }
    static FwOutcome Ref(uint32_t r){ return {REF,0,r,""}; }
};

using FwHandler = std::function<FwOutcome(HostHeap&, const std::vector<Value>&,
                                          ExecutionTrace&, ExecutionMode)>;
struct FwEntry { FwCategory cat; FwHandler fn; std::string note; };

class FrameworkRegistry {
public:
    FrameworkRegistry(){ registerDefaults(); }

    const FwEntry* find(const std::string& sig) const {
        auto it = table_.find(sig); return it==table_.end()?nullptr:&it->second;
    }
    std::vector<std::string> signatures() const {
        std::vector<std::string> v; v.reserve(table_.size());
        for (auto& kv : table_) v.push_back(kv.first);
        return v;
    }
    // (signature, category, note) for every registered handler — coverage report.
    std::vector<std::array<std::string,3>> coverage() const {
        std::vector<std::array<std::string,3>> v;
        for (auto& kv : table_) v.push_back({kv.first, catName(kv.second.cat), kv.second.note});
        std::sort(v.begin(), v.end());
        return v;
    }

    // Returns the outcome; UNHANDLED if no entry OR an analysis-substitute was
    // requested in functional mode. Records a trace entry when it runs.
    FwOutcome dispatch(const std::string& sig, HostHeap& heap,
                       const std::vector<Value>& args, ExecutionTrace& tr,
                       ExecutionMode mode) const {
        auto it = table_.find(sig);
        if (it == table_.end()) return {};                       // UNHANDLED
        const FwEntry& e = it->second;
        if (mode == ExecutionMode::FUNCTIONAL && e.cat == FwCategory::ANALYSIS_SUBSTITUTE)
            return {};                                           // not allowed → UNHANDLED
        FwOutcome o = e.fn(heap, args, tr, mode);
        bool simulated = (e.cat != FwCategory::MODELED);
        std::string out;
        switch (o.kind) {
            case FwOutcome::VOID: out="void"; break;
            case FwOutcome::INT: out="int "+std::to_string(o.i); break;
            case FwOutcome::REF: out="ref "+std::to_string(o.ref); break;
            case FwOutcome::ERROR: out="error "+o.message; break;
            default: out="unhandled"; break;
        }
        tr.framework(sig, e.cat, simulated, out);
        return o;
    }

private:
    std::unordered_map<std::string, FwEntry> table_;
    void add(const std::string& sig, FwCategory c, FwHandler fn, const std::string& note){
        table_[sig] = FwEntry{c, std::move(fn), note};
    }

    void registerDefaults() {
        // --- java.lang.Object: identity + init -----------------------------
        add("Ljava/lang/Object;-><init>(V)", FwCategory::NO_OP,
            [](HostHeap&, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Void(); }, "Object ctor");
        add("Ljava/lang/Object;->hashCode(I)", FwCategory::MODELED,
            [](HostHeap&, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Int(a.empty()?0:(int32_t)a[0].ref); }, "identity hash = heap ref");

        // --- lifecycle base classes: verified no-ops -----------------------
        for (const char* cls : {"Landroid/app/Application;",
                                "Landroid/content/ContextWrapper;",
                                "Landroid/content/Context;"}) {
            add(std::string(cls)+"-><init>(V)", FwCategory::NO_OP,
                [](HostHeap&, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
                    return FwOutcome::Void(); }, "ctor no-op");
        }
        add("Landroid/app/Application;->onCreate(V)", FwCategory::NO_OP,
            [](HostHeap&, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Void(); }, "base Application.onCreate is empty");
        add("Landroid/app/Application;->onTerminate(V)", FwCategory::NO_OP,
            [](HostHeap&, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Void(); }, "base no-op");
        // analysis-only substitute: skipped in ANALYSIS, unsupported in FUNCTIONAL
        add("Landroid/app/Application;->registerActivityLifecycleCallbacks(VL)",
            FwCategory::ANALYSIS_SUBSTITUTE,
            [](HostHeap&, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Void(); },
            "not modeled; skipped for exploration in analysis mode only");

        // --- Context: modeled application context --------------------------
        auto getCtx = [](HostHeap& h, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
            return FwOutcome::Ref(h.applicationContext()); };  // stable identity across calls
        add("Landroid/app/Application;->getApplicationContext(L)",
            FwCategory::MODELED, getCtx, "returns modeled app context");
        add("Landroid/content/ContextWrapper;->getApplicationContext(L)",
            FwCategory::MODELED, getCtx, "returns modeled app context");
        add("Landroid/content/Context;->getApplicationContext(L)",
            FwCategory::MODELED, getCtx, "returns modeled app context");

        // --- Log: modeled (records message, returns byte count like Android)
        for (const char* lvl : {"d","i","w","e","v"}) {
            add(std::string("Landroid/util/Log;->")+lvl+"(ILL)",
                FwCategory::MODELED,
                [lvl](HostHeap& h, const std::vector<Value>& a, ExecutionTrace& tr, ExecutionMode){
                    std::string tag = a.size()>0 ? h.stringOf(a[0].ref) : "";
                    std::string msg = a.size()>1 ? h.stringOf(a[1].ref) : "";
                    std::string line = std::string(lvl)+"/"+tag+": "+msg;
                    tr.logcat.push_back(line);
                    return FwOutcome::Int((int32_t)(tag.size()+msg.size())); },
                "logcat record");
        }

        // --- Bundle: modeled key/value store -------------------------------
        add("Landroid/os/Bundle;-><init>(V)", FwCategory::NO_OP,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(!a.empty()){ if(auto* o=h.obj(a[0].ref)) o->nativeKind="bundle"; }
                return FwOutcome::Void(); }, "Bundle ctor");
        add("Landroid/os/Bundle;->putInt(VLI)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=3){ if(auto* o=h.obj(a[0].ref)) o->kv[h.stringOf(a[1].ref)]=Value::Int(a[2].i); }
                return FwOutcome::Void(); }, "Bundle.putInt");
        add("Landroid/os/Bundle;->getInt(IL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ auto it=o->kv.find(h.stringOf(a[1].ref));
                    if(it!=o->kv.end()) return FwOutcome::Int(it->second.i); } }
                return FwOutcome::Int(0); }, "Bundle.getInt");
        add("Landroid/os/Bundle;->putString(VLL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=3){ if(auto* o=h.obj(a[0].ref)) o->kvs[h.stringOf(a[1].ref)]=h.stringOf(a[2].ref); }
                return FwOutcome::Void(); }, "Bundle.putString");
        add("Landroid/os/Bundle;->getString(LL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ auto it=o->kvs.find(h.stringOf(a[1].ref));
                    if(it!=o->kvs.end()) return FwOutcome::Ref(h.newString(it->second)); } }
                return FwOutcome::Ref(0); }, "Bundle.getString");

        // --- java.util.ArrayList: modeled element list --------------------
        add("Ljava/util/ArrayList;-><init>(V)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(!a.empty()){ if(auto* o=h.obj(a[0].ref)) o->nativeKind="list"; }
                return FwOutcome::Void(); }, "ArrayList ctor");
        add("Ljava/util/ArrayList;->add(ZL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)) o->list.push_back(a[1]); }
                return FwOutcome::Int(1); }, "ArrayList.add -> true");
        add("Ljava/util/ArrayList;->size(I)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(!a.empty()){ if(auto* o=h.obj(a[0].ref)) return FwOutcome::Int((int32_t)o->list.size()); }
                return FwOutcome::Int(0); }, "ArrayList.size");
        add("Ljava/util/ArrayList;->get(LI)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ int ix=a[1].i;
                    if(ix>=0 && (size_t)ix<o->list.size()) return FwOutcome::Ref(o->list[ix].ref); } }
                return FwOutcome::Ref(0); }, "ArrayList.get");
        add("Ljava/util/ArrayList;->isEmpty(Z)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(!a.empty()){ if(auto* o=h.obj(a[0].ref)) return FwOutcome::Int(o->list.empty()?1:0); }
                return FwOutcome::Int(1); }, "ArrayList.isEmpty");

        registerMaps();
        registerStringBuilder();
        registerString();
        registerStorage();
        registerPrefs();
    }

    // Context storage + java.io.File (sandboxed under the app's storageRoot).
    void registerStorage() {
        auto fileObj = [](HostHeap& h, const std::string& path){
            uint32_t r = h.newObject("Ljava/io/File;", "file");
            if (auto* o = h.obj(r)) o->str = path;
            return r; };
        auto cacheDir = [fileObj](HostHeap& h, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
            return FwOutcome::Ref(fileObj(h, h.storageRoot()+"/cache")); };
        auto filesDir = [fileObj](HostHeap& h, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
            return FwOutcome::Ref(fileObj(h, h.storageRoot()+"/files")); };
        auto pkgName = [](HostHeap& h, const std::vector<Value>&, ExecutionTrace&, ExecutionMode){
            return FwOutcome::Ref(h.newString(h.packageName())); };
        for (const char* cls : {"Landroid/app/Application;","Landroid/content/ContextWrapper;","Landroid/content/Context;"}) {
            std::string c(cls);
            add(c+"->getCacheDir(L)", FwCategory::MODELED, cacheDir, "modeled cache dir (File)");
            add(c+"->getFilesDir(L)", FwCategory::MODELED, filesDir, "modeled files dir (File)");
            add(c+"->getPackageName(L)", FwCategory::MODELED, pkgName, "app package name");
        }
        const char* F = "Ljava/io/File;";
        add(std::string(F)+"-><init>(VL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ o->nativeKind="file"; o->str=h.stringOf(a[1].ref); } }
                return FwOutcome::Void(); }, "new File(String)");
        add(std::string(F)+"-><init>(VLL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=3){ if(auto* o=h.obj(a[0].ref)){ o->nativeKind="file";
                    std::string parent = h.obj(a[1].ref)?h.obj(a[1].ref)->str:h.stringOf(a[1].ref);
                    o->str = parent + "/" + h.stringOf(a[2].ref); } }
                return FwOutcome::Void(); }, "new File(File,String)");
        auto pathStr = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            std::string p = (!a.empty() && h.obj(a[0].ref))?h.obj(a[0].ref)->str:"";
            return FwOutcome::Ref(h.newString(p)); };
        add(std::string(F)+"->getAbsolutePath(L)", FwCategory::MODELED, pathStr, "File.getAbsolutePath");
        add(std::string(F)+"->getPath(L)", FwCategory::MODELED, pathStr, "File.getPath");
        add(std::string(F)+"->toString(L)", FwCategory::MODELED, pathStr, "File.toString");
        // Every fs-touching op goes through containment against the app root.
        add(std::string(F)+"->exists(Z)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                std::string real; if(!containOf(h,a,real)) return FwOutcome::Int(0);
                return FwOutcome::Int(fileExists(real)?1:0); }, "File.exists (contained)");
        add(std::string(F)+"->mkdirs(Z)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                std::string real; if(!containOf(h,a,real)) return FwOutcome::Int(0);  // escape -> fail
                return FwOutcome::Int(mkdirs(real)?1:0); }, "File.mkdirs (contained)");
        add(std::string(F)+"->isDirectory(Z)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                std::string real; if(!containOf(h,a,real)) return FwOutcome::Int(0);
                return FwOutcome::Int(isDir(real)?1:0); }, "File.isDirectory (contained)");
    }

    // Resolve the File receiver's path, contained inside the app storage root.
    static bool containOf(HostHeap& h, const std::vector<Value>& a, std::string& out){
        std::string p=(!a.empty()&&h.obj(a[0].ref))?h.obj(a[0].ref)->str:"";
        return containedHostPath(h.storageRoot(), p, out);
    }

    void registerPrefs() {
        // Context.getSharedPreferences(name, mode) -> SharedPreferences (cached/loaded)
        auto getSP = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            std::string name = a.size()>1 ? h.stringOf(a[1].ref) : "default";
            return FwOutcome::Ref(h.sharedPreferences(name)); };
        for (const char* cls : {"Landroid/app/Application;","Landroid/content/ContextWrapper;","Landroid/content/Context;"})
            add(std::string(cls)+"->getSharedPreferences(LLI)", FwCategory::MODELED, getSP, "getSharedPreferences");

        const char* SP = "Landroid/content/SharedPreferences;";
        add(std::string(SP)+"->getString(LLL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ auto it=o->kvs.find(h.stringOf(a[1].ref));
                    if(it!=o->kvs.end()) return FwOutcome::Ref(h.newString(it->second)); } }
                return FwOutcome::Ref(a.size()>2?a[2].ref:0); }, "prefs.getString(default)");
        add(std::string(SP)+"->getInt(ILI)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ auto it=o->kv.find("i:"+h.stringOf(a[1].ref));
                    if(it!=o->kv.end()) return FwOutcome::Int(it->second.i); } }
                return FwOutcome::Int(a.size()>2?a[2].i:0); }, "prefs.getInt(default)");
        add(std::string(SP)+"->getBoolean(ZLZ)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ auto it=o->kv.find("b:"+h.stringOf(a[1].ref));
                    if(it!=o->kv.end()) return FwOutcome::Int(it->second.i); } }
                return FwOutcome::Int(a.size()>2?a[2].i:0); }, "prefs.getBoolean(default)");
        add(std::string(SP)+"->contains(ZL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ std::string k=h.stringOf(a[1].ref);
                    bool c = o->kvs.count(k)||o->kv.count("i:"+k)||o->kv.count("b:"+k);
                    return FwOutcome::Int(c?1:0); } }
                return FwOutcome::Int(0); }, "prefs.contains");
        add(std::string(SP)+"->edit(L)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                uint32_t e=h.newObject("Landroid/content/SharedPreferences$Editor;","editor");
                if(auto* o=h.obj(e)) o->fields["__prefs"]=Value::Ref(a.empty()?0:a[0].ref);
                return FwOutcome::Ref(e); }, "prefs.edit");

        const char* ED = "Landroid/content/SharedPreferences$Editor;";
        auto self = [](const std::vector<Value>& a){ return FwOutcome::Ref(a.empty()?0:a[0].ref); };
        add(std::string(ED)+"->putString(LLL)", FwCategory::MODELED,
            [self](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=3){ if(auto* o=h.obj(a[0].ref)) o->kvs[h.stringOf(a[1].ref)]=h.stringOf(a[2].ref); }
                return self(a); }, "editor.putString");
        add(std::string(ED)+"->putInt(LLI)", FwCategory::MODELED,
            [self](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=3){ if(auto* o=h.obj(a[0].ref)) o->kv["i:"+h.stringOf(a[1].ref)]=Value::Int(a[2].i); }
                return self(a); }, "editor.putInt");
        add(std::string(ED)+"->putBoolean(LLZ)", FwCategory::MODELED,
            [self](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=3){ if(auto* o=h.obj(a[0].ref)) o->kv["b:"+h.stringOf(a[1].ref)]=Value::Int(a[2].i?1:0); }
                return self(a); }, "editor.putBoolean");
        add(std::string(ED)+"->remove(LL)", FwCategory::MODELED,
            [self](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)) o->mapKeys.push_back(h.stringOf(a[1].ref)); }
                return self(a); }, "editor.remove");
        add(std::string(ED)+"->clear(L)", FwCategory::MODELED,
            [self](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(!a.empty()){ if(auto* o=h.obj(a[0].ref)) o->str="clear"; }
                return self(a); }, "editor.clear");
        auto flush = [](HostHeap& h, const std::vector<Value>& a){
            if(a.empty()) return;
            auto* e=h.obj(a[0].ref); if(!e) return;
            auto pit=e->fields.find("__prefs"); if(pit==e->fields.end()) return;
            uint32_t pr=pit->second.ref; auto* p=h.obj(pr); if(!p) return;
            if(e->str=="clear"){ p->kv.clear(); p->kvs.clear(); }
            for(auto& k : e->mapKeys){ p->kvs.erase(k); p->kv.erase("i:"+k); p->kv.erase("b:"+k); }
            for(auto& kv : e->kvs) p->kvs[kv.first]=kv.second;
            for(auto& kv : e->kv) p->kv[kv.first]=kv.second;
            h.prefsPersist(pr);
            e->kv.clear(); e->kvs.clear(); e->mapKeys.clear(); e->str.clear(); };
        add(std::string(ED)+"->apply(V)", FwCategory::MODELED,
            [flush](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                flush(h,a); return FwOutcome::Void(); }, "editor.apply");
        add(std::string(ED)+"->commit(Z)", FwCategory::MODELED,
            [flush](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                flush(h,a); return FwOutcome::Int(1); }, "editor.commit");
    }

public:
    // --- small host-fs helpers (sandbox enforced by the caller's storageRoot) --
    // Centralized containment: resolve a guest path (absolute or relative to
    // root), canonicalize away ".." and symlinks, and accept ONLY if the result
    // is the root or strictly under it. Rejects escapes, absolute paths outside
    // root, and symlink targets leaving the sandbox.
    static bool containedHostPath(const std::string& root, const std::string& guest, std::string& out){
        namespace fs = std::filesystem; std::error_code e;
        if (root.empty()) return false;
        fs::path rootC = fs::weakly_canonical(fs::absolute(root, e), e);
        fs::path g(guest);
        fs::path full = g.is_absolute() ? g : (fs::path(root) / g);
        fs::path gc = fs::weakly_canonical(full, e);
        std::string rs = rootC.generic_string(), gs = gc.generic_string();
        if (gs == rs) { out = gc.string(); return true; }
        if (gs.size() > rs.size() && gs.compare(0, rs.size(), rs) == 0 && gs[rs.size()] == '/') {
            out = gc.string(); return true;
        }
        return false;
    }
    // SharedPreferences name -> safe single path segment. INJECTIVE: distinct
    // names never map to the same file (percent-encode every char outside
    // [A-Za-z0-9_-], including '.', '/', '%'), so "a/b" and "a_b" stay distinct
    // and no "."/".." segment can form. Length-capped (over-long -> hashed tail).
    static std::string safeName(const std::string& name){
        static const char* hex = "0123456789ABCDEF";
        std::string s;
        for (unsigned char c : name) {
            bool ok = (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-';
            if (ok) s.push_back((char)c);
            else { s.push_back('%'); s.push_back(hex[c>>4]); s.push_back(hex[c&0xF]); }
        }
        if (s.empty()) s = "default";
        if (s.size() > 180) {                       // keep filenames bounded, still injective
            uint64_t h = 1469598103934665603ULL;    // FNV-1a over the full name
            for (unsigned char c : name) { h ^= c; h *= 1099511628211ULL; }
            char buf[20]; std::snprintf(buf, sizeof buf, "%016llx", (unsigned long long)h);
            s = s.substr(0, 160) + "~" + buf;
        }
        return s;
    }

    static bool fileExists(const std::string& p){ std::error_code e; return std::filesystem::exists(p,e); }
    static bool isDir(const std::string& p){ std::error_code e; return std::filesystem::is_directory(p,e); }
    static bool mkdirs(const std::string& p){ std::error_code e; std::filesystem::create_directories(p,e); return !e; }

private:
    // key form: String keys compare by content; other objects by identity ref.
    static std::string keyForm(HostHeap& h, uint32_t ref){
        if (auto* o = h.obj(ref)) { if (o->isString) return "s:" + o->str; }
        return "@" + std::to_string(ref);
    }
    static int mapFind(HeapObj* o, const std::string& k){
        for (size_t i=0;i<o->mapKeys.size();++i) if (o->mapKeys[i]==k) return (int)i;
        return -1;
    }

    // HashMap / LinkedHashMap / Map — ordered model (insertion order preserved,
    // null values supported, replace/lookup/remove/size correct for String keys).
    void registerMaps() {
        auto put = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(a.size()<3) return FwOutcome::Ref(0);
            auto* o=h.obj(a[0].ref); if(!o) return FwOutcome::Ref(0);
            std::string k=keyForm(h,a[1].ref); int i=mapFind(o,k);
            uint32_t prev=0;   // value ref 0 == null (null values are supported)
            if(i>=0){ prev=o->mapVals[i].ref; o->mapVals[i]=a[2]; o->mapValNull[i]=(a[2].ref==0); }
            else { o->mapKeys.push_back(k); o->mapVals.push_back(a[2]); o->mapValNull.push_back(a[2].ref==0); }
            return FwOutcome::Ref(prev); };
        auto get = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(a.size()<2) return FwOutcome::Ref(0);
            auto* o=h.obj(a[0].ref); if(!o) return FwOutcome::Ref(0);
            int i=mapFind(o,keyForm(h,a[1].ref));
            return (i>=0)?FwOutcome::Ref(o->mapVals[i].ref):FwOutcome::Ref(0); };
        auto has = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(a.size()<2) return FwOutcome::Int(0);
            auto* o=h.obj(a[0].ref); if(!o) return FwOutcome::Int(0);
            return FwOutcome::Int(mapFind(o,keyForm(h,a[1].ref))>=0?1:0); };
        auto rem = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(a.size()<2) return FwOutcome::Ref(0);
            auto* o=h.obj(a[0].ref); if(!o) return FwOutcome::Ref(0);
            int i=mapFind(o,keyForm(h,a[1].ref)); if(i<0) return FwOutcome::Ref(0);
            uint32_t v=o->mapVals[i].ref;
            o->mapKeys.erase(o->mapKeys.begin()+i); o->mapVals.erase(o->mapVals.begin()+i);
            o->mapValNull.erase(o->mapValNull.begin()+i); return FwOutcome::Ref(v); };
        auto size = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            auto* o=a.empty()?nullptr:h.obj(a[0].ref); return FwOutcome::Int(o?(int32_t)o->mapKeys.size():0); };
        auto empt = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            auto* o=a.empty()?nullptr:h.obj(a[0].ref); return FwOutcome::Int((o&&!o->mapKeys.empty())?0:1); };
        auto clr = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(auto* o=a.empty()?nullptr:h.obj(a[0].ref)){ o->mapKeys.clear(); o->mapVals.clear(); o->mapValNull.clear(); }
            return FwOutcome::Void(); };
        for (const char* cls : {"Ljava/util/HashMap;","Ljava/util/LinkedHashMap;"}) {
            add(std::string(cls)+"-><init>(V)", FwCategory::MODELED,
                [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                    if(!a.empty()){ if(auto* o=h.obj(a[0].ref)) o->nativeKind="map"; }
                    return FwOutcome::Void(); }, "map ctor");
        }
        for (const char* cls : {"Ljava/util/HashMap;","Ljava/util/LinkedHashMap;","Ljava/util/Map;"}) {
            std::string c(cls);
            add(c+"->put(LLL)", FwCategory::MODELED, put, "map.put");
            add(c+"->get(LL)", FwCategory::MODELED, get, "map.get");
            add(c+"->containsKey(ZL)", FwCategory::MODELED, has, "map.containsKey");
            add(c+"->remove(LL)", FwCategory::MODELED, rem, "map.remove");
            add(c+"->size(I)", FwCategory::MODELED, size, "map.size");
            add(c+"->isEmpty(Z)", FwCategory::MODELED, empt, "map.isEmpty");
            add(c+"->clear(V)", FwCategory::MODELED, clr, "map.clear");
        }
    }

    void registerStringBuilder() {
        const char* SB = "Ljava/lang/StringBuilder;";
        add(std::string(SB)+"-><init>(V)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(!a.empty()){ if(auto* o=h.obj(a[0].ref)){ o->nativeKind="sb"; o->str.clear(); } }
                return FwOutcome::Void(); }, "StringBuilder()");
        add(std::string(SB)+"-><init>(VL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)){ o->nativeKind="sb"; o->str=h.stringOf(a[1].ref); } }
                return FwOutcome::Void(); }, "StringBuilder(String)");
        auto appendStr = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)) o->str+=h.stringOf(a[1].ref); }
            return FwOutcome::Ref(a.empty()?0:a[0].ref); };
        auto appendInt = [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
            if(a.size()>=2){ if(auto* o=h.obj(a[0].ref)) o->str+=std::to_string(a[1].i); }
            return FwOutcome::Ref(a.empty()?0:a[0].ref); };
        add(std::string(SB)+"->append(LL)", FwCategory::MODELED, appendStr, "SB.append(String/Object)");
        add(std::string(SB)+"->append(LI)", FwCategory::MODELED, appendInt, "SB.append(int)");
        add(std::string(SB)+"->toString(L)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                std::string s=a.empty()?"":(h.obj(a[0].ref)?h.obj(a[0].ref)->str:"");
                return FwOutcome::Ref(h.newString(s)); }, "SB.toString");
        add(std::string(SB)+"->length(I)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                auto* o=a.empty()?nullptr:h.obj(a[0].ref); return FwOutcome::Int(o?(int32_t)o->str.size():0); }, "SB.length");
    }

    void registerString() {
        add("Ljava/lang/String;->equals(ZL)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                if(a.size()<2) return FwOutcome::Int(0);
                auto* x=h.obj(a[0].ref); auto* y=h.obj(a[1].ref);
                bool eq = x&&y&&x->isString&&y->isString && x->str==y->str;
                return FwOutcome::Int(eq?1:0); }, "String.equals");
        add("Ljava/lang/String;->hashCode(I)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                int32_t hc=0; if(!a.empty()){ if(auto* o=h.obj(a[0].ref))
                    for(unsigned char ch : o->str) hc = hc*31 + (int32_t)ch; }
                return FwOutcome::Int(hc); }, "String.hashCode (Java semantics)");
        add("Ljava/lang/String;->length(I)", FwCategory::MODELED,
            [](HostHeap& h, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                auto* o=a.empty()?nullptr:h.obj(a[0].ref); return FwOutcome::Int(o?(int32_t)o->str.size():0); }, "String.length");
        add("Ljava/lang/String;->toString(L)", FwCategory::MODELED,
            [](HostHeap&, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Ref(a.empty()?0:a[0].ref); }, "String.toString = this");
        add("Ljava/lang/Object;->equals(ZL)", FwCategory::MODELED,
            [](HostHeap&, const std::vector<Value>& a, ExecutionTrace&, ExecutionMode){
                return FwOutcome::Int((a.size()>=2 && a[0].ref==a[1].ref)?1:0); }, "Object.equals = identity");
    }
};

} // namespace apkbridge
