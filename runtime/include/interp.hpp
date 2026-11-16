// APKBridge runtime :: Dalvik interpreter (header-only, C++17)
// Interpreter-first, no JIT. Resolves classes/methods across ALL loaded DEX
// files (loader.hpp), consults the FrameworkRegistry (framework.hpp) for
// external methods, and records an execution trace. Two modes: ANALYSIS and
// FUNCTIONAL.
//
// Correctness (v0.6):
//  - A method with no bytecode NEVER returns silent success: native → explicit
//    JNI-unsupported error, abstract → explicit error, otherwise no-bytecode error.
//  - Instance/static fields are keyed by fully-qualified "Lcls;->name" so the
//    same field resolves identically across DEX files.
//  - getApplicationContext() returns one stable modeled Context (identity).
#pragma once
#include "dex.hpp"
#include "loader.hpp"
#include "framework.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <fstream>
#include <filesystem>

namespace apkbridge {

struct RunResult {
    enum Kind { VOID, INT, REF, EXCEPTION, UNSUPPORTED } kind = VOID;
    int32_t i = 0;
    uint32_t ref = 0;
    std::string message;
    std::string exceptionType;
};

static constexpr uint32_t ACC_STATIC = 0x8, ACC_NATIVE = 0x100, ACC_ABSTRACT = 0x400;

class Interpreter : public HostHeap {
public:
    explicit Interpreter(const Runtime& rt) : rt_(rt) { heap_.emplace_back(); } // 0 = null

    void setMode(ExecutionMode m) { mode_ = m; }
    void setPackage(const std::string& p) { package_ = p; }
    void setStorageRoot(const std::string& r) { storageRoot_ = r; }
    ExecutionMode mode() const { return mode_; }
    const ExecutionTrace& trace() const { return trace_; }
    const FrameworkRegistry& registry() const { return registry_; }

    RunResult run(const std::string& clsDesc, const std::string& name,
                  const std::string& shorty, const std::vector<int32_t>& args) {
        return run(clsDesc, name, shorty, args, mode_);
    }
    RunResult run(const std::string& clsDesc, const std::string& name,
                  const std::string& shorty, const std::vector<int32_t>& args,
                  ExecutionMode mode) {
        mode_ = mode; trace_.clear();
        ResolvedMethod rm = rt_.resolveMethod(clsDesc, name, shorty);
        if (!rm.found()) { RunResult r; r.kind = RunResult::UNSUPPORTED;
            r.message = "method not found: " + clsDesc + "->" + name + "(" + shorty + ")"; return r; }
        std::vector<Value> a; for (int v : args) a.push_back(Value::Int(v));
        return invoke(*rm.dex, *rm.method, a);
    }

    RunResult runLifecycle(const std::string& appClass, ExecutionMode mode) {
        mode_ = mode; trace_.clear();
        uint32_t self = newObject(appClass);
        ResolvedMethod ctor = rt_.resolveMethod(appClass, "<init>", "V");
        if (ctor.found() && ctor.method->codeOff != 0) {
            std::vector<Value> a{ Value::Ref(self) };
            RunResult r = invoke(*ctor.dex, *ctor.method, a);
            if (r.kind == RunResult::UNSUPPORTED || r.kind == RunResult::EXCEPTION) return r;
        }
        ResolvedMethod oc = rt_.resolveVirtual(appClass, appClass, "onCreate", "V");
        if (!oc.found()) { RunResult r; r.kind = RunResult::UNSUPPORTED;
            r.message = "no onCreate()V resolvable from " + appClass; return r; }
        std::vector<Value> a{ Value::Ref(self) };
        return invoke(*oc.dex, *oc.method, a);
    }

    const std::string& heapString(uint32_t ref) const {
        static std::string empty; if (ref == 0 || ref >= heap_.size()) return empty;
        return heap_[ref].str;
    }

    // HostHeap -------------------------------------------------------------
    uint32_t newObject(const std::string& klass, const std::string& nativeKind="") override {
        HeapObj o; o.klass = klass; o.nativeKind = nativeKind; return alloc(std::move(o));
    }
    uint32_t newString(const std::string& s) override {
        HeapObj o; o.isString = true; o.str = s; o.klass = "Ljava/lang/String;"; return alloc(std::move(o));
    }
    std::string stringOf(uint32_t ref) override {
        return (ref && ref < heap_.size()) ? heap_[ref].str : std::string();
    }
    HeapObj* obj(uint32_t ref) override {
        return (ref && ref < heap_.size()) ? &heap_[ref] : nullptr;
    }
    uint32_t applicationContext() override {
        if (appCtxRef_ == 0) appCtxRef_ = newObject("Landroid/content/Context;", "context");
        return appCtxRef_;
    }
    std::string packageName() override { return package_.empty() ? "unknown.app" : package_; }
    std::string storageRoot() override {
        if (storageRoot_.empty())
            storageRoot_ = (std::filesystem::temp_directory_path() /
                            ("apkbridge-" + packageName())).string();
        return storageRoot_;
    }
    uint32_t sharedPreferences(const std::string& name) override {
        auto it = prefsCache_.find(name);
        if (it != prefsCache_.end()) return it->second;
        uint32_t r = newObject("Landroid/content/SharedPreferences;", "prefs");
        heap_[r].str = name;
        prefsLoad(r, name);              // load persisted values if present
        prefsCache_[name] = r;
        return r;
    }
    void prefsPersist(uint32_t prefsRef) override {
        HeapObj* o = obj(prefsRef); if (!o) return;
        std::string dir = storageRoot() + "/shared_prefs";
        std::error_code e; std::filesystem::create_directories(dir, e);
        std::ofstream f(dir + "/" + FrameworkRegistry::safeName(o->str) + ".prefs", std::ios::trunc);
        for (auto& kv : o->kvs) f << "S\t" << kv.first << "\t" << kv.second << "\n";
        for (auto& kv : o->kv)  f << "K\t" << kv.first << "\t" << kv.second.i << "\n";
    }

private:
    const Runtime& rt_;
    std::vector<HeapObj> heap_;
    std::unordered_map<std::string, Value> statics_;  // "Lcls;->name" -> value
    uint32_t appCtxRef_ = 0;
    std::string package_, storageRoot_;
    std::unordered_map<std::string, uint32_t> prefsCache_;
    // class-init state machine: UNINIT -> INITIALIZING -> INITIALIZED / FAILED
    enum class InitState { INITIALIZING, INITIALIZED, FAILED };
    std::unordered_map<std::string, InitState> initState_;
    std::unordered_map<std::string, std::string> initFailure_;  // FAILED reason
    int depth_ = 0;

    void prefsLoad(uint32_t ref, const std::string& name) {
        std::ifstream f(storageRoot() + "/shared_prefs/" + FrameworkRegistry::safeName(name) + ".prefs");
        if (!f) return;
        HeapObj* o = obj(ref); std::string line;
        while (std::getline(f, line)) {
            size_t t1 = line.find('\t'), t2 = line.rfind('\t');
            if (t1 == std::string::npos || t2 == t1) continue;
            std::string kind = line.substr(0, t1);
            std::string key = line.substr(t1 + 1, t2 - t1 - 1);
            std::string val = line.substr(t2 + 1);
            if (kind == "S") o->kvs[key] = val;
            else if (kind == "K") o->kv[key] = Value::Int(std::atoi(val.c_str()));
        }
    }

    // Run a class's <clinit> once before first use. Recursion-guarded; failures
    // propagate (never silently skipped).
    RunResult ensureInit(const std::string& cls) {
        RunResult ok;  // VOID
        if (cls.empty() || cls[0] != 'L') return ok;
        auto it = initState_.find(cls);
        if (it != initState_.end()) {
            if (it->second == InitState::INITIALIZED) return ok;
            if (it->second == InitState::INITIALIZING) return ok;   // re-entrant: its own init in progress
            // FAILED: re-use of a class whose <clinit> failed is an error (never silent OK)
            RunResult r; r.kind = RunResult::UNSUPPORTED;
            auto f = initFailure_.find(cls);
            r.message = "class initialization previously failed: " + cls +
                        (f != initFailure_.end() ? " (" + f->second + ")" : "");
            return r;
        }
        if (!rt_.findClass(cls)) { initState_[cls] = InitState::INITIALIZED; return ok; } // framework: nothing
        initState_[cls] = InitState::INITIALIZING;
        ResolvedMethod ci = rt_.resolveMethod(cls, "<clinit>", "V");
        RunResult r;
        if (ci.found() && ci.method->codeOff != 0) { std::vector<Value> none; r = invoke(*ci.dex, *ci.method, none); }
        if (r.kind == RunResult::UNSUPPORTED || r.kind == RunResult::EXCEPTION) {
            initState_[cls] = InitState::FAILED;
            initFailure_[cls] = r.message.empty() ? r.exceptionType : r.message;
            return r;   // propagate: class is NOT initialized
        }
        initState_[cls] = InitState::INITIALIZED;
        return r;
    }
    ExecutionMode mode_ = ExecutionMode::FUNCTIONAL;
    FrameworkRegistry registry_;
    ExecutionTrace trace_;

    uint32_t alloc(HeapObj o) { heap_.push_back(std::move(o)); return (uint32_t)heap_.size() - 1; }

    // Reject no-bytecode methods explicitly (never silent success).
    RunResult noCode(const Method& m) {
        RunResult r; r.kind = RunResult::UNSUPPORTED;
        std::string sig = m.classDesc + "->" + m.name + "(" + m.shorty + ")";
        if (m.accessFlags & ACC_NATIVE) r.message = "native (JNI) method not supported: " + sig;
        else if (m.accessFlags & ACC_ABSTRACT) r.message = "abstract method has no implementation: " + sig;
        else r.message = "method has no bytecode: " + sig;
        trace_.stop(r.message);
        return r;
    }

    RunResult invoke(const DexFile& dex, const Method& m, std::vector<Value>& incoming) {
        if (++depth_ > 256) { --depth_; RunResult r; r.kind = RunResult::UNSUPPORTED;
            r.message = "call depth exceeded"; return r; }
        { RunResult ir = ensureInit(m.classDesc);   // run <clinit> before first use
          if (ir.kind == RunResult::UNSUPPORTED || ir.kind == RunResult::EXCEPTION) { --depth_; return ir; } }
        CodeItem ci = dex.readCode(m.codeOff);
        if (!ci.valid) { --depth_; return noCode(m); }
        std::vector<Value> reg(ci.registersSize);
        uint32_t base = ci.registersSize - ci.insSize;
        for (uint32_t k = 0; k < incoming.size() && base + k < reg.size(); ++k)
            reg[base + k] = incoming[k];
        RunResult res = execute(dex, m, ci, reg);
        --depth_;
        return res;
    }

    static int32_t sext(uint32_t v, int bits) {
        int32_t s = (int32_t)(v & ((1u << bits) - 1));
        if (s & (1 << (bits - 1))) s |= -(1 << bits);
        return s;
    }
    RunResult makeExc(const std::string& t, const std::string& msg) {
        RunResult r; r.kind = RunResult::EXCEPTION; r.exceptionType = t; r.message = msg; return r;
    }

    RunResult execute(const DexFile& dex, const Method& m, const CodeItem& ci, std::vector<Value>& reg) {
        const uint16_t* in = ci.insns;
        uint32_t pc = 0;
        Value resultReg;
        uint32_t pendingExcRef = 0;
        uint64_t steps = 0;
        const uint64_t kStepBudget = 20000000ull;
        auto U = [&](uint32_t off) -> uint16_t { return in[off]; };

        while (pc < ci.insnsCount) {
            if (++steps > kStepBudget) {
                RunResult r; r.kind = RunResult::UNSUPPORTED;
                r.message = "instruction budget exceeded in " + m.classDesc + "->" + m.name;
                trace_.stop(r.message); return r;
            }
            uint16_t unit = in[pc];
            uint8_t op = unit & 0xFF;
            switch (op) {
            case 0x00: pc += 1; break;
            case 0x01: { int d=(unit>>8)&0xF, s=(unit>>12)&0xF; reg[d]=reg[s]; pc+=1; } break;
            case 0x07: { int d=(unit>>8)&0xF, s=(unit>>12)&0xF; reg[d]=reg[s]; pc+=1; } break; // move-object
            case 0x0A: { int d=(unit>>8)&0xFF; reg[d]=resultReg; pc+=1; } break;
            case 0x0C: { int d=(unit>>8)&0xFF; reg[d]=resultReg; pc+=1; } break;
            case 0x0D: { int d=(unit>>8)&0xFF; reg[d]=Value::Ref(pendingExcRef); pc+=1; } break;
            case 0x0E: { RunResult r; r.kind=RunResult::VOID; return r; }
            case 0x0F: { int a=(unit>>8)&0xFF; RunResult r; r.kind=RunResult::INT; r.i=reg[a].i; return r; }
            case 0x11: { int a=(unit>>8)&0xFF; RunResult r; r.kind=RunResult::REF; r.ref=reg[a].ref; return r; }
            case 0x12: { int d=(unit>>8)&0xF; int32_t v=sext(unit>>12,4); reg[d]=Value::Int(v); pc+=1; } break;
            case 0x13: { int d=(unit>>8)&0xFF; int32_t v=(int16_t)U(pc+1); reg[d]=Value::Int(v); pc+=2; } break;
            case 0x14: { int d=(unit>>8)&0xFF; uint32_t v=U(pc+1)|((uint32_t)U(pc+2)<<16); reg[d]=Value::Int((int32_t)v); pc+=3; } break;
            case 0x1A: { int d=(unit>>8)&0xFF; uint32_t sidx=U(pc+1);
                         reg[d]=Value::Ref(newString(dex.getString(sidx))); pc+=2; } break;
            case 0x1C: { int d=(unit>>8)&0xFF; uint32_t tidx=U(pc+1);    // const-class
                         HeapObj o; o.klass="Ljava/lang/Class;"; o.nativeKind="class"; o.str=dex.typeDesc(tidx);
                         reg[d]=Value::Ref(alloc(std::move(o))); pc+=2; } break;
            case 0x1F: { pc+=2; } break;   // check-cast: pass-through (no type verification)
            case 0x20: { int d=(unit>>8)&0xF; uint32_t tidx=U(pc+1); (void)tidx;   // instance-of (best-effort)
                         int s=(unit>>12)&0xF; reg[d]=Value::Int(reg[s].ref!=0?1:0); pc+=2; } break;
            case 0x21: { int d=(unit>>8)&0xF, a=(unit>>12)&0xF; uint32_t r=reg[a].ref;
                         if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","array-length on null");
                         size_t len = heap_[r].oarr.empty()? heap_[r].arr.size() : heap_[r].oarr.size();
                         reg[d]=Value::Int((int32_t)len); pc+=1; } break;
            case 0x22: { int d=(unit>>8)&0xFF; uint32_t tidx=U(pc+1); std::string kd=dex.typeDesc(tidx);
                         { RunResult ir=ensureInit(kd); if(ir.kind==RunResult::UNSUPPORTED||ir.kind==RunResult::EXCEPTION) return ir; }
                         HeapObj o; o.typeIdx=tidx; o.klass=kd;
                         reg[d]=Value::Ref(alloc(std::move(o))); pc+=2; } break;
            case 0x23: { int d=(unit>>8)&0xF, sz=(unit>>12)&0xF; uint32_t tidx=U(pc+1);
                         int32_t n=reg[sz].i; if(n<0) return makeExc("Ljava/lang/NegativeArraySizeException;","");
                         std::string td=dex.typeDesc(tidx); bool isObj = td.size()>1 && (td[1]=='L'||td[1]=='[');
                         HeapObj o; o.isArray=true; o.klass=td;
                         if(isObj) o.oarr.assign(n, Value::Ref(0)); else o.arr.assign(n,0);
                         reg[d]=Value::Ref(alloc(std::move(o))); pc+=2; } break;
            case 0x27: { int a=(unit>>8)&0xFF; uint32_t er=reg[a].ref;
                         auto h=dex.findHandler(ci,pc);
                         if(h){ pendingExcRef=er; pc=*h; break; }
                         RunResult r; r.kind=RunResult::EXCEPTION; r.ref=er;
                         r.exceptionType = er&&er<heap_.size()? heap_[er].klass:"";
                         trace_.stop("uncaught exception "+r.exceptionType); return r; }
            case 0x28: { int32_t off=sext((unit>>8)&0xFF,8); pc=(uint32_t)((int32_t)pc+off); } break;
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: {
                         int a=(unit>>8)&0xF, b=(unit>>12)&0xF; int32_t off=(int16_t)U(pc+1);
                         int32_t x=reg[a].i, y=reg[b].i; bool t=false;
                         switch(op){case 0x32:t=x==y;break;case 0x33:t=x!=y;break;case 0x34:t=x<y;break;
                                    case 0x35:t=x>=y;break;case 0x36:t=x>y;break;case 0x37:t=x<=y;break;}
                         pc = t ? (uint32_t)((int32_t)pc+off) : pc+2; } break;
            case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D: {
                         int a=(unit>>8)&0xFF; int32_t off=(int16_t)U(pc+1); int32_t x=reg[a].i; bool t=false;
                         switch(op){case 0x38:t=x==0;break;case 0x39:t=x!=0;break;case 0x3A:t=x<0;break;
                                    case 0x3B:t=x>=0;break;case 0x3C:t=x>0;break;case 0x3D:t=x<=0;break;}
                         pc = t ? (uint32_t)((int32_t)pc+off) : pc+2; } break;
            case 0x44: { int d=(unit>>8)&0xFF; uint16_t bc=U(pc+1); int a=bc&0xFF, idx=(bc>>8)&0xFF;
                         uint32_t r=reg[a].ref; int32_t ix=reg[idx].i;
                         if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","aget null");
                         if(ix<0||(size_t)ix>=heap_[r].arr.size()) return makeExc("Ljava/lang/ArrayIndexOutOfBoundsException;","");
                         reg[d]=Value::Int(heap_[r].arr[ix]); pc+=2; } break;
            case 0x4B: { int s=(unit>>8)&0xFF; uint16_t bc=U(pc+1); int a=bc&0xFF, idx=(bc>>8)&0xFF;
                         uint32_t r=reg[a].ref; int32_t ix=reg[idx].i;
                         if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","aput null");
                         if(ix<0||(size_t)ix>=heap_[r].arr.size()) return makeExc("Ljava/lang/ArrayIndexOutOfBoundsException;","");
                         heap_[r].arr[ix]=reg[s].i; pc+=2; } break;
            case 0x46: { int d=(unit>>8)&0xFF; uint16_t bc=U(pc+1); int a=bc&0xFF, idx=(bc>>8)&0xFF; // aget-object
                         uint32_t r=reg[a].ref; int32_t ix=reg[idx].i;
                         if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","aget-object null");
                         if(ix<0||(size_t)ix>=heap_[r].oarr.size()) return makeExc("Ljava/lang/ArrayIndexOutOfBoundsException;","");
                         reg[d]=heap_[r].oarr[ix]; pc+=2; } break;
            case 0x4D: { int s=(unit>>8)&0xFF; uint16_t bc=U(pc+1); int a=bc&0xFF, idx=(bc>>8)&0xFF; // aput-object
                         uint32_t r=reg[a].ref; int32_t ix=reg[idx].i;
                         if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","aput-object null");
                         if(ix<0||(size_t)ix>=heap_[r].oarr.size()) return makeExc("Ljava/lang/ArrayIndexOutOfBoundsException;","");
                         heap_[r].oarr[ix]=reg[s]; pc+=2; } break;
            // instance fields (keyed by fully-qualified name for cross-DEX stability)
            case 0x52: case 0x53: case 0x55: case 0x56: case 0x57: case 0x58: { // iget (int/typed)
                         int d=(unit>>8)&0xF, o=(unit>>12)&0xF; std::string f=dex.fieldRefName(U(pc+1));
                         uint32_t r=reg[o].ref; if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","iget null @pc="+std::to_string(pc));
                         auto it=heap_[r].fields.find(f); reg[d]=it!=heap_[r].fields.end()?it->second:Value::Int(0); pc+=2; } break;
            case 0x54: { int d=(unit>>8)&0xF, o=(unit>>12)&0xF; std::string f=dex.fieldRefName(U(pc+1)); // iget-object
                         uint32_t r=reg[o].ref; if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","iget-object null @pc="+std::to_string(pc));
                         auto it=heap_[r].fields.find(f); reg[d]=it!=heap_[r].fields.end()?it->second:Value::Ref(0); pc+=2; } break;
            case 0x59: case 0x5A: case 0x5C: case 0x5D: case 0x5E: case 0x5F: { // iput (int/typed)
                         int s=(unit>>8)&0xF, o=(unit>>12)&0xF; std::string f=dex.fieldRefName(U(pc+1));
                         uint32_t r=reg[o].ref; if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","iput null @pc="+std::to_string(pc));
                         heap_[r].fields[f]=reg[s]; pc+=2; } break;
            case 0x5B: { int s=(unit>>8)&0xF, o=(unit>>12)&0xF; std::string f=dex.fieldRefName(U(pc+1)); // iput-object
                         uint32_t r=reg[o].ref; if(!r||r>=heap_.size()) return makeExc("Ljava/lang/NullPointerException;","iput-object null @pc="+std::to_string(pc));
                         heap_[r].fields[f]=reg[s]; pc+=2; } break;
            // static fields (0x60 sget..0x66 typed, 0x67 sput..0x6D typed)
            case 0x60: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                         int d=(unit>>8)&0xFF; uint32_t fidx=U(pc+1);
                         { RunResult ir=ensureInit(dex.typeDesc(dex.fieldId(fidx).classIdx)); if(ir.kind==RunResult::UNSUPPORTED||ir.kind==RunResult::EXCEPTION) return ir; }
                         std::string f=dex.fieldRefName(fidx);
                         auto it=statics_.find(f); reg[d]=it!=statics_.end()?it->second:(op==0x62?Value::Ref(0):Value::Int(0));
                         pc+=2; } break;
            case 0x67: case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D: {
                         int s=(unit>>8)&0xFF; uint32_t fidx=U(pc+1);
                         { RunResult ir=ensureInit(dex.typeDesc(dex.fieldId(fidx).classIdx)); if(ir.kind==RunResult::UNSUPPORTED||ir.kind==RunResult::EXCEPTION) return ir; }
                         std::string f=dex.fieldRefName(fidx); statics_[f]=reg[s]; pc+=2; } break;
            case 0x6E: case 0x6F: case 0x70: case 0x71: {   // invoke-virtual/super/direct/static
                         uint32_t a=(unit>>12)&0xF, g=(unit>>8)&0xF; uint32_t midx=U(pc+1); uint16_t regs=U(pc+2);
                         uint32_t rC=regs&0xF, rD=(regs>>4)&0xF, rE=(regs>>8)&0xF, rF=(regs>>12)&0xF;
                         uint32_t rv[5]={rC,rD,rE,rF,g};
                         std::vector<Value> argv; for(uint32_t k=0;k<a;++k) argv.push_back(reg[rv[k]]);
                         const MethodId& mid = dex.methodId(midx);
                         std::string classDesc = dex.typeDesc(mid.classIdx);
                         std::string name = dex.getString(mid.nameIdx);
                         std::string shorty = dex.getString(dex.protoId(mid.protoIdx).shortyIdx);
                         std::string recv;
                         if(op==0x6E && !argv.empty()){ if(auto* ro=obj(argv[0].ref)) recv=ro->klass; }
                         ResolvedMethod rm = (op==0x6E)
                             ? rt_.resolveVirtual(recv, classDesc, name, shorty)
                             : rt_.resolveMethod(classDesc, name, shorty);
                         if(rm.found() && rm.method->codeOff!=0){
                             RunResult sub = invoke(*rm.dex, *rm.method, argv);
                             if(sub.kind==RunResult::UNSUPPORTED) return sub;
                             if(sub.kind==RunResult::EXCEPTION){
                                 auto h=dex.findHandler(ci,pc);
                                 if(h){ pendingExcRef=sub.ref; pc=*h; break; }
                                 return sub; }
                             if(sub.kind==RunResult::INT) resultReg=Value::Int(sub.i);
                             else if(sub.kind==RunResult::REF) resultReg=Value::Ref(sub.ref);
                             pc+=3; break;
                         }
                         if(rm.found()){ // declared in a loaded class but no code → native/abstract
                             RunResult r; r.kind=RunResult::UNSUPPORTED;
                             std::string sig=classDesc+"->"+name+"("+shorty+")";
                             r.message=((rm.method->accessFlags&ACC_NATIVE)?"native (JNI) method not supported: ":
                                        (rm.method->accessFlags&ACC_ABSTRACT)?"abstract method invoked: ":
                                        "method has no bytecode: ")+sig+" caller="+m.classDesc+"->"+m.name+" pc="+std::to_string(pc);
                             trace_.stop(r.message); return r;
                         }
                         // class not in loaded set → external/framework
                         std::string sig = classDesc+"->"+name+"("+shorty+")";
                         FwOutcome fo = registry_.dispatch(sig, *this, argv, trace_, mode_);
                         if(fo.kind==FwOutcome::UNHANDLED || fo.kind==FwOutcome::ERROR){
                             RunResult r; r.kind=RunResult::UNSUPPORTED;
                             std::ostringstream ss;
                             ss<<"unsupported framework method ["<<sig<<"] caller="
                               <<m.classDesc<<"->"<<m.name<<"("<<m.shorty<<") pc="<<pc<<" mode="<<modeName(mode_)<<" reason=";
                             if(fo.kind==FwOutcome::ERROR) ss<<fo.message;
                             else ss<<(registry_.find(sig)?"analysis-only handler (not allowed in functional mode)":"no registered handler");
                             r.message=ss.str(); trace_.stop(ss.str()); return r;
                         }
                         if(fo.kind==FwOutcome::INT) resultReg=Value::Int(fo.i);
                         else if(fo.kind==FwOutcome::REF) resultReg=Value::Ref(fo.ref);
                         pc+=3; } break;
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
            case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F: case 0xA0: case 0xA1: { // binop-int (+and/or/xor/shl/shr/ushr)
                         int d=(unit>>8)&0xFF; uint16_t bc=U(pc+1); int a=bc&0xFF, b=(bc>>8)&0xFF;
                         int32_t x=reg[a].i, y=reg[b].i, z=0;
                         if((op==0x93||op==0x94)&&y==0) return makeExc("Ljava/lang/ArithmeticException;","divide by zero");
                         switch(op){case 0x90:z=x+y;break;case 0x91:z=x-y;break;case 0x92:z=x*y;break;
                                    case 0x93:z=x/y;break;case 0x94:z=x%y;break;case 0x95:z=x&y;break;
                                    case 0x96:z=x|y;break;case 0x97:z=x^y;break;case 0x98:z=x<<(y&31);break;
                                    case 0x99:z=x>>(y&31);break;case 0x9A:z=(int32_t)((uint32_t)x>>(y&31));break;
                                    default:z=0;break;}
                         reg[d]=Value::Int(z); pc+=2; } break;
            case 0xD8: { int d=(unit>>8)&0xFF; uint16_t bc=U(pc+1); int a=bc&0xFF; int32_t lit=sext((bc>>8)&0xFF,8);
                         reg[d]=Value::Int(reg[a].i+lit); pc+=2; } break;
            case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: { // binop-int/2addr add/sub/mul/div/rem
                         int d=(unit>>8)&0xF, s=(unit>>12)&0xF; int32_t x=reg[d].i, y=reg[s].i, z=0;
                         if((op==0xB3||op==0xB4)&&y==0) return makeExc("Ljava/lang/ArithmeticException;","divide by zero");
                         switch(op){case 0xB0:z=x+y;break;case 0xB1:z=x-y;break;case 0xB2:z=x*y;break;
                                    case 0xB3:z=x/y;break;default:z=x%y;break;}
                         reg[d]=Value::Int(z); pc+=1; } break;
            default: {
                RunResult r; r.kind=RunResult::UNSUPPORTED;
                std::ostringstream ss; ss<<"unsupported opcode 0x"<<std::hex<<(int)op
                   <<" in "<<m.classDesc<<"->"<<m.name<<" @pc="<<std::dec<<pc;
                r.message=ss.str(); trace_.stop(ss.str()); return r; }
            }
        }
        RunResult r; r.kind=RunResult::VOID; return r;
    }
};

} // namespace apkbridge
