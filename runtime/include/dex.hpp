// APKBridge runtime :: DEX parser (header-only, C++17, no deps)
// Portable: compiles on Linux/Windows/macOS and links into an iOS static lib.
// Parses the subset of DEX 035 the interpreter needs. Bounds-checked for
// untrusted input: every read validates against file size before dereferencing.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <optional>
#include <unordered_map>
#include <cstdio>

namespace apkbridge {

struct DexError : std::runtime_error {
    explicit DexError(const std::string& m) : std::runtime_error(m) {}
};

struct MethodId { uint16_t classIdx; uint16_t protoIdx; uint32_t nameIdx; };
struct FieldId  { uint16_t classIdx; uint16_t typeIdx;  uint32_t nameIdx; };
struct ProtoId  { uint32_t shortyIdx; uint32_t returnTypeIdx; uint32_t paramsOff; };

struct TryItem { uint32_t startAddr; uint16_t insnCount; uint16_t handlerOff; };
struct CatchHandler { int32_t typeIdx; uint32_t address; }; // typeIdx<0 => catch-all

struct CodeItem {
    uint16_t registersSize = 0;
    uint16_t insSize = 0;
    uint16_t outsSize = 0;
    uint16_t triesSize = 0;
    const uint16_t* insns = nullptr;  // pointer into file
    uint32_t insnsCount = 0;          // in 16-bit code units
    std::vector<TryItem> tries;
    // handler lists keyed by handlerOff (relative), each a list of CatchHandler
    uint32_t handlersBase = 0;        // file offset of encoded_catch_handler_list
    bool valid = false;
};

struct Method {
    uint32_t methodIdx = 0;
    uint32_t accessFlags = 0;
    uint32_t codeOff = 0;
    std::string name;
    std::string shorty;
    std::string classDesc;
};

struct Class {
    uint32_t typeIdx = 0;
    std::string desc;
    std::string superDesc;
    std::vector<Method> directMethods;
    std::vector<Method> virtualMethods;
};

class DexFile {
public:
    explicit DexFile(std::vector<uint8_t> bytes) : buf_(std::move(bytes)) { parse(); }

    static DexFile fromPath(const std::string& path) {
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) throw DexError("cannot open " + path);
        std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> b(n > 0 ? (size_t)n : 0);
        if (n > 0 && std::fread(b.data(), 1, (size_t)n, f) != (size_t)n) { std::fclose(f); throw DexError("short read"); }
        std::fclose(f);
        return DexFile(std::move(b));
    }

    size_t size() const { return buf_.size(); }

    std::string getString(uint32_t idx) const {
        if (idx >= stringIds_.size()) throw DexError("string idx oob");
        uint32_t off = stringIds_[idx];
        // skip uleb128 length (in UTF-16 units), then read MUTF-8 until NUL
        size_t p = off; uint32_t len = readULEB(p);
        (void)len;
        std::string s;
        while (p < buf_.size() && buf_[p] != 0) s.push_back((char)buf_[p++]);
        return s;
    }
    std::string typeDesc(uint32_t typeIdx) const {
        if (typeIdx >= typeIds_.size()) throw DexError("type idx oob");
        return getString(typeIds_[typeIdx]);
    }
    const MethodId& methodId(uint32_t i) const {
        if (i >= methodIds_.size()) throw DexError("method idx oob");
        return methodIds_[i];
    }
    const FieldId& fieldId(uint32_t i) const {
        if (i >= fieldIds_.size()) throw DexError("field idx oob");
        return fieldIds_[i];
    }
    const ProtoId& protoId(uint32_t i) const {
        if (i >= protoIds_.size()) throw DexError("proto idx oob");
        return protoIds_[i];
    }
    const std::vector<Class>& classes() const { return classes_; }
    uint32_t stringCount() const { return (uint32_t)stringIds_.size(); }
    uint32_t methodCount() const { return (uint32_t)methodIds_.size(); }

    // Describe a method ref as "Lcls;->name(shorty)"
    std::string methodRefName(uint32_t midx) const {
        const auto& m = methodId(midx);
        return typeDesc(m.classIdx) + "->" + getString(m.nameIdx) +
               "(" + getString(protoId(m.protoIdx).shortyIdx) + ")";
    }
    std::string fieldRefName(uint32_t fidx) const {
        const auto& f = fieldId(fidx);
        return typeDesc(f.classIdx) + "->" + getString(f.nameIdx);
    }

    CodeItem readCode(uint32_t off) const {
        CodeItem ci;
        if (off == 0) return ci;
        if (off + 16 > buf_.size()) throw DexError("code_item oob");
        size_t p = off;
        ci.registersSize = rd16(p); ci.insSize = rd16(p);
        ci.outsSize = rd16(p); ci.triesSize = rd16(p);
        uint32_t debugOff = rd32(p); (void)debugOff;
        ci.insnsCount = rd32(p);
        if (p + (size_t)ci.insnsCount * 2 > buf_.size()) throw DexError("insns oob");
        ci.insns = reinterpret_cast<const uint16_t*>(buf_.data() + p);
        p += (size_t)ci.insnsCount * 2;
        if (ci.triesSize) {
            if ((ci.insnsCount & 1) != 0) p += 2; // padding
            for (uint16_t i = 0; i < ci.triesSize; ++i) {
                TryItem t; t.startAddr = rd32(p); t.insnCount = rd16(p); t.handlerOff = rd16(p);
                ci.tries.push_back(t);
            }
            ci.handlersBase = (uint32_t)p; // encoded_catch_handler_list starts here
        }
        ci.valid = true;
        return ci;
    }

    // Resolve a catch handler address for a throw at `addr` within code `ci`.
    // Returns the handler insn address, or nullopt if none in this method.
    std::optional<uint32_t> findHandler(const CodeItem& ci, uint32_t addr) const {
        for (const auto& t : ci.tries) {
            if (addr >= t.startAddr && addr < t.startAddr + t.insnCount) {
                size_t p = ci.handlersBase + t.handlerOff;
                int64_t size = readSLEB(p);
                int64_t n = size < 0 ? -size : size;
                for (int64_t i = 0; i < n; ++i) {
                    uint32_t tIdx = readULEB(p); uint32_t a = readULEB(p); (void)tIdx;
                    return a; // first typed handler (type check simplified)
                }
                if (size <= 0) { uint32_t a = readULEB(p); return a; } // catch-all
            }
        }
        return std::nullopt;
    }

    const Class* findClass(const std::string& desc) const {
        for (const auto& c : classes_) if (c.desc == desc) return &c;
        return nullptr;
    }
    const Method* findMethod(const std::string& clsDesc, const std::string& name,
                             const std::string& shorty) const {
        const Class* c = findClass(clsDesc);
        if (!c) return nullptr;
        for (const auto* list : {&c->directMethods, &c->virtualMethods})
            for (const auto& m : *list)
                if (m.name == name && (shorty.empty() || m.shorty == shorty)) return &m;
        return nullptr;
    }
    const Method* findMethodByIdx(uint32_t midx) const {
        auto it = methodByIdx_.find(midx);
        return it == methodByIdx_.end() ? nullptr : it->second;
    }

private:
    std::vector<uint8_t> buf_;
    std::vector<uint32_t> stringIds_;
    std::vector<uint32_t> typeIds_;
    std::vector<ProtoId> protoIds_;
    std::vector<FieldId> fieldIds_;
    std::vector<MethodId> methodIds_;
    std::vector<Class> classes_;
    std::unordered_map<uint32_t, const Method*> methodByIdx_;

    uint16_t rd16(size_t& p) const {
        if (p + 2 > buf_.size()) throw DexError("rd16 oob");
        uint16_t v; std::memcpy(&v, buf_.data() + p, 2); p += 2; return v;
    }
    uint32_t rd32(size_t& p) const {
        if (p + 4 > buf_.size()) throw DexError("rd32 oob");
        uint32_t v; std::memcpy(&v, buf_.data() + p, 4); p += 4; return v;
    }
    uint32_t at32(size_t p) const { return rd32(p); }

    uint32_t readULEB(size_t& p) const {
        uint32_t result = 0; int shift = 0; uint8_t b;
        do {
            if (p >= buf_.size()) throw DexError("uleb oob");
            b = buf_[p++]; result |= (uint32_t)(b & 0x7F) << shift; shift += 7;
        } while (b & 0x80);
        return result;
    }
    int64_t readSLEB(size_t& p) const {
        int64_t result = 0; int shift = 0; uint8_t b;
        do {
            if (p >= buf_.size()) throw DexError("sleb oob");
            b = buf_[p++]; result |= (int64_t)(b & 0x7F) << shift; shift += 7;
        } while (b & 0x80);
        if (shift < 64 && (b & 0x40)) result |= -((int64_t)1 << shift);
        return result;
    }

    void parse() {
        if (buf_.size() < 112) throw DexError("too small for header");
        if (std::memcmp(buf_.data(), "dex\n", 4) != 0) throw DexError("bad magic");
        size_t p = 56;
        uint32_t strSize = rd32(p); uint32_t strOff = rd32(p);
        uint32_t typeSize = rd32(p); uint32_t typeOff = rd32(p);
        uint32_t protoSize = rd32(p); uint32_t protoOff = rd32(p);
        uint32_t fieldSize = rd32(p); uint32_t fieldOff = rd32(p);
        uint32_t methodSize = rd32(p); uint32_t methodOff = rd32(p);
        uint32_t classSize = rd32(p); uint32_t classOff = rd32(p);

        stringIds_.resize(strSize);
        { size_t q = strOff; for (uint32_t i = 0; i < strSize; ++i) stringIds_[i] = rd32(q); }
        typeIds_.resize(typeSize);
        { size_t q = typeOff; for (uint32_t i = 0; i < typeSize; ++i) typeIds_[i] = rd32(q); }
        protoIds_.resize(protoSize);
        { size_t q = protoOff; for (uint32_t i = 0; i < protoSize; ++i) {
            ProtoId pr; pr.shortyIdx = rd32(q); pr.returnTypeIdx = rd32(q); pr.paramsOff = rd32(q);
            protoIds_[i] = pr; } }
        fieldIds_.resize(fieldSize);
        { size_t q = fieldOff; for (uint32_t i = 0; i < fieldSize; ++i) {
            FieldId f; f.classIdx = rd16(q); f.typeIdx = rd16(q); f.nameIdx = rd32(q);
            fieldIds_[i] = f; } }
        methodIds_.resize(methodSize);
        { size_t q = methodOff; for (uint32_t i = 0; i < methodSize; ++i) {
            MethodId m; m.classIdx = rd16(q); m.protoIdx = rd16(q); m.nameIdx = rd32(q);
            methodIds_[i] = m; } }

        // class_defs
        size_t q = classOff;
        for (uint32_t i = 0; i < classSize; ++i) {
            Class c;
            c.typeIdx = rd32(q);
            uint32_t access = rd32(q); (void)access;
            uint32_t superIdx = rd32(q);
            uint32_t interfacesOff = rd32(q); (void)interfacesOff;
            uint32_t sourceIdx = rd32(q); (void)sourceIdx;
            uint32_t annotationsOff = rd32(q); (void)annotationsOff;
            uint32_t classDataOff = rd32(q);
            uint32_t staticValuesOff = rd32(q); (void)staticValuesOff;
            c.desc = typeDesc(c.typeIdx);
            c.superDesc = (superIdx != 0xFFFFFFFF) ? typeDesc(superIdx) : "";
            if (classDataOff) parseClassData(classDataOff, c);
            classes_.push_back(std::move(c));
        }
        // index methods by global idx for invoke resolution
        for (auto& c : classes_)
            for (auto* list : {&c.directMethods, &c.virtualMethods})
                for (auto& m : *list) methodByIdx_[m.methodIdx] = &m;
    }

    void parseClassData(uint32_t off, Class& c) {
        size_t p = off;
        uint32_t nStatic = readULEB(p), nInstance = readULEB(p);
        uint32_t nDirect = readULEB(p), nVirtual = readULEB(p);
        // skip encoded fields (static then instance)
        uint32_t prev = 0;
        for (uint32_t i = 0; i < nStatic + nInstance; ++i) {
            if (i == nStatic) prev = 0;
            readULEB(p); /*idx diff*/ readULEB(p); /*access*/
        }
        prev = 0;
        for (uint32_t i = 0; i < nDirect; ++i) {
            uint32_t d = readULEB(p); prev += d;
            Method m; m.methodIdx = prev; m.accessFlags = readULEB(p); m.codeOff = readULEB(p);
            fillMethodMeta(m); c.directMethods.push_back(std::move(m));
        }
        prev = 0;
        for (uint32_t i = 0; i < nVirtual; ++i) {
            uint32_t d = readULEB(p); prev += d;
            Method m; m.methodIdx = prev; m.accessFlags = readULEB(p); m.codeOff = readULEB(p);
            fillMethodMeta(m); c.virtualMethods.push_back(std::move(m));
        }
    }

    void fillMethodMeta(Method& m) {
        const auto& mid = methodId(m.methodIdx);
        m.name = getString(mid.nameIdx);
        m.classDesc = typeDesc(mid.classIdx);
        m.shorty = getString(protoId(mid.protoIdx).shortyIdx);
    }
};

} // namespace apkbridge
