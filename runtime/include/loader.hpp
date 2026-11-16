// APKBridge runtime :: multi-DEX class loader (header-only, C++17)
// Owns every classes*.dex of one imported APK and resolves classes, methods
// and fields ACROSS them. Method indices are per-DEX, so resolution works by
// (classDescriptor, name, shorty) looked up in the global class index, with a
// superclass walk over loaded classes and receiver-type virtual dispatch.
#pragma once
#include "dex.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>

namespace apkbridge {

struct ResolvedMethod {
    const DexFile* dex = nullptr;   // the DEX that defines this method
    const Method* method = nullptr; // may have codeOff==0 (native/abstract)
    bool found() const { return method != nullptr; }
};

class Runtime {
public:
    void addDexBytes(std::vector<uint8_t> bytes) {
        dexes_.push_back(std::make_unique<DexFile>(std::move(bytes)));
        indexDex(*dexes_.back());
    }
    void addDexPath(const std::string& path) {
        dexes_.push_back(std::make_unique<DexFile>(DexFile::fromPath(path)));
        indexDex(*dexes_.back());
    }
    size_t dexCount() const { return dexes_.size(); }
    const DexFile& dex(size_t i) const { return *dexes_.at(i); }

    const Class* findClass(const std::string& desc, const DexFile** outDex = nullptr) const {
        auto it = classIndex_.find(desc);
        if (it == classIndex_.end()) return nullptr;
        if (outDex) *outDex = it->second.first;
        return it->second.second;
    }

    // Resolve a concrete (or declared) method by signature, walking superclasses
    // over the loaded set. Prefers a definition WITH code; if only a no-code
    // (native/abstract) declaration exists, returns that so the caller can
    // report it precisely instead of guessing.
    ResolvedMethod resolveMethod(const std::string& startClass,
                                 const std::string& name,
                                 const std::string& shorty) const {
        ResolvedMethod declared;  // first no-code match, as a fallback
        std::string cur = startClass;
        int guard = 0;
        while (!cur.empty() && guard++ < 64) {
            const DexFile* d = nullptr;
            const Class* c = findClass(cur, &d);
            if (!c) break;  // superclass not in loaded set → external/framework
            for (const auto* list : {&c->directMethods, &c->virtualMethods})
                for (const auto& m : *list)
                    if (m.name == name && m.shorty == shorty) {
                        if (m.codeOff != 0) return {d, &m};       // concrete
                        if (!declared.found()) declared = {d, &m}; // native/abstract
                    }
            cur = c->superDesc;
        }
        return declared;
    }

    // Virtual dispatch: pick the most-derived override starting from the
    // receiver's runtime class, falling back to the static ref class.
    ResolvedMethod resolveVirtual(const std::string& receiverClass,
                                  const std::string& refClass,
                                  const std::string& name,
                                  const std::string& shorty) const {
        if (!receiverClass.empty()) {
            ResolvedMethod r = resolveMethod(receiverClass, name, shorty);
            if (r.found() && r.method->codeOff != 0) return r;
        }
        return resolveMethod(refClass, name, shorty);
    }

private:
    std::vector<std::unique_ptr<DexFile>> dexes_;
    std::unordered_map<std::string, std::pair<const DexFile*, const Class*>> classIndex_;
    void indexDex(const DexFile& d) {
        for (const auto& c : d.classes())
            classIndex_.emplace(c.desc, std::make_pair(&d, &c)); // first definition wins
    }
};

} // namespace apkbridge
