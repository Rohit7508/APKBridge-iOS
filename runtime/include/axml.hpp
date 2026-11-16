// APKBridge runtime :: binary AndroidManifest.xml (AXML) parser (header-only).
// Extracts package, versionName/Code, min/target SDK and permissions from the
// compiled manifest. Bounds-checked for untrusted input. C++ port of the
// analyzer's Python AXML decoder (kept in step with it).
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

namespace apkbridge {

struct AxmlError : std::runtime_error { explicit AxmlError(const std::string& m):std::runtime_error(m){} };

struct ManifestInfo {
    std::string package;
    std::string versionName;
    std::string applicationClass;   // <application android:name> (dotted)
    int64_t versionCode = -1;
    int64_t minSdk = -1;
    int64_t targetSdk = -1;
    std::vector<std::string> permissions;
    std::vector<std::string> activities;
};

class Axml {
public:
    explicit Axml(const std::vector<uint8_t>& data) : d_(data) { parse(); }
    const ManifestInfo& info() const { return info_; }

private:
    const std::vector<uint8_t>& d_;
    std::vector<std::string> pool_;
    ManifestInfo info_;

    static constexpr uint16_t STR_POOL = 0x0001;
    static constexpr uint16_t XML_TYPE = 0x0003;
    static constexpr uint16_t START_EL = 0x0102;
    static constexpr uint32_t FLAG_UTF8 = 1u << 8;

    uint16_t r16(size_t p) const { if (p+2>d_.size()) throw AxmlError("r16 oob"); return (uint16_t)(d_[p]|(d_[p+1]<<8)); }
    uint32_t r32(size_t p) const { if (p+4>d_.size()) throw AxmlError("r32 oob");
        return (uint32_t)d_[p]|((uint32_t)d_[p+1]<<8)|((uint32_t)d_[p+2]<<16)|((uint32_t)d_[p+3]<<24); }

    std::string str(uint32_t idx) const { return idx < pool_.size() ? pool_[idx] : std::string(); }

    void parseStringPool(size_t off) {
        uint32_t count = r32(off + 8);
        uint32_t flags = r32(off + 16);
        uint32_t stringsStart = r32(off + 20);
        if (count > d_.size() / 4) throw AxmlError("implausible string_count");
        bool utf8 = (flags & FLAG_UTF8) != 0;
        size_t base = off + stringsStart;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t so = r32(off + 28 + i * 4);
            size_t p = base + so;
            if (utf8) {
                p = skipLen8(p);            // char count
                size_t blen; p = readLen8(p, blen);
                if (p + blen > d_.size()) throw AxmlError("utf8 str oob");
                pool_.emplace_back((const char*)&d_[p], blen);
            } else {
                size_t n; p = readLen16(p, n);
                std::string s; s.reserve(n);
                for (size_t k = 0; k < n; ++k) { if (p+1 >= d_.size()) break; s.push_back((char)d_[p]); p += 2; }
                pool_.push_back(std::move(s));
            }
        }
    }
    size_t skipLen8(size_t p) const { uint8_t v=d_[p++]; if (v&0x80) p++; return p; }
    size_t readLen8(size_t p, size_t& out) const { uint8_t v=d_[p++]; if (v&0x80){ out=((v&0x7F)<<8)|d_[p++]; } else out=v; return p; }
    size_t readLen16(size_t p, size_t& out) const { uint16_t v=r16(p); p+=2; if (v&0x8000){ uint16_t lo=r16(p); p+=2; out=((v&0x7FFF)<<16)|lo; } else out=v; return p; }

    void parse() {
        if (r16(0) != XML_TYPE) throw AxmlError("not AXML");
        uint16_t headerSize = r16(2);
        uint32_t total = r32(4);
        size_t end = total < d_.size() ? total : d_.size();
        size_t off = headerSize;
        while (off + 8 <= end) {
            uint16_t ct = r16(off);
            uint32_t cs = r32(off + 4);
            if (cs == 0) break;
            if (ct == STR_POOL) parseStringPool(off);
            else if (ct == START_EL) readStart(off);
            off += cs;
        }
    }

    void readStart(size_t off) {
        size_t base = off + 8;
        uint32_t nameI = r32(base + 12);
        uint16_t attrStart = r16(base + 16);
        uint16_t attrCount = r16(base + 20);
        std::string name = str(nameI);
        size_t ab = base + 8 + attrStart;
        auto attrStr = [&](const char* key) -> std::string {
            for (uint16_t i = 0; i < attrCount; ++i) {
                size_t a = ab + i * 20;
                uint32_t aname = r32(a + 4);
                int32_t raw = (int32_t)r32(a + 8);
                if (str(aname) == key) {
                    if (raw != -1) return str((uint32_t)raw);
                    return str(r32(a + 16));
                }
            }
            return "";
        };
        auto attrInt = [&](const char* key, bool& found) -> int64_t {
            for (uint16_t i = 0; i < attrCount; ++i) {
                size_t a = ab + i * 20;
                uint32_t aname = r32(a + 4);
                if (str(aname) == key) { found = true; return (int32_t)r32(a + 16); }
            }
            found = false; return -1;
        };
        bool f;
        if (name == "manifest") {
            info_.package = attrStr("package");
            info_.versionName = attrStr("versionName");
            int64_t vc = attrInt("versionCode", f); if (f) info_.versionCode = vc;
        } else if (name == "uses-sdk") {
            int64_t mn = attrInt("minSdkVersion", f); if (f) info_.minSdk = mn;
            int64_t tg = attrInt("targetSdkVersion", f); if (f) info_.targetSdk = tg;
        } else if (name == "application") {
            info_.applicationClass = attrStr("name");
        } else if (name == "uses-permission") {
            std::string p = attrStr("name"); if (!p.empty()) info_.permissions.push_back(p);
        } else if (name == "activity") {
            std::string a = attrStr("name"); if (!a.empty()) info_.activities.push_back(a);
        }
    }
};

} // namespace apkbridge
