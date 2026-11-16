// APKBridge runtime :: ZIP/APK reader (header-only, C++17, links libz)
// Reads the ZIP central directory and extracts entries (STORE + DEFLATE) with
// strict limits for untrusted input:
//   - per-entry decompressed cap, total cap, entry-count cap
//   - compression-ratio (zip-bomb) guard
//   - path-traversal sanitization on extraction ("../", absolute, drive, NUL)
// Depends only on zlib (libz), which ships on iOS/macOS/Linux/Windows.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <zlib.h>

namespace apkbridge {

struct ZipError : std::runtime_error { explicit ZipError(const std::string& m):std::runtime_error(m){} };

struct ZipEntry {
    std::string name;
    uint16_t method = 0;          // 0 = store, 8 = deflate
    uint64_t compSize = 0;
    uint64_t uncompSize = 0;
    uint32_t localHeaderOff = 0;
    uint32_t crc32 = 0;
};

struct ZipLimits {
    uint64_t maxEntryBytes = 256ull * 1024 * 1024;   // per entry
    uint64_t maxTotalBytes = 2ull * 1024 * 1024 * 1024;
    uint32_t maxEntries = 200000;
    uint64_t maxCompressedBytes = 600ull * 1024 * 1024; // whole-APK input cap
    double    maxRatio   = 300.0;                    // uncomp/comp per entry
};

class ZipArchive {
public:
    explicit ZipArchive(std::vector<uint8_t> bytes, ZipLimits lim = {})
        : buf_(std::move(bytes)), lim_(lim) {
        if ((uint64_t)buf_.size() > lim_.maxCompressedBytes)
            throw ZipError("archive exceeds max compressed input size");
        parseCentralDirectory();
    }

    static ZipArchive fromPath(const std::string& p, ZipLimits lim = {}) {
        FILE* f = std::fopen(p.c_str(), "rb");
        if (!f) throw ZipError("cannot open " + p);
        std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
        if (n > 0 && (uint64_t)n > lim.maxCompressedBytes) { std::fclose(f);
            throw ZipError("APK exceeds max compressed input size"); }
        std::vector<uint8_t> b(n > 0 ? (size_t)n : 0);
        if (n > 0 && std::fread(b.data(), 1, (size_t)n, f) != (size_t)n) { std::fclose(f); throw ZipError("short read"); }
        std::fclose(f);
        return ZipArchive(std::move(b), lim);
    }

    const std::vector<ZipEntry>& entries() const { return entries_; }

    bool has(const std::string& name) const {
        for (auto& e : entries_) if (e.name == name) return true;
        return false;
    }

    // Decompress one entry fully into memory, enforcing caps. Throws on any
    // limit breach or corruption. Safe to call on untrusted archives.
    std::vector<uint8_t> read(const std::string& name) const {
        for (auto& e : entries_) if (e.name == name) return extract(e);
        throw ZipError("entry not found: " + name);
    }

    // Returns a filesystem-safe relative path for an entry, or empty string if
    // the name is unsafe (absolute, traversal, drive-letter, backslash, NUL).
    static std::string sanitizeRelPath(const std::string& name) {
        if (name.empty() || name.size() > 1024) return "";
        if (name.find('\0') != std::string::npos) return "";
        if (name[0] == '/' || name[0] == '\\') return "";               // absolute
        if (name.size() >= 2 && name[1] == ':') return "";              // C:
        std::string norm;
        size_t i = 0;
        while (i < name.size()) {
            size_t j = name.find_first_of("/\\", i);
            std::string seg = name.substr(i, j == std::string::npos ? std::string::npos : j - i);
            if (seg == "..") return "";                                 // traversal
            if (seg != "." && !seg.empty()) norm += (norm.empty() ? "" : "/") + seg;
            if (j == std::string::npos) break;
            i = j + 1;
        }
        return norm;
    }

private:
    std::vector<uint8_t> buf_;
    ZipLimits lim_;
    std::vector<ZipEntry> entries_;
    mutable uint64_t totalExtracted_ = 0;

    uint16_t r16(size_t p) const {
        if (p + 2 > buf_.size()) throw ZipError("r16 oob");
        return (uint16_t)(buf_[p] | (buf_[p+1] << 8));
    }
    uint32_t r32(size_t p) const {
        if (p + 4 > buf_.size()) throw ZipError("r32 oob");
        return (uint32_t)buf_[p] | ((uint32_t)buf_[p+1]<<8) | ((uint32_t)buf_[p+2]<<16) | ((uint32_t)buf_[p+3]<<24);
    }

    void parseCentralDirectory() {
        // Find End Of Central Directory (EOCD) signature 0x06054b50, scanning back.
        if (buf_.size() < 22) throw ZipError("too small for zip");
        size_t eocd = std::string::npos;
        size_t maxBack = buf_.size() >= 65557 ? buf_.size() - 65557 : 0;
        for (size_t p = buf_.size() - 22; ; --p) {
            if (r32(p) == 0x06054b50) { eocd = p; break; }
            if (p == maxBack) break;
        }
        if (eocd == std::string::npos) throw ZipError("no EOCD (not a zip?)");
        uint32_t total = r16(eocd + 10);
        uint32_t cdSize = r32(eocd + 12); (void)cdSize;
        uint32_t cdOff = r32(eocd + 16);
        if (total > lim_.maxEntries) throw ZipError("too many entries");
        size_t p = cdOff;
        for (uint32_t i = 0; i < total; ++i) {
            if (r32(p) != 0x02014b50) throw ZipError("bad central dir record");
            ZipEntry e;
            e.method = r16(p + 10);
            e.crc32 = r32(p + 16);
            e.compSize = r32(p + 20);
            e.uncompSize = r32(p + 24);
            uint16_t nameLen = r16(p + 28);
            uint16_t extraLen = r16(p + 30);
            uint16_t commentLen = r16(p + 32);
            e.localHeaderOff = r32(p + 42);
            if (p + 46 + nameLen > buf_.size()) throw ZipError("name oob");
            e.name.assign((const char*)&buf_[p + 46], nameLen);
            entries_.push_back(std::move(e));
            p += 46 + nameLen + extraLen + commentLen;
        }
    }

    std::vector<uint8_t> extract(const ZipEntry& e) const {
        if (e.uncompSize > lim_.maxEntryBytes) throw ZipError("entry exceeds per-entry cap: " + e.name);
        if (e.compSize > 0 && (double)e.uncompSize / (double)e.compSize > lim_.maxRatio)
            throw ZipError("entry exceeds compression-ratio cap (possible zip bomb): " + e.name);
        if (totalExtracted_ + e.uncompSize > lim_.maxTotalBytes)
            throw ZipError("cumulative extraction exceeds maxTotalBytes cap");
        totalExtracted_ += e.uncompSize;
        // local header: sig(4) ver(2) flag(2) method(2) time(2) date(2) crc(4)
        // comp(4) uncomp(4) nameLen(2) extraLen(2)
        size_t lh = e.localHeaderOff;
        if (r32(lh) != 0x04034b50) throw ZipError("bad local header: " + e.name);
        uint16_t nameLen = r16(lh + 26);
        uint16_t extraLen = r16(lh + 28);
        size_t dataOff = lh + 30 + nameLen + extraLen;
        if (dataOff + e.compSize > buf_.size()) throw ZipError("entry data oob: " + e.name);
        std::vector<uint8_t> out;
        if (e.method == 0) {                       // stored
            out.assign(buf_.begin() + dataOff, buf_.begin() + dataOff + e.compSize);
        } else if (e.method == 8) {                // deflate
            out.resize(e.uncompSize);
            z_stream zs; std::memset(&zs, 0, sizeof(zs));
            if (inflateInit2(&zs, -15) != Z_OK) throw ZipError("inflateInit failed");
            zs.next_in = const_cast<Bytef*>(&buf_[dataOff]);
            zs.avail_in = (uInt)e.compSize;
            zs.next_out = out.empty() ? nullptr : out.data();
            zs.avail_out = (uInt)out.size();
            int rc = inflate(&zs, Z_FINISH);
            inflateEnd(&zs);
            if (rc != Z_STREAM_END && !(rc == Z_OK && zs.avail_out == 0))
                throw ZipError("inflate failed for " + e.name);
        } else {
            throw ZipError("unsupported compression method for " + e.name);
        }
        // integrity: verify CRC-32
        uLong c = crc32(0L, Z_NULL, 0);
        c = crc32(c, out.empty() ? Z_NULL : out.data(), (uInt)out.size());
        if ((uint32_t)c != e.crc32) throw ZipError("CRC mismatch for " + e.name);
        return out;
    }
};

} // namespace apkbridge
