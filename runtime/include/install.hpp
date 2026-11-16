// APKBridge runtime :: crash-safe install transaction (header-only, C++17)
// Atomically replaces an app's CODE directory (<sandbox>/dex) while preserving
// user data (<sandbox>/files, databases, shared_prefs) and keeping a backup
// (<sandbox>/dex.old) until the new version is committed. A journal marker
// (<sandbox>/.txn) lets recover() bring an interrupted update to a consistent
// state on next launch — the previous version is never lost mid-swap.
//
// Layout during a commit:
//   dex.new  prepared new code (validated) — staged before the swap
//   dex      live code
//   dex.old  backup of the previous live code, kept until commit verified
//   .txn     journal marker: "BEGIN" | "DONE" (absent = no update in flight)
#pragma once
#include <string>
#include <fstream>
#include <filesystem>
#include <system_error>

namespace apkbridge {

struct InstallResult { bool ok=false; std::string state; std::string message; };

class InstallTxn {
public:
    // Prepare: copy a validated staging code dir into <sandbox>/dex.new.
    // (Validation of the staging contents happens before this is called.)
    static InstallResult prepare(const std::string& sandbox, const std::string& stagingDex) {
        namespace fs = std::filesystem; std::error_code e;
        fs::path nd = fs::path(sandbox)/"dex.new";
        if (!fs::is_directory(stagingDex, e) || e)
            return {false,"","staging code directory is missing"};
        if (!hasRegularFile(stagingDex))
            return {false,"","staging code is empty"};
        fs::remove_all(nd, e);
        if (e) return {false,"","cannot clear previous dex.new: "+e.message()};
        fs::create_directories(sandbox, e);
        if (e) return {false,"","cannot create sandbox: "+e.message()};
        fs::copy(stagingDex, nd, fs::copy_options::recursive, e);
        if (e) {
            std::error_code cleanup;
            fs::remove_all(nd, cleanup);
            return {false,"","prepare copy failed: "+e.message()};
        }
        if (!hasRegularFile(nd)) {
            fs::remove_all(nd, e);
            return {false,"","prepared code is empty"};
        }
        return {true,"PREPARED",""};
    }

    // Commit the prepared dex.new into dex, keeping dex.old until verified.
    // `stopAfter` (test-only) simulates a crash after step N (0 = run fully).
    static InstallResult commit(const std::string& sandbox, int stopAfter=0) {
        namespace fs = std::filesystem; std::error_code e;
        fs::path base(sandbox), dex=base/"dex", old=base/"dex.old", nd=base/"dex.new";
        if (!hasRegularFile(nd)) return {false,"","no valid prepared dex.new"};
        // step 1: journal BEGIN
        std::string markerError;
        if (!writeMarker(sandbox, "BEGIN", markerError))
            return {false,"","journal BEGIN failed: "+markerError};
        if (stopAfter==1) return {true,"BEGIN","stopped(1)"};
        // step 2: move current live code aside as backup (only if it exists)
        if (fs::exists(dex)) {
            fs::remove_all(old, e);
            if (e) return {false,"","old backup cleanup failed: "+e.message()};
            fs::rename(dex, old, e);
            if (e) return {false,"","backup rename failed: "+e.message()};
        }
        if (stopAfter==2) return {true,"BACKED_UP","stopped(2)"};
        // step 3: promote new code to live
        fs::rename(nd, dex, e);
        if (e) {
            restoreBackup(old, dex);
            return {false,"","promote rename failed: "+e.message()};
        }
        if (stopAfter==3) return {true,"PROMOTED","stopped(3)"};
        // step 4: verify new live code, then journal DONE
        if (!hasRegularFile(dex)) {
            fs::remove_all(dex, e);
            restoreBackup(old, dex);
            return {false,"","verify failed: live dex empty"};
        }
        if (!writeMarker(sandbox, "DONE", markerError)) {
            fs::remove_all(dex, e);
            restoreBackup(old, dex);
            return {false,"","journal DONE failed: "+markerError};
        }
        if (stopAfter==4) return {true,"DONE","stopped(4)"};
        // step 5: drop backup + marker — fully committed
        fs::remove_all(old, e);
        if (e) return {false,"DONE","backup cleanup failed: "+e.message()};
        if (!clearMarker(sandbox, markerError))
            return {false,"DONE","journal cleanup failed: "+markerError};
        return {true,"COMMITTED",""};
    }

    // Bring an interrupted sandbox to a consistent state (run on app launch).
    static InstallResult recover(const std::string& sandbox) {
        namespace fs = std::filesystem; std::error_code e;
        fs::path base(sandbox), dex=base/"dex", old=base/"dex.old", nd=base/"dex.new";
        std::string m = readMarker(sandbox);
        if (m.empty()) {                      // no update in flight
            fs::remove_all(nd, e);            // discard any abandoned prepared code
            if (e) return {false,"","abandoned code cleanup failed: "+e.message()};
            if (fs::exists(old)) {
                if (hasRegularFile(dex)) fs::remove_all(old, e);
                else if (!restoreBackup(old, dex))
                    return {false,"","orphan backup recovery failed"};
                if (e) return {false,"","orphan backup recovery failed: "+e.message()};
            }
            return {true, fs::exists(dex)?"INTACT":"EMPTY", "no journal"};
        }
        if (m != "BEGIN" && m != "DONE")
            return {false,"","invalid install journal state"};
        if (m == "DONE") {                    // crashed after promote, before cleanup
            if (!hasRegularFile(dex) && hasRegularFile(old)) {
                fs::remove_all(dex, e);
                if (!restoreBackup(old, dex)) return {false,"","failed to restore backup after invalid promoted code"};
                fs::remove_all(nd, e);
                std::string markerError;
                if (!clearMarker(sandbox, markerError)) return {false,"","journal cleanup failed: "+markerError};
                return {true,"ROLLED_BACK","invalid promoted code; restored previous code"};
            }
            if (!hasRegularFile(dex)) return {false,"","DONE journal has no valid live code"};
            fs::remove_all(old, e); if (e) return {false,"","backup cleanup failed: "+e.message()};
            fs::remove_all(nd, e); if (e) return {false,"","prepared cleanup failed: "+e.message()};
            std::string markerError;
            if (!clearMarker(sandbox, markerError)) return {false,"","journal cleanup failed: "+markerError};
            return {true,"COMMITTED","finalized after DONE"};
        }
        // m == "BEGIN": decide by what is present
        bool hasDex=fs::exists(dex), hasOld=fs::exists(old);
        if (hasDex && hasOld) {               // new promoted but DONE not journaled -> accept new
            if (hasRegularFile(dex)) {
                fs::remove_all(old, e);
                if (e) return {false,"","backup cleanup failed: "+e.message()};
                fs::remove_all(nd, e);
                std::string markerError;
                if (!clearMarker(sandbox, markerError)) return {false,"","journal cleanup failed: "+markerError};
                return {true,"COMMITTED","new code already live; backup dropped"};
            }
            fs::remove_all(dex, e);
            if (!restoreBackup(old, dex)) return {false,"","invalid live code and backup restore failed"};
            fs::remove_all(nd, e);
            std::string markerError;
            if (!clearMarker(sandbox, markerError)) return {false,"","journal cleanup failed: "+markerError};
            return {true,"ROLLED_BACK","invalid live code; restored previous code"};
        }
        if (!hasDex && hasOld) {              // crashed mid-swap -> restore previous
            if (!restoreBackup(old, dex)) return {false,"","failed to restore previous code"};
            fs::remove_all(nd, e);
            std::string markerError;
            if (!clearMarker(sandbox, markerError)) return {false,"","journal cleanup failed: "+markerError};
            return {true,"ROLLED_BACK","restored previous code"};
        }
        // dex present, no backup: nothing was moved yet -> keep current, drop new
        if (hasDex && !hasRegularFile(dex)) return {false,"","current live code is invalid"};
        fs::remove_all(nd, e);
        std::string markerError;
        if (!clearMarker(sandbox, markerError)) return {false,"","journal cleanup failed: "+markerError};
        return {true, hasDex?"ROLLED_BACK":"EMPTY", "kept current code"};
    }

private:
    static bool hasRegularFile(const std::filesystem::path& d) {
        std::error_code e;
        if (!std::filesystem::is_directory(d, e)) return false;
        for (auto& ent : std::filesystem::recursive_directory_iterator(
                 d, std::filesystem::directory_options::skip_permission_denied, e)) {
            if (e) return false;
            if (ent.is_regular_file(e) && !e) return true;
        }
        return false;
    }
    static bool restoreBackup(const std::filesystem::path& old, const std::filesystem::path& dex) {
        namespace fs = std::filesystem; std::error_code e;
        if (!fs::exists(old)) return false;
        if (fs::exists(dex)) { fs::remove_all(dex, e); if (e) return false; }
        fs::rename(old, dex, e);
        return !e && hasRegularFile(dex);
    }
    static std::string markerPath(const std::string& s){ return (std::filesystem::path(s)/".txn").string(); }
    static bool writeMarker(const std::string& s, const std::string& v, std::string& error){
        // write-temp + rename for an atomic marker update
        std::string tmp = markerPath(s)+".tmp";
        {
            std::ofstream f(tmp, std::ios::trunc);
            if (!f) { error="cannot create marker temp file"; return false; }
            f << v; f.flush();
            if (!f) { error="cannot write marker temp file"; return false; }
        }
        std::error_code e;
        std::filesystem::remove(markerPath(s), e);
        e.clear();
        std::filesystem::rename(tmp, markerPath(s), e);
        if (e) { error=e.message(); return false; }
        return true;
    }
    static std::string readMarker(const std::string& s){
        std::ifstream f(markerPath(s)); if(!f) return ""; std::string v; std::getline(f,v); return v;
    }
    static bool clearMarker(const std::string& s, std::string& error){
        std::error_code e; std::filesystem::remove(markerPath(s), e);
        if (e) { error=e.message(); return false; }
        std::filesystem::remove(markerPath(s)+".tmp", e);
        if (e) { error=e.message(); return false; }
        return true;
    }
};

} // namespace apkbridge
