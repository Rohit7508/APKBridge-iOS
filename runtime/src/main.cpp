// APKBridge runtime CLI — exercises the SAME C ABI the iOS host calls.
// Subcommands:
//   import  <app.apk> <destDir>
//   classes <file.dex> [offset] [limit]
//   methods <file.dex> <Lclass;>
//   run     <file.dex> <Lclass;> <method> <shorty> [int args...]
//   inspect <file.dex>
// Prints the C ABI's JSON verbatim.
#include "apkbridge_runtime.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int emit(const char* json) {
    if (!json) { std::fprintf(stderr, "null result\n"); return 1; }
    std::printf("%s\n", json);
    bool unsupported = std::strstr(json, "\"kind\":\"unsupported\"") != nullptr
                    || std::strstr(json, "\"ok\":false") != nullptr;
    apkbridge_free(json);
    return unsupported ? 3 : 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage:\n"
            "  apkbridge_run import  <app.apk> <destDir>\n"
            "  apkbridge_run classes <file.dex> [offset] [limit]\n"
            "  apkbridge_run methods <file.dex> <Lclass;>\n"
            "  apkbridge_run run     <file.dex> <Lclass;> <method> <shorty> [int args...]\n"
            "  apkbridge_run inspect <file.dex>\n");
        return 2;
    }
    std::string cmd = argv[1];
    if (cmd == "import" && argc >= 4)
        return emit(apkbridge_import_apk(argv[2], argv[3]));
    if (cmd == "classes" && argc >= 3) {
        int off = argc >= 4 ? std::atoi(argv[3]) : 0;
        int lim = argc >= 5 ? std::atoi(argv[4]) : 100;
        return emit(apkbridge_list_classes(argv[2], off, lim));
    }
    if (cmd == "methods" && argc >= 4)
        return emit(apkbridge_list_methods(argv[2], argv[3]));
    if (cmd == "run" && argc >= 6) {
        std::vector<int32_t> args; const char* mode = nullptr;
        for (int i = 6; i < argc; ++i) {
            if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) { mode = argv[++i]; }
            else args.push_back((int32_t)std::strtol(argv[i], nullptr, 10));
        }
        if (mode)
            return emit(apkbridge_run_method_mode(argv[2], argv[3], argv[4], argv[5],
                                                  args.data(), (int)args.size(), mode));
        return emit(apkbridge_run_method(argv[2], argv[3], argv[4], argv[5],
                                         args.data(), (int)args.size()));
    }
    if (cmd == "lifecycle" && argc >= 4) {
        const char* mode = nullptr;
        for (int i = 4; i < argc; ++i) if (std::strcmp(argv[i],"--mode")==0 && i+1<argc) mode=argv[++i];
        return emit(apkbridge_run_lifecycle(argv[2], argv[3], mode));
    }
    if (cmd == "inspect" && argc >= 3)
        return emit(apkbridge_inspect_dex(argv[2]));

    // Back-compat: `apkbridge_run <dex> <cls> <method> <shorty> [args] [--json]`
    if (argc >= 5 && cmd != "import" && cmd != "classes" && cmd != "methods"
        && cmd != "run" && cmd != "inspect") {
        std::vector<int32_t> args;
        for (int i = 5; i < argc; ++i) if (std::strcmp(argv[i], "--json"))
            args.push_back((int32_t)std::strtol(argv[i], nullptr, 10));
        return emit(apkbridge_run_method(argv[1], argv[2], argv[3], argv[4],
                                         args.data(), (int)args.size()));
    }
    std::fprintf(stderr, "bad arguments\n");
    return 2;
}
