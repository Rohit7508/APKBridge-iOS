// RuntimeBridge.swift — Swift wrapper over the C ABI of the C++ runtime core.
// The DEX parse / ZIP import / interpret logic is the SAME C++ code tested on
// Linux (runtime/). iOS only hosts it. No Android code runs natively here.
//
// NOTE: this file calls C functions declared in apkbridge_runtime.h via the
// bridging header. It is written for iOS 16+ and has NOT been compiled in this
// Linux workspace (no Swift/iOS toolchain); it is verified by review + the
// macOS CI job, not here.
import Foundation

// MARK: - Decoded result types

struct ImportResult: Codable {
    let ok: Bool
    var error: String?
    var package: String?
    var applicationClass: String?
    var versionName: String?
    var versionCode: Int?
    var minSdk: Int?
    var targetSdk: Int?
    var permissions: [String]?
    var dexFiles: [DexRef]?
    var nativeLibs: [NativeLib]?
    struct DexRef: Codable, Hashable { let name: String; let path: String }
    struct NativeLib: Codable, Hashable { let abi: String; let name: String }
}

struct ClassPage: Codable { let total: Int; let offset: Int; let classes: [String] }

struct MethodList: Codable {
    let `class`: String
    let methods: [MethodInfo]
}
struct MethodInfo: Codable, Hashable, Identifiable {
    let name: String
    let shorty: String
    let `static`: Bool
    let hasCode: Bool
    let runnable: Bool
    var id: String { name + ":" + shorty }
    /// number of int parameters the interpreter expects (shorty minus return char)
    var argCount: Int { max(0, shorty.count - 1) }
}

struct RunOutcome: Codable {
    let kind: String   // int | ref | void | exception | unsupported | error
    let value: String
    let extra: String
}

struct DexInspection: Codable {
    let classes: Int
    let methods: Int
    let strings: Int
}

enum ExecMode: String, CaseIterable, Identifiable {
    case analysis, functional
    var id: String { rawValue }
    var label: String { self == .analysis ? "Analysis" : "Functional" }
}

struct TraceEntry: Codable, Hashable {
    let kind: String; let signature: String; let category: String
    let simulated: Bool; let outcome: String; let detail: String
}
struct ExecTrace: Codable { let entries: [TraceEntry]; let logcat: [String] }
struct RunOutcomeEx: Codable {
    let kind: String; let value: String; let extra: String
    var mode: String?; var trace: ExecTrace?
}

// MARK: - Bridge

enum RuntimeBridge {
    private static func call(_ c: UnsafePointer<CChar>?) -> Data? {
        guard let c else { return nil }
        defer { apkbridge_free(c) }
        return String(cString: c).data(using: .utf8)
    }

    static func importAPK(apkPath: String, destDir: String) -> ImportResult {
        guard let data = call(apkbridge_import_apk(apkPath, destDir)),
              let r = try? JSONDecoder().decode(ImportResult.self, from: data) else {
            return ImportResult(ok: false, error: "bridge/decode failure")
        }
        return r
    }

    static func listClasses(dexPath: String, offset: Int, limit: Int) -> ClassPage {
        guard let data = call(apkbridge_list_classes(dexPath, Int32(offset), Int32(limit))),
              let r = try? JSONDecoder().decode(ClassPage.self, from: data) else {
            return ClassPage(total: 0, offset: offset, classes: [])
        }
        return r
    }

    static func listMethods(dexPath: String, className: String) -> [MethodInfo] {
        guard let data = call(apkbridge_list_methods(dexPath, className)),
              let r = try? JSONDecoder().decode(MethodList.self, from: data) else { return [] }
        return r.methods
    }

    /// Parse a DEX through the C++ core and return its measured table counts.
    /// Error JSON intentionally fails this strict decode and becomes nil.
    static func inspect(dexPath: String) -> DexInspection? {
        guard let data = call(apkbridge_inspect_dex(dexPath)),
              let r = try? JSONDecoder().decode(DexInspection.self, from: data) else {
            return nil
        }
        return r
    }

    static func run(dexPath: String, cls: String, method: String,
                    shorty: String, args: [Int32]) -> RunOutcome {
        let c = args.withUnsafeBufferPointer { buf in
            apkbridge_run_method(dexPath, cls, method, shorty, buf.baseAddress, Int32(args.count))
        }
        guard let data = call(c),
              let r = try? JSONDecoder().decode(RunOutcome.self, from: data) else {
            return RunOutcome(kind: "error", value: "bridge/decode failure", extra: "")
        }
        return r
    }

    /// Run with an explicit mode and capture the execution trace + logcat.
    static func runEx(dexPath: String, cls: String, method: String, shorty: String,
                      args: [Int32], mode: ExecMode) -> RunOutcomeEx {
        let c = args.withUnsafeBufferPointer { buf in
            apkbridge_run_method_mode(dexPath, cls, method, shorty,
                                      buf.baseAddress, Int32(args.count), mode.rawValue)
        }
        guard let data = call(c),
              let r = try? JSONDecoder().decode(RunOutcomeEx.self, from: data) else {
            return RunOutcomeEx(kind: "error", value: "bridge/decode failure", extra: "")
        }
        return r
    }

    struct InstallState: Codable { let ok: Bool; let state: String; var error: String?; var note: String? }

    /// Crash-safe commit of a validated staging code dir into the app sandbox
    /// (keeps a backup until verified). Runs the tested C++ transaction.
    static func installCommit(sandbox: String, stagingDex: String) -> InstallState {
        guard let data = call(apkbridge_install_commit(sandbox, stagingDex)),
              let r = try? JSONDecoder().decode(InstallState.self, from: data) else {
            return InstallState(ok: false, state: "", error: "bridge failure")
        }
        return r
    }
    /// Recover an interrupted install (call on launch, per app sandbox).
    @discardableResult
    static func installRecover(sandbox: String) -> InstallState {
        guard let data = call(apkbridge_install_recover(sandbox)),
              let r = try? JSONDecoder().decode(InstallState.self, from: data) else {
            return InstallState(ok: false, state: "", error: "bridge failure")
        }
        return r
    }

    /// Model framework instantiation + initial lifecycle for an Application class.
    static func runLifecycle(dexPath: String, appClass: String, mode: ExecMode) -> RunOutcomeEx {
        let c = apkbridge_run_lifecycle(dexPath, appClass, mode.rawValue)
        guard let data = call(c),
              let r = try? JSONDecoder().decode(RunOutcomeEx.self, from: data) else {
            return RunOutcomeEx(kind: "error", value: "bridge/decode failure", extra: "")
        }
        return r
    }
}
