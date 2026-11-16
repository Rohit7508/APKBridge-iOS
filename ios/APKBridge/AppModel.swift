// AppModel.swift — imported-app model, per-APK isolated storage, and a
// persisted library. Each APK gets its own sandbox directory; metadata is
// saved to disk and reloaded on launch. (iOS 16+; reviewed, not compiled here.)
import Foundation

struct ImportedApp: Identifiable, Codable, Hashable {
    var package: String
    var applicationClass: String = ""
    var versionName: String
    var versionCode: Int
    var minSdk: Int
    var targetSdk: Int
    var permissions: [String]
    var dexFiles: [DexRef]
    var nativeLibs: [NativeLib]
    var bundleDir: String
    var runLog: [String]
    var settings: [String: String]

    struct DexRef: Codable, Hashable { let name: String; let path: String }
    struct NativeLib: Codable, Hashable { let abi: String; let name: String }

    // Identity is the package id (unique; dedupe relies on it).
    var id: String { package.isEmpty ? bundleDir : package }
    static func == (a: ImportedApp, b: ImportedApp) -> Bool { a.id == b.id }
    func hash(into h: inout Hasher) { h.combine(id) }

    var primaryDex: String? { dexFiles.first?.path }
    var abis: [String] { Array(Set(nativeLibs.map { $0.abi })).sorted() }
}

final class AppLibrary: ObservableObject {
    @Published private(set) var apps: [ImportedApp] = []

    private let fm = FileManager.default

    private var root: URL {
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("APKBridgeApps", isDirectory: true)
        try? fm.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }
    private var libraryFile: URL { root.appendingPathComponent("library.json") }

    init() { load() }

    /// A fresh temporary extraction directory (used before the package id is
    /// known; dex files are then moved into the package sandbox).
    func stagingDir() -> URL {
        let dir = root.appendingPathComponent("_staging", isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Isolated sandbox directory for a package id (stable across launches).
    func sandbox(forPackage pkg: String) -> URL {
        let safe = pkg.isEmpty ? "unknown-\(UUID().uuidString)" :
            pkg.replacingOccurrences(of: "/", with: "_")
        let dir = root.appendingPathComponent(safe, isDirectory: true)
        for sub in ["files", "databases", "dex"] {
            try? fm.createDirectory(at: dir.appendingPathComponent(sub),
                                    withIntermediateDirectories: true)
        }
        return dir
    }

    /// Insert or replace by package id (prevents duplicate package IDs).
    func upsert(_ app: ImportedApp) {
        if let i = apps.firstIndex(where: { $0.id == app.id }) { apps[i] = app }
        else { apps.append(app) }
        save()
    }

    func remove(_ app: ImportedApp) {
        apps.removeAll { $0.id == app.id }
        try? fm.removeItem(atPath: app.bundleDir)
        save()
    }

    func log(_ id: String, _ line: String) {
        guard let i = apps.firstIndex(where: { $0.id == id }) else { return }
        let ts = ISO8601DateFormatter().string(from: Date())
        apps[i].runLog.append("[\(ts)] \(line)")
        if apps[i].runLog.count > 200 { apps[i].runLog.removeFirst(apps[i].runLog.count - 200) }
        save()
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(apps) else { return }
        try? data.write(to: libraryFile, options: .atomic)
    }
    private func load() {
        guard let data = try? Data(contentsOf: libraryFile),
              let decoded = try? JSONDecoder().decode([ImportedApp].self, from: data) else { return }
        apps = decoded
        // Auto-recover any install interrupted by a crash/kill mid-update: the
        // tested transaction restores the previous code or finalizes the new one,
        // never leaving a half-written dex/. User data is untouched.
        for app in apps { RuntimeBridge.installRecover(sandbox: app.bundleDir) }
    }
}
