// ContentView.swift — SwiftUI host (iOS 16+).
// Honesty enforced in code: the UI shows ONLY real interpreter output. There is
// no simulated Android screen, and an app is never labelled "running" — only a
// single method's real result (int / exception / unsupported) is ever shown.
//
// Reviewed for iOS 16 (no iOS 17-only APIs such as ContentUnavailableView).
// NOT compiled in this Linux workspace; verified by the macOS CI job.
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var library = AppLibrary()
    @State private var showImporter = false
    @State private var banner: String?

    private var apkType: UTType { UTType(filenameExtension: "apk") ?? .data }

    var body: some View {
        NavigationStack {
            Group {
                if library.apps.isEmpty {
                    EmptyLibraryView()
                } else {
                    List {
                        ForEach(library.apps) { app in
                            NavigationLink(value: app) { AppRow(app: app) }
                        }
                        .onDelete { idx in idx.map { library.apps[$0] }.forEach(library.remove) }
                    }
                }
            }
            .navigationTitle("APK Library")
            .navigationDestination(for: ImportedApp.self) { AppDetail(app: $0, library: library) }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    NavigationLink { RemoteAndroidSetupView() } label: {
                        Label("Remote Android", systemImage: "display")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button { showImporter = true } label: { Image(systemName: "plus") }
                }
            }
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [apkType],
                          allowsMultipleSelection: true) { result in
                if case .success(let urls) = result { importAPKs(urls) }
                else if case .failure(let err) = result { banner = err.localizedDescription }
            }
            .alert("Import", isPresented: Binding(get: { banner != nil },
                                                  set: { if !$0 { banner = nil } })) {
                Button("OK", role: .cancel) { banner = nil }
            } message: { Text(banner ?? "") }
        }
    }

    private func importAPKs(_ urls: [URL]) {
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }

            let fm = FileManager.default
            // (1) Extract into a UNIQUE temp dir — never touch any install yet.
            let staging = library.stagingDir()
            defer { try? fm.removeItem(at: staging) }                 // (7) cleanup
            let res = RuntimeBridge.importAPK(apkPath: url.path, destDir: staging.path)

            // (2)+(3) Validate: ok, package id, and every DEX present & readable.
            guard res.ok, let pkg = res.package, !pkg.isEmpty else {
                banner = "Could not import \(url.lastPathComponent): \(res.error ?? "invalid APK")"
                continue
            }
            let dexes = res.dexFiles ?? []
            let allReadable = !dexes.isEmpty && dexes.allSatisfy {
                fm.isReadableFile(atPath: $0.path) &&
                (try? Data(contentsOf: URL(fileURLWithPath: $0.path), options: .mappedIfSafe)) != nil &&
                RuntimeBridge.inspect(dexPath: $0.path) != nil     // parses as a real DEX
            }
            guard allReadable else {
                banner = "Import of \(url.lastPathComponent) failed validation (unreadable/invalid DEX)."
                continue   // staging is cleaned by defer; NO existing install was touched
            }

            // (4)+(8) Preserve the existing install and its user data.
            let sandbox = library.sandbox(forPackage: pkg)        // files/databases/shared_prefs live here
            let dexDir = sandbox.appendingPathComponent("dex")

            // Build dex references the library will record (point at the live dex/).
            var dexRefs: [ImportedApp.DexRef] = dexes.map {
                .init(name: $0.name, path: dexDir.appendingPathComponent($0.name).path)
            }

            // (5)+(6) Crash-safe swap of CODE ONLY via the tested C++ transaction:
            // prepares dex.new from the validated staging dir, keeps dex.old as a
            // backup until the new code is in place and verified, and leaves a
            // journal so an interrupted update auto-recovers on next launch.
            // User data (files/databases/shared_prefs) is never touched.
            let commit = RuntimeBridge.installCommit(sandbox: sandbox.path, stagingDex: staging.path)
            guard commit.ok else {
                // recover() guarantees a consistent state (previous code intact).
                RuntimeBridge.installRecover(sandbox: sandbox.path)
                banner = "Update of \(pkg) failed; previous version preserved."
                continue
            }

            // (8) Carry over prior logs/settings on update (user data in sandbox
            // subdirs — files/databases/shared_prefs — is never touched above).
            let prior = library.apps.first { $0.id == pkg }
            let app = ImportedApp(
                package: pkg,
                applicationClass: res.applicationClass ?? "",
                versionName: res.versionName ?? "",
                versionCode: res.versionCode ?? -1,
                minSdk: res.minSdk ?? -1,
                targetSdk: res.targetSdk ?? -1,
                permissions: res.permissions ?? [],
                dexFiles: dexRefs,
                nativeLibs: (res.nativeLibs ?? []).map { .init(abi: $0.abi, name: $0.name) },
                bundleDir: sandbox.path,
                runLog: prior?.runLog ?? [],
                settings: prior?.settings ?? [:])
            library.upsert(app)   // dedupe by package id
        }
    }
}

private struct EmptyLibraryView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shippingbox").font(.system(size: 48)).foregroundStyle(.secondary)
            Text("No APKs imported").font(.headline)
            Text("Tap + to import one or more .apk files. APKBridge analyzes them and can run supported DEX methods.")
                .font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).padding(.horizontal, 40)
        }
    }
}

private struct AppRow: View {
    let app: ImportedApp
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(app.package).font(.headline)
            Text("\(app.versionName) · \(app.dexFiles.count) dex · \(app.nativeLibs.count) native libs")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
