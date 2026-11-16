// DetailViews.swift — app detail, DEX class browser, method browser, and the
// real method-execution UI. (iOS 16+; reviewed, not compiled here.)
import SwiftUI

struct AppDetail: View {
    let app: ImportedApp
    @ObservedObject var library: AppLibrary

    var body: some View {
        Form {
            Section("Package") {
                LabeledContent("Name", value: app.package)
                LabeledContent("Version", value: "\(app.versionName) (code \(app.versionCode))")
                LabeledContent("SDK", value: "min \(app.minSdk) / target \(app.targetSdk)")
                LabeledContent("DEX files", value: "\(app.dexFiles.count)")
                LabeledContent("Native ABIs", value: app.abis.isEmpty ? "none" : app.abis.joined(separator: ", "))
                LabeledContent("Native libs", value: "\(app.nativeLibs.count)")
                LabeledContent("Permissions", value: "\(app.permissions.count)")
            }
            Section("Run supported DEX methods") {
                if let dex = app.primaryDex {
                    NavigationLink("Browse classes & methods") {
                        ClassBrowser(dexPath: dex, app: app, library: library)
                    }
                    if !app.applicationClass.isEmpty {
                        NavigationLink("Run Application lifecycle") {
                            LifecycleRunner(app: app, library: library)
                        }
                    }
                } else {
                    Text("No DEX available").foregroundStyle(.secondary)
                }
                Text("Only the real interpreter runs here. Unsupported opcodes/APIs are reported explicitly; no Android app is launched.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !app.permissions.isEmpty {
                Section("Permissions (\(app.permissions.count))") {
                    ForEach(app.permissions, id: \.self) { Text($0).font(.caption.monospaced()) }
                }
            }
            Section("Run log") {
                if app.runLog.isEmpty { Text("No runs yet").foregroundStyle(.secondary) }
                else { ForEach(app.runLog.reversed(), id: \.self) { Text($0).font(.caption.monospaced()) } }
            }
        }
        .navigationTitle(app.package)
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ClassBrowser: View {
    let dexPath: String
    let app: ImportedApp
    @ObservedObject var library: AppLibrary

    @State private var classes: [String] = []
    @State private var total = 0
    @State private var query = ""

    private var shown: [String] {
        query.isEmpty ? classes
            : classes.filter { $0.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        List {
            Section {
                ForEach(shown, id: \.self) { cls in
                    NavigationLink(cls) {
                        MethodBrowser(dexPath: dexPath, className: cls, app: app, library: library)
                    }
                    .font(.caption.monospaced())
                }
            } footer: {
                if classes.count < total {
                    Button("Load more (\(classes.count)/\(total))") { loadMore() }
                }
            }
        }
        .searchable(text: $query, prompt: "Filter classes")
        .navigationTitle("Classes")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { if classes.isEmpty { loadMore() } }
    }

    private func loadMore() {
        let page = RuntimeBridge.listClasses(dexPath: dexPath, offset: classes.count, limit: 200)
        total = page.total
        classes.append(contentsOf: page.classes)
    }
}

struct MethodBrowser: View {
    let dexPath: String
    let className: String
    let app: ImportedApp
    @ObservedObject var library: AppLibrary
    @State private var methods: [MethodInfo] = []

    var body: some View {
        List(methods) { m in
            if m.runnable {
                NavigationLink {
                    MethodRunner(dexPath: dexPath, className: className, method: m,
                                 app: app, library: library)
                } label: { MethodRow(m: m) }
            } else {
                MethodRow(m: m)   // not runnable in current subset -> not tappable
            }
        }
        .navigationTitle(shortName(className))
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if methods.isEmpty {
                methods = RuntimeBridge.listMethods(dexPath: dexPath, className: className)
            }
        }
    }
    private func shortName(_ d: String) -> String {
        d.split(separator: "/").last.map(String.init)?.replacingOccurrences(of: ";", with: "") ?? d
    }
}

private struct MethodRow: View {
    let m: MethodInfo
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text(m.name).font(.body.monospaced())
                Text("(\(m.shorty))\(m.`static` ? " · static" : "")\(m.hasCode ? "" : " · no code")")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            if m.runnable { Image(systemName: "play.circle").foregroundStyle(.green) }
            else { Text("unsupported").font(.caption2).foregroundStyle(.orange) }
        }
    }
}

struct MethodRunner: View {
    let dexPath: String
    let className: String
    let method: MethodInfo
    let app: ImportedApp
    @ObservedObject var library: AppLibrary

    @State private var argText: [String]
    @State private var outcome: RunOutcome?

    init(dexPath: String, className: String, method: MethodInfo,
         app: ImportedApp, library: AppLibrary) {
        self.dexPath = dexPath; self.className = className; self.method = method
        self.app = app; self.library = library
        _argText = State(initialValue: Array(repeating: "0", count: method.argCount))
    }

    var body: some View {
        Form {
            Section("Method") {
                LabeledContent("Class", value: className).font(.caption.monospaced())
                LabeledContent("Name", value: method.name)
                LabeledContent("Shorty", value: method.shorty)
            }
            if method.argCount > 0 {
                Section("Integer arguments") {
                    ForEach(0..<method.argCount, id: \.self) { i in
                        HStack {
                            Text("arg \(i)")
                            TextField("int", text: Binding(
                                get: { argText[i] },
                                set: { argText[i] = $0 }))
                                .keyboardType(.numbersAndPunctuation)
                                .multilineTextAlignment(.trailing)
                        }
                    }
                }
            }
            Section {
                Button("Run on interpreter") { runIt() }
            }
            if let o = outcome {
                Section("Result (real interpreter output)") {
                    LabeledContent("Kind", value: o.kind)
                    if !o.value.isEmpty { LabeledContent("Value", value: o.value) }
                    if !o.extra.isEmpty { LabeledContent("Detail", value: o.extra) }
                }
            }
        }
        .navigationTitle(method.name)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func runIt() {
        let args = argText.map { Int32($0.trimmingCharacters(in: .whitespaces)) ?? 0 }
        let o = RuntimeBridge.run(dexPath: dexPath, cls: className,
                                  method: method.name, shorty: method.shorty, args: args)
        outcome = o
        let argsDesc = args.map(String.init).joined(separator: ",")
        library.log(app.id, "\(className)->\(method.name)(\(argsDesc)) => \(o.kind) \(o.value)")
    }
}

// Runs a package's Application lifecycle (construct instance, <init>, onCreate)
// in the chosen mode, showing the execution trace, logcat and stop reason.
struct LifecycleRunner: View {
    let app: ImportedApp
    @ObservedObject var library: AppLibrary
    @State private var mode: ExecMode = .functional
    @State private var result: RunOutcomeEx?

    var body: some View {
        Form {
            Section("Target") {
                LabeledContent("Application", value: app.applicationClass)
                Picker("Mode", selection: $mode) {
                    ForEach(ExecMode.allCases) { Text($0.label).tag($0) }
                }.pickerStyle(.segmented)
            }
            Section { Button("Run lifecycle") { runIt() } }
            if let r = result {
                Section("Result") {
                    LabeledContent("Kind", value: r.kind)
                    if !r.value.isEmpty { Text(r.value).font(.caption.monospaced()) }
                }
                if let t = r.trace {
                    Section("Framework calls (\(t.entries.filter { $0.kind == "framework" }.count))") {
                        ForEach(t.entries.filter { $0.kind == "framework" }, id: \.signature) { e in
                            VStack(alignment: .leading) {
                                Text(e.signature).font(.caption2.monospaced())
                                Text("\(e.category)\(e.simulated ? " · simulated" : " · modeled") → \(e.outcome)")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                    if !t.logcat.isEmpty {
                        Section("Logcat") { ForEach(t.logcat, id: \.self) { Text($0).font(.caption2.monospaced()) } }
                    }
                }
            }
        }
        .navigationTitle("Lifecycle").navigationBarTitleDisplayMode(.inline)
    }

    private func runIt() {
        guard let dex = app.primaryDex else { return }
        let r = RuntimeBridge.runLifecycle(dexPath: dex, appClass: app.applicationClass, mode: mode)
        result = r
        library.log(app.id, "lifecycle(\(mode.rawValue)) => \(r.kind) \(r.value)")
    }
}
