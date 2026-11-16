# iOS Build Status — honest account

**There is no verified iOS `.app` or `.ipa` as of v1.0.** This document states
exactly what was and was not done, so "the workflow exists" is never mistaken
for "the build succeeded."

## Priority 1 this release: the build was attempted, not faked
I could not run the macOS compile from this container (no Apple toolchain), and
the macOS build runs on a GitHub Actions runner that a push triggers. **That push
was denied in this session and was not re-attempted or worked around.** No build
log, `.app`, or device run was fabricated. The exact Windows commands to push and
trigger the build yourself are in `docs/BUILD_FROM_WINDOWS.md`.

## What was verified in this (Linux) environment
- The C++ that compiles **into** the iOS app — `runtime/src/bridge.cpp` plus
  `dex.hpp`, `interp.hpp`, `zip.hpp`, `axml.hpp`, `framework.hpp`, `install.hpp` —
  builds cleanly with `g++ -std=c++17` and links `zlib`, and all runtime tests
  pass (49/49 with DCR). This is the same translation unit the app target
  compiles, and it includes the new `apkbridge_install_commit/recover` C ABI.
- The C ABI the Swift calls was exercised end-to-end via the CLI on the real
  DCR APK (import, list-classes, list-methods, run), and the install transaction
  is covered by interruption-recovery tests.

## What was NOT done, and cannot be done here
- **The Swift/SwiftUI app was not compiled.** There is no Swift or iOS toolchain
  on Linux (SwiftUI/UIKit are Apple-platform only). Any "successful iOS build"
  claim would be fabricated, so none is made.

## Static review performed on the Swift (in lieu of a compiler here)
- Removed `ContentUnavailableView` (iOS 17+) → replaced with an iOS 16-safe view.
- `NavigationStack` + `navigationDestination(for:)`, `LabeledContent`,
  `searchable`, `fileImporter` — all iOS 16-available.
- C interop: `const char*` → `String(cString:)` then `apkbridge_free`; int args
  passed via `withUnsafeBufferPointer`.
- `ImportedApp` is `Identifiable` + `Hashable` (needed by `ForEach` /
  `navigationDestination`); `MethodInfo.static` escaped as a keyword.
These are review findings, not a compiler's verdict; the macOS CI job is what
will actually confirm them.

## How to produce the real build (macOS required)
```bash
brew install xcodegen
cd ios && xcodegen generate
xcodebuild -project APKBridge.xcodeproj -scheme APKBridge -sdk iphoneos \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO | tee ios_build.log
```
The GitHub Actions `ios-build` job (supported macOS 15 runner) runs exactly this and
uploads the **unsigned** `.app`. If it fails, the job log contains the real
compiler errors to fix — that log, not this file, is the source of truth.

## To get it onto an iPhone 16 Pro Max
Signing + sideload steps are in `docs/BUILD_FROM_WINDOWS.md` (Step 5) and
`BUILD.md`. A signed, installed, device-run build is the only thing that may be
called "running on device" — not reached yet.
