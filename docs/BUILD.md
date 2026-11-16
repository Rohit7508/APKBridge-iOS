# Build & Test Instructions

## Portable runtime + analyzer (Windows / Linux / macOS)
Everything except the iOS app is buildable and testable with no Mac.

```bash
# 1. C++ interpreter + conformance tests
cmake -S runtime -B runtime/build -DCMAKE_BUILD_TYPE=Release
cmake --build runtime/build -j
./runtime/build/runtime_tests tests/fixtures         # 6/6 expected

# 2. (re)generate the self-authored DEX fixtures (pure Python, no Android SDK)
python tests/dexgen/make_fixtures.py

# 3. analyzer unit + untrusted-input safety tests
python tests/analyzer/test_apk_analyzer.py           # 11/11 expected

# 4. three-way conformance: manifest vs JVM reference vs interpreter
python tests/run_conformance.py                      # requires javac/java

# 5. analyze any APK
python analyzer/apk_analyzer.py path/to/App.apk --json out.json
```

On **Windows**: install CMake + Visual Studio Build Tools (MSVC) or MinGW, and
Python 3; the exact commands above work (`runtime\build\runtime_tests.exe`).
A JDK is needed only for step 4's reference oracle.

## iOS app (requires macOS + Xcode — NOT possible on Windows/Linux)
The iOS host is provided as Swift source + a bridging header + an XcodeGen
spec (`ios/project.yml`). The C++ runtime compiles into the app as C++17.

```bash
brew install xcodegen
cd ios && xcodegen generate        # produces APKBridge.xcodeproj
open APKBridge.xcodeproj           # build/run from Xcode, or:
xcodebuild -project APKBridge.xcodeproj -scheme APKBridge -sdk iphoneos \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO
```

### Code-signing requirements (to install on a real iPhone 16 Pro Max)
An installable `.ipa` requires signing — CI (and this repo) cannot produce one
without credentials. You need:
- An Apple Developer account (free personal team works for 7-day sideload; paid
  team for 1-year and TestFlight).
- A **Development** signing certificate + a provisioning profile whose App ID
  matches `dev.apkbridge.host` and includes your device UDID.
- In Xcode: Signing & Capabilities → select your Team → let Xcode manage signing
  → Product ▸ Archive → Distribute (Ad Hoc / Development) → export `.ipa`.

### Sideloadly (installing the signed build)
Sideloadly installs an **already-built** `.ipa` onto a device using your Apple
ID for signing; it does **not** compile an iOS app and cannot turn this project
into an app on its own. Flow: build the `.app`/`.ipa` on a Mac (or via the
macOS CI job, then sign locally) → open Sideloadly → drag the `.ipa` → sign with
your Apple ID → install to the connected iPhone. Free Apple IDs expire the app
after 7 days and limit the number of sideloaded apps.

> There is currently **no signed, installed, device-verified IPA**. The macOS CI
> job builds only an UNSIGNED `.app` artifact. Any claim of an installed app
> must come from an actual signed build on a real device, which has not happened.
