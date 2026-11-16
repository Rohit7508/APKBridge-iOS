# APKBridge iOS (v1.0.1)

A multi-APK compatibility-runtime research project: import Android APKs, browse
their DEX, and execute a supported subset of Dalvik bytecode through a portable,
tested C++ runtime — with an iOS SwiftUI host over the same engine. Nothing is
hardcoded to one app.

> **Honesty contract.** Verified facts (executed tests / measured bytes) are
> kept separate from what is only reviewed or still blocked. No fabricated
> builds, device runs, or success logs. See `docs/DEVELOPMENT_STATUS.md` and
> `docs/IOS_BUILD_STATUS.md`.

## Layout
```
runtime/    C++17 engine: DEX parse+interp, zlib ZIP reader, AXML parser, C ABI
analyzer/   Python APK analyzer
ios/        SwiftUI host + bridging header + XcodeGen spec (needs macOS)
tests/      DEX assembler, fixtures, C++ suite, analyzer tests, JVM harness
docs/       DEVELOPMENT_STATUS, BUILD, IOS_BUILD_STATUS
.github/    CI (Linux runtime+analyzer tests; macOS iOS build)
```

## Run everything (Linux/macOS/Windows — no Mac needed)
```bash
./run_all_tests.sh
```
Expected without a private APK: C++ runtime 54 passed / 3 skipped, analyzer
10 passed / 1 skipped, and three-way JVM conformance 8/8 in agreement.

## Use the engine directly (same C ABI the iOS app calls)
```bash
apkbridge_run import  App.apk  /tmp/out        # safe extract + metadata JSON
apkbridge_run classes /tmp/out/classes.dex 0 100
apkbridge_run methods /tmp/out/classes.dex "La/b/C;"
apkbridge_run run     /tmp/out/classes.dex "La/b/C;" method I 42
```

## Status in one line
Import + analysis + DEX interpreter + class/method browser + a recoverable
install transaction are real and covered by portable tests. v1.0.1 restores the
analyzer source, prevents commit after preparation failure, validates promoted
code before discarding the backup, and keeps application data outside the
replaceable `dex/` directory. The iOS host is written for iOS 16 and links the
same tested C++ core. GitHub Actions performs the authoritative macOS/Xcode
build; a green `ios-build` job means Xcode produced an unsigned `.app` bundle.

This public repository intentionally excludes proprietary APKs, signing
material, credentials, and private application-analysis reports.

## Remote Android — real DCR login and features on iPhone

The optional **Remote Android** screen connects through a certificate-pinned HTTPS pairing flow to your own Android phone, using `remote_host/` on a trusted computer. DCR **runs on the Android phone** (with its normal authentication, Android services and hardware checks), and the iPhone shows its screen and sends touch input. This does **not** make the Android APK execute natively on iOS. No modified DCR APK or credentials are committed. See [`remote_host/README.md`](remote_host/README.md), [`docs/REMOTE_ANDROID_STATUS.md`](docs/REMOTE_ANDROID_STATUS.md) and [`docs/KSIGN_STATIC_ANALYSIS.md`](docs/KSIGN_STATIC_ANALYSIS.md).
