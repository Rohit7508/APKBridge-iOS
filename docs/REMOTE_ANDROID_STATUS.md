# APKBridge Remote Android — implementation and verification

## Purpose

Authentic DCR execution, including real login and post-login features, depends on Android's Java/native services, React Native modules and, potentially, dynamic vendor resources. The iOS DEX interpreter does not provide these dependencies. KSign-style iOS IPA signing does not translate Android DEX/ELF to native iOS code.

## Implemented in this branch

1. SwiftUI **Remote Android** setup and embedded pinned-certificate HTTPS WebKit viewer. The existing APK library, importer and DEX browser remain available.
2. `remote_host/server.py`: authenticated HTTPS companion for a **real, authorized Android phone** with developer-authorized ADB over USB. Screenshot capture, normalized touch/swipe and Back button. The existing unmodified Android application performs its usual login and server communication.
3. 12-character randomly generated pairing code, temporary Secure/HttpOnly/SameSite session, CSRF protection for remote input, limits for payload/coordinates, rate-limited bad codes. Certificate SHA-256 must be manually matched in the iPhone client.
4. Standalone test suite using fake Android backend so no proprietary APK or real device is needed in CI.

## Evidence / status

- Source compiles and portable project tests pass on Linux. Server auth/control tests run without a device.
- iOS Swift compilation: **requires a genuine GitHub Actions macOS run of this exact branch**. Earlier repo revision was already verified on iPhone, but the new remote view has not been installed/verified until the updated Xcode build completes.
- Android live remote control: **not verified** without a user-authorized Android phone physically connected to a host with ADB.
- DCR login / post-login functionality on iPhone: **not verified**. Can only be claimed after a real Android host is paired and the legitimate app login works.
- Does **not** execute DCR natively on iPhone; it relays the real Android device. No APK conversion, no bypass of credentials, licensing, enterprise checks, or attendance verification.

## Boundaries

The remote host requires a separate real Android phone and an available Windows/Linux/macOS computer. On trusted local Wi-Fi, the user controls the Android app from iPhone with approximately one screenshot per second. Some device- or hardware-bound features (camera, biometrics, GPS, secure surfaces) require use of the actual Android device. The Remote Android feature is separate from the existing DEX runtime and can be disabled without affecting APK import.

See `remote_host/README.md` for operation and security precautions.
