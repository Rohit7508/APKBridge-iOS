# APKBridge iOS — Development Status (v1.0.1)

_Last updated: 2026-11-16 • Build/test env: Linux + g++13 / clang / cmake / zlib / JDK17. No Android SDK, no macOS/Xcode, no device. Build warning-clean._

Status categories used throughout:
**Tested-W/L** (executed + asserted here on Windows/Linux) ·
**Tested-Android-RT** (compared against a real Android run) ·
**Compiled-iOS** (Xcode actually built it) ·
**Tested-iPhone** (ran on a physical device) ·
**Not-implemented** ·
**Blocked** (cannot be done in this environment).

## Portable validation target

CI requires the public-source inventory, C++ runtime suite, Python analyzer
suite, and JVM conformance suite to pass before the macOS build begins. Private
APK regression cases remain optional and are skipped when no authorized APK is
present.

## v1.0.1 reliability fixes

- The complete analyzer implementation is included and checked by the source
  inventory test.
- Installation preparation failure now prevents commit.
- Journal, copy, rename, verification, recovery, and cleanup failures are
  propagated instead of silently accepted.
- Recovery validates promoted code before removing the previous installation.
- Application files and SharedPreferences live at the stable per-app sandbox
  root, outside the replaceable `dex/` directory.
- `.gitignore` and the source inventory reject APKs, signing material, and
  common secret files from the public source package.

## Tested-W/L — v1.0 baseline retained
- **Crash-safe install transaction (Priority 2)** — `runtime/include/install.hpp`,
  exercised by 6 new tests. Commit keeps a `dex.old` backup until the new code is
  promoted **and verified**, then drops it. A journal marker (`.txn`) lets
  `recover()` finish correctly after a crash simulated at **every** stage:
  after BEGIN → rolls back to previous code; after backup → rolls back; after
  promote → commits new; after DONE → finalizes; abandoned prepare → keeps
  previous. User data (`files/`, `databases/`, `shared_prefs/`) is untouched in
  all cases. The iOS host calls this same tested C++ via the C ABI.
- **Filesystem security** — real-symlink escape rejected (resolved target
  canonicalized then containment-checked), sibling-app root rejected, in-root
  allowed. SharedPreferences names are **injective** (percent-encoded): `a/b`,
  `a_b`, `a.b` distinct; and **collision-resistant for long names** — two names
  sharing a 300-char prefix map to different files via a hash over the full name,
  within a safe filename length (new `prefs_name_long_distinct` test).
- All prior runtime features retained and passing: multi-DEX loader, collections,
  storage, SharedPreferences isolation + persistence, class-init state machine,
  native-method rejection, context identity, two execution modes.

## Compiled-iOS — build-ready, NOT yet compiled (no Swift/iOS toolchain here)
- The iOS host (SwiftUI) links the tested C++ core via a bridging header. The C
  ABI it depends on — including the new `apkbridge_install_commit/recover` —
  **compiles cleanly** here (`bridge.cpp` → object). The import flow now delegates
  the code swap to the tested transaction, and the library runs `installRecover`
  on launch. The Xcode compile itself requires a macOS runner (see Blocked).

## Blocked
- **First iOS Xcode build (Priority 1)** — the push to trigger the macOS runner
  was **denied** in this session and was **not re-attempted or faked**. The
  project is build-ready (`ios/project.yml`, `.github/workflows/ci.yml`).
  Reproduce from Windows: `docs/BUILD_FROM_WINDOWS.md`. Status detail:
  `docs/IOS_BUILD_STATUS.md`.
- **Tested-Android-RT (Priority 4)** — no Android SDK/emulator here, so no
  device/emulator comparison was run. Not faked.

## Not-implemented
- Opcodes: longs/floats/doubles, packed/sparse switch, filled-new-array.
- Android **Parcel marshalling / SafeParcelable** (this is the real DCR stop —
  see below), and Binder IPC transactions.

## DCR — Binder origin analysis (Priority 5), corrected from v0.9
The functional stop is `Parcel.readStrongBinder()`. Tracing the actual bytecode
(`tools/dexdis.py`) **corrects the v0.9 claim** that this required the remote
Google Play Services process:
- The GMS `IObjectWrapper` Proxy (`Lc/l/a/e/e/b$a$a;`) has **no remote methods**
  and there is **no `onTransact`/transaction code** for the interface. Its only
  operation, `ObjectWrapper.unwrap` (`Lc/l/a/e/e/d;->h`), reads the wrapped object
  **in-process** (field read, or reflection across a same-process classloader).
  `asInterface` takes the **local** path when `queryLocalInterface` succeeds.
- So `IObjectWrapper` is **locally implemented** and does not by itself require
  the external GMS process. The binder originates from a **SafeParcelable
  `createFromParcel`** reading a binder written by a matching `writeStrongBinder`.
- The true limitation is that our runtime does **not model Parcel marshalling**
  (a coverage gap), not a hard external-service dependency. Whether the broader
  GMS component works without Play Services is **left unresolved** — the bytecode
  does not settle it, and no feature is assumed from the descriptor.
- No binder handle is fabricated; authentication, licensing, attendance
  verification and attestation are untouched. Full analysis:
  `reports/dcr_binder_report_v1.0.md`.

## Definition-of-success check
| Priority | Item | Status |
|---|---|---|
| 1 | Successful macOS Xcode build | **Blocked** — push denied; not faked. Windows build guide provided. |
| 2 | Recoverable updates; backup kept until verified; auto-recover; data preserved | **Tested-W/L** — 6 interruption-stage tests pass |
| 3 | Filesystem correctness incl. long-name prefs; existing tests pass | **Tested-W/L** — 49/49 |
| 4 | Real Android reference compared | **Blocked** — no SDK/emulator |
| 5 | DCR Binder origin traced without assuming a remote service | **Tested-W/L** — local wrapper, no transaction; v0.9 corrected |
| 6 | Docs accurate to v1.0 | this document + README + IOS_BUILD_STATUS |
