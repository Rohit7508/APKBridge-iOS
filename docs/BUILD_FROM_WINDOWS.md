# Reproducible build: Windows → GitHub Actions (macOS) → iPhone

APKBridge is developed on Windows/Linux, but an iOS app can only be compiled on
macOS with Xcode. This project uses a **GitHub Actions macOS runner** to do that
compile. From this container I was **not able to push** to the repository (the
push was denied — see `docs/IOS_BUILD_STATUS.md`), so this guide gives the exact
commands for the repository owner to push the source and trigger the build from
their own Windows machine. Nothing here claims a build that has not run.

## What you need (one-time)
- Git for Windows (`git --version` in PowerShell/Command Prompt).
- A GitHub account that can push to the repo, and the GitHub CLI `gh` (optional,
  for downloading artifacts) — `winget install GitHub.cli`.
- For installing on a real iPhone: a Mac with Xcode **or** a signing service
  (see "Signing", below). The CI itself produces an **unsigned** `.app`.

## Step 1 — Put the v1.0 source in a folder
Unzip `APKBridge-v1.0.zip` to e.g. `C:\dev\apkbridge`.

## Step 2 — Push to GitHub (exact commands, run in the project folder)
```powershell
cd C:\dev\apkbridge
git init
git add .
git commit -m "APKBridge v1.0"
git branch -M main
# Replace OWNER/REPO with your GitHub repo (create it first at github.com/new):
git remote add origin https://github.com/OWNER/REPO.git
git push -u origin main
```
If the repo already exists with history, use `git pull --rebase origin main`
before `git push`.

## Step 3 — The build runs automatically
`.github/workflows/ci.yml` triggers on every push. It has two jobs:
1. **portable** (Ubuntu): builds the C++ runtime and runs all tests + conformance.
2. **ios-build** (macOS 14): `xcodegen generate` → `xcodebuild … -sdk iphoneos`
   with signing disabled. It **fails** if `xcodebuild` fails or if no
   `APKBridge.app` is produced, so a green check means Xcode really compiled it.

To trigger manually instead of on push:
```powershell
gh workflow run "APKBridge CI"
```

## Step 4 — Get the result
In the repo's **Actions** tab, open the latest run:
- `ios-build-log` artifact — the full `xcodebuild` log (uploaded even on failure).
- `APKBridge-unsigned-app` artifact — the unsigned `APKBridge.app` (only if the
  build succeeded).

Or with the CLI:
```powershell
gh run list --workflow "APKBridge CI"
gh run download <run-id> -n APKBridge-unsigned-app
gh run download <run-id> -n ios-build-log
```

## Step 5 — Install on the iPhone (requires signing — not done by CI)
The CI output is **unsigned** and will not install as-is. To put it on an
iPhone 16 Pro Max (iOS 16+), one of:
- **Xcode on a Mac:** open the project (`cd ios && xcodegen generate`), select
  your device and your free/paid Apple Developer team under Signing &
  Capabilities, and Run. This signs and installs in one step.
- **Sideload a signed IPA:** wrap the `.app` in a `Payload/` folder, zip it to
  `APKBridge.ipa`, then sign with your Apple Developer certificate (e.g.
  `codesign`/`xcrun` on a Mac, or a sideloading tool) and install via Apple
  Configurator, Xcode Devices, or your MDM. A free Apple ID gives a 7-day
  provisioning profile; a paid account gives a year.

APKBridge requests no special entitlements, so a personal-team signature is
enough for local testing. **No device install has been performed or verified
here** — this guide ends at the artifacts CI produces.

## If the macOS build fails
Read `ios-build-log` for the first `error:` line and fix in the Swift/project
source, then push again. The C++ core is already compiled and tested on every
run by the `portable` job, so iOS failures are isolated to the Swift host or the
XcodeGen spec (`ios/project.yml`).
