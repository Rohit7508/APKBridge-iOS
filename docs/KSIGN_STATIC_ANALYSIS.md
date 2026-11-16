# Ksign.ipa — offline static assessment

**Scope:** Analysis of the single uploaded `Ksign.ipa`. No code was executed. No signing certificates or private keys were extracted or published.

- Input file: 10,616,358 bytes; SHA-256 `65cfe1db6e7fe9340566692a0938bcd69bc295ea4c5cf262fe3eb899c8c2c25b`.
- ZIP local entries start with `Payload/Ksign.app`, and the main `Ksign` executable could be safely decompressed and CRC-checked.
- The uploaded file is **incomplete/corrupt as an IPA**: its ZIP end-of-central-directory is absent and the final observed `OpenSSL.framework/OpenSSL` entry is incomplete. Therefore the full IPA signature, file inventory and provisioning metadata cannot be validated.
- The recovered `Ksign` executable is a native **Mach-O 64-bit ARM64** executable (`MH_EXECUTE`, PIE), not Android DEX or an Android virtual machine.
- Mach-O load commands include iOS/Apple `UIKit`, `SwiftUI`, `Security`, `WebKit`, `CryptoKit`, `Foundation`, system `libc++`, `libz` and embedded `OpenSSL.framework/OpenSSL`. It contains an `LC_CODE_SIGNATURE` load command and `LC_ENCRYPTION_INFO_64` with `cryptid=0`. A code-signature command does not prove the signature is valid.
- Observed packaged resources reference **Zsign**, Swift cryptography / NIO, archive tooling, app installation UI, and an `ellekit.deb` package. These support its app-management/signing purpose. The presence of a package does not establish that it is active on a non-jailbroken iPhone.
- **Conclusion:** A signing/IPA-management workflow cannot make DCR's Android bytecode and native ELF components execute as iOS Mach-O code. No reusable Android application runtime was evidenced in this uploaded package.

Decision: preserve APKBridge as a legitimate DEX inspector, and add a separate authenticated Remote Android viewer when a full authorized DCR UI is required. This is genuine remote Android execution, not native iOS execution.
