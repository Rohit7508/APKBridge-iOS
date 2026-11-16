# Remote Android host — authentic Android execution

APKBridge's DEX interpreter cannot run all of DCR's Android/React Native/JNI dependencies on iOS. This **optional** companion service is a different execution path: it displays and controls **your real Android phone**, on which the unmodified, legitimately installed DCR application runs and enforces its usual login, permissions and hardware checks. It is not APK-to-IPA conversion.

## Requirements

- A Windows/Linux/macOS computer with Python 3.10+, Android Platform Tools (`adb`), and OpenSSL.
- `Pillow` for resizing screenshots: `python -m pip install Pillow`.
- **Your own** Android phone, attached by USB, with the device's normal developer authorization granted to the computer. Keep the physical phone and computer in your possession.
- An iPhone running the updated APKBridge app; both computers on a **trusted private LAN**. No public Internet port forwarding.

## First run

From `remote_host/`, create a TLS certificate locally. Do not commit or share the private key:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
  -keyout host.key -out host.crt -subj "/CN=APKBridge Remote Android"
```

Check the attached device is authorized: `adb devices`. It should show `device`, not `unauthorized` or `offline`.

Start the host (use an explicit LAN bind only when the iPhone is on the same trusted network):

```bash
python server.py --cert host.crt --key host.key --listen 0.0.0.0 --port 8443
```

By default the server binds `127.0.0.1` and is not reachable from other devices. It prints three **local** values: the HTTPS URL format, the full SHA-256 certificate fingerprint, and a temporary pairing code. Find your PC's private LAN IP address (e.g. `ipconfig` on Windows) and enter the corresponding `https://PC-IP:8443/` and the fingerprint in APKBridge → **Remote Android**. Then enter the temporary code on the iPhone screen. Do not share the code, private key or account credentials in chat.

Pairing creates an HTTPS-only, HttpOnly, SameSite session cookie. Touches are sent as authenticated commands; the host does **not** request DCR account passwords or inject credentials. The temporary session expires after inactivity.

### Limitations

- Experimental screenshot-driven remote UI (~1 frame per second), not low-latency gaming/video streaming. It can be used to inspect navigation and ordinary app screens; tests are required for any specific DCR feature.
- Android phone must remain powered on, unlocked when appropriate, and USB-connected to the computer. Computer must stay on.
- Camera, microphone, biometrics, GPS, secure-content flags, and hardware-backed verification **remain on Android**. Screens deliberately protected by the OS may render black and are not bypassed.
- The Android device may forbid remote input or app behavior, which this project does not override.
- ADB is a powerful developer tool. Disable wireless debugging and stop this server when not in use; never open port 8443 to the Internet.
- Only one Android device session is intended per host. This is a prototype, not a public multi-user remote desktop service.

## Tests

```bash
python -m unittest remote_host/test_server.py
```

Tests use a fake Android backend so CI can verify pairing, session isolation, request size limits, CSRF and control coordinate validation without having DCR or an Android device. **A real DCR login has not been verified** until it is tested on an authorized Android device.
