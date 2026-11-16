// Secure viewer for a *real*, user-authorized Android phone hosted by APKBridge Remote.
// This is not APK emulation. All apps, logins and system checks execute on Android.
import SwiftUI
import WebKit
import CryptoKit
import Security

struct RemoteAndroidSetupView: View {
    @AppStorage("remote_host_url") private var address = ""
    @AppStorage("remote_certificate_sha256") private var fingerprint = ""
    @State private var errorText: String?

    private var connection: (URL, String)? {
        let candidate = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: candidate),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let url = components.url else { return nil }
        let normalized = fingerprint
            .filter { $0.isHexDigit }
            .uppercased()
        guard normalized.count == 64 else { return nil }
        return (url, normalized)
    }

    var body: some View {
        Form {
            Section("Real Android connection") {
                TextField("https://192.168.1.10:8443/", text: $address)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                TextField("Certificate SHA-256 fingerprint", text: $fingerprint, axis: .vertical)
                    .lineLimit(2...3)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .font(.caption.monospaced())
                if let (url, pin) = connection {
                    NavigationLink("Connect to Android") {
                        RemoteAndroidBrowser(url: url, certificateSHA256: pin)
                    }
                } else {
                    Text("Enter an HTTPS address and its 64-digit certificate fingerprint to connect.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("How it works") {
                Label("DCR runs on your real Android phone.", systemImage: "checkmark.shield")
                Label("This iPhone shows its screen and sends touch gestures.", systemImage: "hand.tap")
                Text("The Android phone must be authorized and paired with your computer. It is not an Android emulator. Camera and biometric checks remain on the Android phone.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Security") {
                Text("Only connect to your own trusted computer. The iPhone verifies the exact TLS certificate fingerprint; it never asks APKBridge to store DCR credentials.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Remote Android")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct RemoteAndroidBrowser: View {
    let url: URL
    let certificateSHA256: String
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            if let errorMessage = errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(8)
                    .frame(maxWidth: .infinity)
                    .background(Color.red.opacity(0.08))
            }
            PinnedRemoteWebView(url: url, pin: certificateSHA256) { error in
                errorMessage = error
            }
        }
        .navigationTitle("Android Live")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct PinnedRemoteWebView: UIViewRepresentable {
    let url: URL
    let pin: String
    let onError: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(origin: url, pin: pin, onError: onError)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = context.coordinator
        web.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
        return web
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        private let origin: URL
        private let pin: String
        private let onError: (String) -> Void

        init(origin: URL, pin: String, onError: @escaping (String) -> Void) {
            self.origin = origin
            self.pin = pin
            self.onError = onError
        }

        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let requested = navigationAction.request.url else {
                decisionHandler(.cancel)
                return
            }
            // Never let a redirect or clicked link leave the pinned HTTPS origin.
            let allowed = requested.scheme?.lowercased() == "https"
                && requested.host?.lowercased() == origin.host?.lowercased()
                && (requested.port ?? 443) == (origin.port ?? 443)
            decisionHandler(allowed ? .allow : .cancel)
        }

        func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                     completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  challenge.protectionSpace.host.lowercased() == origin.host?.lowercased(),
                  challenge.protectionSpace.port == (origin.port ?? 443),
                  let trust = challenge.protectionSpace.serverTrust,
                  let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                onError("TLS connection was rejected.")
                return
            }
            let bytes = SecCertificateCopyData(certificate) as Data
            let actual = SHA256.hash(data: bytes).map { String(format: "%02X", $0) }.joined()
            guard actual == pin else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                onError("Certificate mismatch. Do not connect: this is not the paired Android host.")
                return
            }
            // Trust this *exact* certificate only, even if the host uses a local/self-signed CA.
            completionHandler(.useCredential, URLCredential(trust: trust))
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            onError("Cannot reach Android host: \(error.localizedDescription)")
        }
    }
}
