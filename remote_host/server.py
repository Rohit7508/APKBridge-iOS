#!/usr/bin/env python3
"""APKBridge Remote Android: authenticated TLS viewer for an Android device you own.

The Android application executes on a real Android device; this service relays
screenshots and user input. It does not emulate Android, patch APKs, intercept
login credentials, or bypass protected/secure screen capture.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
from typing import Protocol
from urllib.parse import parse_qs

MAX_REQUEST = 4096
SESSION_SECONDS = 1800
PAIRING_ATTEMPTS = 6
PAIRING_WINDOW_SECONDS = 300


class Backend(Protocol):
    def frame(self) -> tuple[bytes, int, int]: ...
    def tap(self, x: int, y: int) -> None: ...
    def swipe(self, x0: int, y0: int, x1: int, y1: int, duration: int) -> None: ...
    def back(self) -> None: ...


class ADBBackend:
    """Only uses explicitly authorized ADB device access; no shell input strings."""
    def __init__(self, adb: str = 'adb', serial: str | None = None):
        self.base = [adb] + (['-s', serial] if serial else [])
        self.lock = threading.Lock()
        self.cached: tuple[bytes, int, int] | None = None
        self.last_frame = 0.0
        try:
            from PIL import Image
        except ImportError as exc:
            raise RuntimeError('Install Pillow: python -m pip install Pillow') from exc
        self.Image = Image

    def command(self, *args: str, timeout: float = 8) -> bytes:
        p = subprocess.run(self.base + list(args), capture_output=True,
                           timeout=timeout, check=False)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or b'ADB command failed')[:250].decode('utf8', 'replace'))
        return p.stdout

    def frame(self) -> tuple[bytes, int, int]:
        with self.lock:
            now = time.monotonic()
            if self.cached is not None and now - self.last_frame < 0.65:
                return self.cached
            png = self.command('exec-out', 'screencap', '-p', timeout=9)
            with self.Image.open(io.BytesIO(png)) as image:
                image.load()
                width, height = image.size
                if not 1 <= width <= 8192 or not 1 <= height <= 8192:
                    raise RuntimeError('Device reported invalid screenshot dimensions')
                image.thumbnail((620, 1300))
                buf = io.BytesIO()
                image.convert('RGB').save(buf, format='JPEG', quality=66, optimize=True)
                output = buf.getvalue()
            if len(output) > 3 * 1024 * 1024:
                raise RuntimeError('Screenshot too large')
            self.cached = (output, width, height)
            self.last_frame = time.monotonic()
            return self.cached

    def tap(self, x: int, y: int) -> None:
        self.command('shell', 'input', 'tap', str(x), str(y))

    def swipe(self, x0: int, y0: int, x1: int, y1: int, duration: int) -> None:
        self.command('shell', 'input', 'swipe', str(x0), str(y0), str(x1), str(y1), str(duration))

    def back(self) -> None:
        self.command('shell', 'input', 'keyevent', '4')


class RemoteState:
    def __init__(self, backend: Backend, pairing_code: str | None = None):
        self.backend = backend
        self.pairing_code = pairing_code or secrets.token_hex(6).upper()
        self.sessions: dict[str, tuple[float, str]] = {}
        self.attempts: dict[str, list[float]] = {}
        self.lock = threading.RLock()

    def authorize(self, code: str, peer: str) -> tuple[str, str] | None:
        now = time.monotonic()
        with self.lock:
            attempts = [t for t in self.attempts.get(peer, []) if now - t < PAIRING_WINDOW_SECONDS]
            if len(attempts) >= PAIRING_ATTEMPTS:
                self.attempts[peer] = attempts
                return None
            if not hmac.compare_digest(code.upper(), self.pairing_code):
                attempts.append(now)
                self.attempts[peer] = attempts
                return None
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            self.sessions[token] = (now + SESSION_SECONDS, csrf)
            self.attempts.pop(peer, None)
            return token, csrf

    def verify(self, token: str) -> str | None:
        now = time.monotonic()
        with self.lock:
            if token not in self.sessions:
                return None
            expiry, csrf = self.sessions[token]
            if expiry <= now:
                self.sessions.pop(token, None)
                return None
            self.sessions[token] = (now + SESSION_SECONDS, csrf)
            return csrf


def make_handler(state: RemoteState, ui_path: Path):
    ui = ui_path.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        server_version = 'APKBridgeRemote/1.0'
        sys_version = ''

        def log_message(self, format: str, *args):
            # Avoid logging cookies, query parameters, submitted pairing codes.
            sys.stderr.write('[remote] ' + (format % args).replace(self.path, self.path.split('?')[0]) + '\n')

        def _send(self, code: int, body: bytes, mime: str = 'text/plain; charset=utf-8',
                  headers: dict[str, str] | None = None):
            self.send_response(code)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.send_header('Strict-Transport-Security', 'max-age=86400')
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _token(self):
            try:
                cookie = SimpleCookie()
                cookie.load(self.headers.get('Cookie', ''))
                return cookie['apkb_session'].value if 'apkb_session' in cookie else ''
            except Exception:
                return ''

        def _csrf(self):
            return state.verify(self._token())

        def _body(self):
            length = self.headers.get('Content-Length', '')
            if not length.isdecimal():
                return None
            n = int(length)
            if n < 0 or n > MAX_REQUEST:
                return None
            return self.rfile.read(n)

        def _json(self, code, value):
            self._send(code, json.dumps(value, separators=(',', ':')).encode(), 'application/json')

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            if path == '/health':
                return self._json(200, {'ready': True, 'version': '1.0'})
            if path in ('/', '/login'):
                csrf = self._csrf()
                page = ui.replace(b'__SESSION_CSRF__', (csrf or '').encode('ascii'))
                return self._send(200, page, 'text/html; charset=utf-8')
            if not self._csrf():
                return self._json(401, {'error': 'Pairing required'})
            if path == '/frame.jpg':
                try:
                    data, width, height = state.backend.frame()
                    return self._send(200, data, 'image/jpeg', {'X-Device-Width':str(width),'X-Device-Height':str(height)})
                except Exception:
                    return self._json(503, {'error': 'Android device unavailable'})
            if path == '/api/size':
                try:
                    _, width, height = state.backend.frame()
                    return self._json(200, {'width':width,'height':height})
                except Exception:
                    return self._json(503, {'error': 'Android device unavailable'})
            return self._json(404, {'error': 'Not found'})

        def do_POST(self):
            # Browsers set Origin for cross-site POST; reject if origin differs.
            origin = self.headers.get('Origin', '')
            host = self.headers.get('Host', '')
            if not host or (origin and origin != 'https://' + host):
                return self._json(403, {'error': 'Origin rejected'})
            raw = self._body()
            if raw is None:
                return self._json(413, {'error': 'Invalid request size'})
            if self.path == '/login':
                code = parse_qs(raw.decode('utf-8', 'replace')).get('code', [''])[0]
                result = state.authorize(code, self.client_address[0])
                if not result:
                    return self._json(403, {'error': 'Invalid or rate-limited pairing code'})
                token, _ = result
                return self._send(303, b'', headers={'Location': '/',
                    'Set-Cookie': f'apkb_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}'})
            if self.path != '/api/action':
                return self._json(404, {'error': 'Not found'})
            csrf = self._csrf()
            if not csrf:
                return self._json(401, {'error': 'Pairing required'})
            if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), csrf):
                return self._json(403, {'error': 'Missing or invalid CSRF token'})
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                return self._json(415, {'error': 'Expected JSON'})
            try:
                body = json.loads(raw)
                action = body.get('action')
                if action == 'back':
                    state.backend.back()
                elif action in ('tap', 'swipe'):
                    _, w, h = state.backend.frame()
                    def coord(k):
                        v = body[k]
                        if isinstance(v, bool) or not isinstance(v, (float,int)) or not 0 <= v <= 1:
                            raise ValueError('Invalid normalized coordinate')
                        return v
                    if action == 'tap':
                        x, y = coord('x'), coord('y')
                        state.backend.tap(min(w - 1, int(x*w)), min(h - 1, int(y*h)))
                    else:
                        x0,y0,x1,y1 = [coord(k) for k in ('x0','y0','x1','y1')]
                        ms = body.get('duration',350)
                        if isinstance(ms, bool) or not isinstance(ms,int) or not 100 <= ms <= 1500:
                            raise ValueError('Bad swipe duration')
                        state.backend.swipe(min(w-1,int(x0*w)),min(h-1,int(y0*h)),
                                            min(w-1,int(x1*w)),min(h-1,int(y1*h)),ms)
                else:
                    raise ValueError('Unknown action')
            except (KeyError, ValueError, TypeError, AttributeError):
                return self._json(400, {'error': 'Invalid action'})
            except Exception:
                return self._json(503, {'error': 'Android device unavailable'})
            return self._json(200, {'ok': True})
    return Handler


def tls_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_file), str(key_file))
    return ctx


def certificate_fingerprint(cert_file: Path) -> str:
    pem = cert_file.read_text(encoding='utf-8')
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest().upper()


def main():
    p = argparse.ArgumentParser(description='APKBridge secure viewer of YOUR authorized Android device')
    p.add_argument('--listen', default='127.0.0.1', help='Bind address (explicitly use 0.0.0.0 for trusted LAN)')
    p.add_argument('--port', type=int, default=8443)
    p.add_argument('--adb', default='adb')
    p.add_argument('--serial', help='ADB device serial for multi-device hosts')
    p.add_argument('--cert', required=True, type=Path, help='TLS PEM certificate')
    p.add_argument('--key', required=True, type=Path, help='TLS private key (never commit)')
    args = p.parse_args()
    if not 1 <= args.port <= 65535:
        p.error('Invalid port')
    backend = ADBBackend(args.adb, args.serial)
    # Verify the device is authorized before accepting clients.
    if backend.command('get-state').strip() != b'device':
        p.error('No authorized Android device found')
    state = RemoteState(backend)
    server = ThreadingHTTPServer((args.listen,args.port), make_handler(state,Path(__file__).with_name('ui.html')))
    server.daemon_threads = True
    server.socket = tls_context(args.cert,args.key).wrap_socket(server.socket, server_side=True)
    print(f'HTTPS address: https://<YOUR_PC_LOCAL_IP>:{args.port}/')
    print('Certificate SHA-256:', certificate_fingerprint(args.cert))
    print('PAIRING CODE (enter inside app; do not share):', state.pairing_code)
    print('Stop with Ctrl+C. This is remote control of a REAL Android device, not iOS APK emulation.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
