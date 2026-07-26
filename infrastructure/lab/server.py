"""Deterministic local-only HTTP service for safe adapter integration tests."""

import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberAudit-Lab/1.0"

    def do_HEAD(self) -> None:
        self._respond(head=True)

    def do_GET(self) -> None:
        self._respond(head=False)

    def _respond(self, *, head: bool) -> None:
        if self.path == "/slow":
            time.sleep(4)
        if self.path == "/redirect-local":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.end_headers()
            return
        if self.path == "/redirect-blocked":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if self.path == "/.well-known/security.txt":
            body = b"Contact: mailto:security@example.invalid\nExpires: 2030-01-01T00:00:00Z\n"
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /internal-demo/\n"
        elif self.path == "/large":
            body = b"x" * 400_000
        else:
            body = b"<html><meta name='generator' content='WordPress'><body>CyberAudit Lab</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/secure":
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
        else:
            self.send_header("Set-Cookie", "lab_session=demo-only; HttpOnly; SameSite=Lax")
            self.send_header("X-Powered-By", "CyberAudit-Lab")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"lab_http {format % args}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-mode", choices=["local", "container"], default="local")
    args = parser.parse_args()
    host = "127.0.0.1" if args.host_mode == "local" else "0.0.0.0"  # noqa: S104
    ThreadingHTTPServer((host, 8080), Handler).serve_forever()
