"""Local TLS fixture with a generated self-signed certificate."""

import argparse
import datetime
import ipaddress
import ssl
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"CyberAudit TLS laboratory"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"lab_tls {format % args}")


def certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=14))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "lab-cert.pem"
    key_path = directory / "lab-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-mode", choices=["local", "container"], default="local")
    args = parser.parse_args()
    host = "127.0.0.1" if args.host_mode == "local" else "0.0.0.0"  # noqa: S104
    with tempfile.TemporaryDirectory(prefix="cyberaudit-tls-lab-") as directory:
        cert_path, key_path = certificate(Path(directory))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server = ThreadingHTTPServer((host, 8443), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
