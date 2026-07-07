"""Demo relying party — a minimal, stdlib-only verifier endpoint for live wallet interop.

Run it, expose it over HTTPS (any tunnel), and point a wallet at the printed
authorize URL:

    PUBLIC_URL=https://<your-tunnel> python examples/demo_rp.py

Endpoints:
    GET  /start            create a transaction; returns the openid4vp:// authorize URL
    POST /wallet-response  the direct_post response_uri the wallet POSTs to
    GET  /result           JSON of the most recent verification outcome

DEMO TRUST MODEL (not for production): the issuer key is taken from the leaf
certificate of the presentation's own `x5c` header (trust-on-first-use). A real
deployment resolves issuers through a `TrustAnchorSource` backed by trusted
lists — see docs/design/backends.md. Claims are printed to stdout: this is a
demo harness, not a service.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vouchkit.openid4vp import CredentialQuery, Verifier  # noqa: E402
from vouchkit.sdjwt import SdJwtError, _b64url_decode, _b64url_encode  # noqa: E402

PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8799").rstrip("/")
PORT = int(os.environ.get("PORT", "8799"))
RESPONSE_URI = f"{PUBLIC_URL}/wallet-response"
CLIENT_ID = f"redirect_uri:{RESPONSE_URI}"

QUERY = CredentialQuery(id="q1", vct="*")  # demo: accept any SD-JWT VC type


class X5cLeafTrust:
    """DEMO ONLY: trust the presentation's own leaf certificate (TOFU)."""

    def __init__(self) -> None:
        self._pending_jwk: dict | None = None

    def prime(self, presentation: str) -> None:
        header = json.loads(_b64url_decode(presentation.split(".")[0]))
        x5c = header.get("x5c")
        if not x5c:
            raise SdJwtError("presentation carries no x5c header (demo trust needs it)")
        import base64

        cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
        key = cert.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise SdJwtError("demo trust supports EC issuer keys only")
        numbers = key.public_numbers()
        self._pending_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_encode(numbers.x.to_bytes(32, "big")),
            "y": _b64url_encode(numbers.y.to_bytes(32, "big")),
        }
        subject = cert.subject.rfc4514_string()
        print(f"[demo-trust] TOFU issuer cert subject: {subject}")

    def resolve(self, issuer: str, kid: str | None = None) -> dict:
        if self._pending_jwk is None:
            raise SdJwtError("demo trust not primed")
        return self._pending_jwk


TRUST = X5cLeafTrust()
VERIFIER = Verifier(CLIENT_ID, RESPONSE_URI, trust_anchors=TRUST)
LAST: dict = {"status": "waiting"}
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/start":
            if os.environ.get("VOUCHKIT_DEMO_X509"):
                url, state = make_x509_signed_authorize_url(VERIFIER, QUERY)
            else:
                tx = VERIFIER.start(QUERY)
                url, state = tx.authorize_url, tx.state
            with LOCK:
                LAST.clear()
                LAST.update({"status": "started", "state": state})
            print(f"\n[demo-rp] authorize URL:\n{url}\n")
            self._send(200, {"authorize_url": url, "state": state})
        elif path == "/result":
            with LOCK:
                self._send(200, dict(LAST))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/wallet-response":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        print(f"[demo-rp] direct_post received: keys={sorted(form)}")
        try:
            vp_token = form.get("vp_token", "")
            token_obj = json.loads(vp_token) if isinstance(vp_token, str) else vp_token
            first = next(iter(token_obj.values()))[0] if isinstance(token_obj, dict) else None
            if first:
                TRUST.prime(first)
            credential = VERIFIER.handle_response(form)
            outcome = {
                "status": "verified",
                "issuer": credential.issuer,
                "vct": credential.vct,
                "claims": credential.claims,
                "key_binding_verified": credential.key_binding_verified,
            }
            print(f"[demo-rp] VERIFIED ✅ {json.dumps(outcome)}")
        except Exception as exc:  # noqa: BLE001 - demo surface: report everything
            outcome = {"status": "rejected", "error": type(exc).__name__, "detail": str(exc)}
            print(f"[demo-rp] REJECTED ❌ {outcome}")
        with LOCK:
            LAST.clear()
            LAST.update(outcome)
        self._send(200, {})

    def log_message(self, fmt: str, *args) -> None:  # quiet default access log
        return




def make_x509_signed_authorize_url(verifier: Verifier, query: CredentialQuery) -> tuple[str, str]:
    """Build an x509_hash-signed authorization request (self-signed cert, by value).

    OpenID4VP 1.0 `x509_hash`: client_id = base64url(SHA-256(DER cert)); the wallet
    checks the x5c leaf hashes to it. Whether the wallet *trusts* the cert is policy.
    """
    import base64
    import datetime
    import hashlib
    import json as _json

    from cryptography.hazmat.primitives import hashes as _hashes, serialization
    from cryptography.x509.oid import NameOID

    from vouchkit.sdjwt import _b64url_encode as b64u, _sign_es256

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vouchkit demo RP")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, _hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    client_id = "x509_hash:" + b64u(hashlib.sha256(der).digest())

    tx = verifier.start(query)  # state/nonce bookkeeping
    request_object = dict(tx.request_object)
    request_object["client_id"] = client_id
    verifier.client_id = client_id  # KB-JWT aud must match what the wallet sees

    header = {"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [base64.b64encode(der).decode()]}
    h = b64u(_json.dumps(header, separators=(",", ":")).encode())
    p = b64u(_json.dumps(request_object, separators=(",", ":")).encode())
    sig = b64u(_sign_es256(f"{h}.{p}".encode("ascii"), key))
    from urllib.parse import urlencode as _urlencode

    url = "openid4vp://?" + _urlencode({"client_id": client_id, "request": f"{h}.{p}.{sig}"})
    return url, tx.state


if __name__ == "__main__":
    print(f"[demo-rp] client_id={CLIENT_ID}")
    print(f"[demo-rp] listening on :{PORT}, public at {PUBLIC_URL}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
