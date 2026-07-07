# vouchkit

**The wallet-relying-party toolkit for personal-data services.**

vouchkit lets a service become a **(wallet-)relying party** for the EU Digital Identity
Wallet: request and verify wallet presentations with a small, auditable, pure-Python core —
built for teams that need to accept the EUDI wallet without adopting a JVM stack or a vendor
runtime.

> **Status: pre-alpha.** The SD-JWT VC verification core and the integrator test kit are
> implemented and adversarially tested. OpenID4VP transport, the Digital Credentials API
> front-end, and trust-anchor resolution are in active development. Do not use in production
> yet — but do try it, file issues, and break it.

## Why vouchkit

- **Easy to integrate.** Pure Python, `pip install vouchkit`, one runtime dependency
  (`cryptography`). A FastAPI/ASGI integration layer and a language-agnostic sidecar are on
  the roadmap — one engine, two skins.
- **Easy to maintain.** Scoped to what the EUDI ARF actually mandates for relying parties
  (HAIP profile: ES256, `sha-256` disclosures, KB-JWT). No speculative surface.
- **Easy to verify programmatically.** The test kit ships as public API: mint known-good and
  deliberately broken presentations in your own CI — no wallet, no trust list, no network.
  Failures are precise, typed exceptions. Adversarial tests are the spine of the suite.
- **Nothing that blocks a review.** Apache-2.0 only (the whole dependency tree), DCO instead
  of a CLA, no telemetry, and a logging discipline that never touches personal data.

## Quick look

```python
from vouchkit import verify_sd_jwt_vc

result = verify_sd_jwt_vc(
    presentation,              # <issuer-jwt>~<disclosure>*~<kb-jwt> from the wallet
    issuer_jwk,                # the issuer key you trust (trust-anchor layer coming)
    expected_aud="https://rp.example",
    expected_nonce=session_nonce,
)
result.claims                  # only what the user disclosed
result.key_binding_verified    # True — the wallet proved holder binding
```

And in your test suite, no wallet required:

```python
from vouchkit.testkit import TestIssuer, TestHolder

issuer, holder = TestIssuer(), TestHolder()
jwt, disclosures = issuer.issue({"given_name": "Ada"}, holder_jwk=holder.public_jwk)
presentation = holder.present(jwt, disclosures, ["given_name"], aud=AUD, nonce=NONCE)
```

## Vocabulary (per the EUDI Architecture and Reference Framework)

Your service becomes a **relying party**; the thing you deploy is a **relying-party
instance**; its core is a **verifier** for **PID/(Q)EAA** attestations in **SD-JWT VC**
(and later ISO mdoc) format, requested over **OpenID4VP**.

## Roadmap

1. ✅ SD-JWT VC verification core + integrator test kit
2. OpenID4VP request/response (signed request objects, `direct_post.jwt`, DCQL)
3. Digital Credentials API front-end snippet + session mapping
4. Trust-anchor resolution (x5c chains, trusted lists)
5. Sidecar container (REST) · mdoc format · status-list revocation

## Contributing

Contributions are welcome under the [Apache License 2.0](LICENSE) with a
[Developer Certificate of Origin](CONTRIBUTING.md) sign-off (`git commit -s`). No CLA.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
