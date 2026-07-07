# PROMPT.md — paste this into your coding agent

vouchkit's quickstart is a prompt, not a tutorial. Copy everything below the line into
Claude Code, Cursor, Copilot, or any coding agent working in your service's repository.
It scopes the agent to what vouchkit does **today** (pre-alpha: SD-JWT VC verification +
the integrator test kit — the OpenID4VP transport layer is on the roadmap and not yet
released).

---

Add EUDI-wallet credential verification to this service using **vouchkit**
(https://github.com/vouchkit/vouchkit — Apache-2.0, pure Python, `cryptography` is its
only runtime dependency). Follow these steps exactly:

1. **Install:** add `vouchkit` to the project's dependencies (`pip install vouchkit` /
   `uv add vouchkit`). Requires Python ≥ 3.11.

2. **Wire verification** where this service receives an SD-JWT VC presentation string
   (format `<issuer-jwt>~<disclosure>*~<kb-jwt>`):

   ```python
   from vouchkit import verify_sd_jwt_vc, SdJwtError

   result = verify_sd_jwt_vc(
       presentation,
       issuer_jwk,                 # the trusted issuer's P-256 public JWK
       expected_aud=RP_URL,        # this service's identifier, as challenged
       expected_nonce=session_nonce,
   )
   # result.claims           -> dict of ONLY what the user disclosed
   # result.key_binding_verified -> must be True in the RP flow
   ```

   Key binding is required by default — do not pass `require_key_binding=False` in a
   relying-party flow. Trust-anchor resolution (which issuer keys to trust) is the
   caller's responsibility in this release; load issuer JWKs from configuration.

3. **Handle failures by type, never by string.** Catch `SdJwtError` subclasses
   (`InvalidSignature`, `DisclosureError`, `InvalidKeyBinding`, `ExpiredCredential`,
   `UnsupportedAlgorithm`) and map them to this service's error responses.
   **Never log presentation contents, disclosed claims, or personal data — log only the
   exception type.**

4. **Prove the integration in CI** using vouchkit's test kit (no wallet needed):

   ```python
   from vouchkit.testkit import TestIssuer, TestHolder
   ```

   Write at least four tests against this service's verification endpoint/function:
   (a) a valid presentation with key binding verifies and yields exactly the disclosed
   claims; (b) a presentation with a tampered disclosure is rejected; (c) a wrong
   `nonce` is rejected; (d) an expired credential is rejected. Mint all fixtures with
   `TestIssuer`/`TestHolder` — never hardcode token strings.

5. **Run the test suite** and report results. If anything in vouchkit's API surprises
   you, read `src/vouchkit/sdjwt.py` in its repository — it is ~300 lines and is the
   authoritative reference.

Constraints: do not add other new dependencies; do not weaken key-binding or expiry
checks; do not catch the base `Exception` around verification.
