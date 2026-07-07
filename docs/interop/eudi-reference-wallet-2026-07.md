# Interop session: EUDI reference wallet (Android demo build 2026.06.38)

**Date:** 2026-07-07 · **Device:** Pixel 8 Pro, Android 16 · **Wallet:**
`eu.europa.ec.euidi` demo release 2026.06.38 · **Verifier:** vouchkit `examples/demo_rp.py`
over `adb reverse` (localhost-only; no public exposure).

## What worked

1. **Wallet onboarding + credential issuance** from the demo issuer (`issuer.eudiw.dev`):
   a **Health ID (SD-JWT VC)** (configuration `eu.europa.ec.eudi.hiid_sd_jwt_vc`) was issued
   into the wallet after two workarounds (below).
2. **Intent delivery:** `openid4vp://` authorize URLs fired via `am start` open the wallet's
   presentation flow reliably — plain-parameter and `request=`-JWT forms both parse.
3. **Prefix negotiation:** `client_id` prefix `x509_hash` is **accepted** by this build
   (`redirect_uri` is not — see finding 2), and our ES256-signed request object
   (`typ: oauth-authz-req+jwt`, x5c header) passes JWT validation up to trust evaluation.

## Findings (each is an upstream fact, not a vouchkit bug)

1. **Demo-issuer outage, FormEU path:** `issuer.eudiw.dev` (preprod-12-05-26) crashes with
   `KeyError: 'code'` in `views.py:209 verify` on every FormEU authorization — server-side,
   deterministic in a session that has once crashed. **Workaround that succeeded:** a fresh
   browser session (switched default browser), i.e. the failure sticks to the issuer session.
   PID Combined issuance also failed once (deferred-flow error) before the crash was isolated.
2. **`UnsupportedClientIdPrefix` for `redirect_uri:`** — this wallet build rejects unsigned
   requests using the `redirect_uri` client-id prefix outright. Practical consequence: the
   reference wallet talks only to verifiers presenting **signed request objects** with
   x509-based identifiers.
3. **Reader trust is enforced (the headline finding):** with `x509_hash` + a self-signed
   cert, resolution fails in `ReaderTrustStoreImpl` with `CERTIFICATE_PATH_ERROR` →
   `InvalidJarJwt(cause=Untrusted x5c)`. The wallet requires the verifier's signing
   certificate to chain to a CA in its **reader trust store**. This is the
   access-certificate / RP-registration model of eIDAS 2 working as designed, observed live —
   and it makes WP-B3 (RP-registration readiness) a load-bearing workstream, not paperwork.

## Paths to the full live round-trip (in preference order)

1. **Dev wallet flavor with our CA:** the reference wallet's reader trust store is
   build-time configurable; build the Android app with a vouchkit demo CA added, then the
   existing `demo_rp.py --x509` flow should complete. (Bounded agent task; large Android
   toolchain.)
2. **Test reader certificate** from an EUDI ecosystem trust list that the demo build already
   ships (investigate whether eudiw.dev issues test reader certs to third parties).
3. Track wallet builds for a dev "skip reader trust" toggle.

Until then, the **TestWallet CI round-trip** (tests/test_openid4vp.py) remains the end-to-end
proof of the vouchkit stack itself; this session proved everything up to the wallet's trust
policy with a real wallet, real credential, and real transport.

## Reproduction

```
adb reverse tcp:8799 tcp:8799
VOUCHKIT_DEMO_X509=1 PUBLIC_URL=http://localhost:8799 python examples/demo_rp.py
curl -s localhost:8799/start          # → authorize_url
adb shell am start -a android.intent.action.VIEW -d "'<authorize_url>'"
curl -s localhost:8799/result
```
