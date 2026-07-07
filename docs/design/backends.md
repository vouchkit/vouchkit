# Backend seam — optional extension interfaces

**Status:** design, v1 (2026-07). This document fixes the extension seam *before* the session
layer is built, so everything above the verification core programs against interfaces, never
against any particular provider.

## Principles

1. **The core stays a pure function.** `verify_sd_jwt_vc` does no I/O, ever. Everything with
   a lifecycle — key fetching, receipt recording, session issuance — lives behind a backend
   interface with a local default.
2. **Local-first defaults.** vouchkit is complete without any hosted service: static trust
   anchors from configuration, no-op receipts, in-process sessions. A deployment that never
   configures a backend never makes a network call.
3. **Backends are pluggable packages, not forks.** Third-party backends ship as separate
   pip packages registering entry points in the `vouchkit.backends` group; the core never
   imports, vendors, or special-cases any of them. Hosted providers (for example the
   LifeCare network's consent-infrastructure backend) implement the same interfaces the
   local defaults do — same tests, same docs, no privileged hooks.
4. **Zero personal data by default.** Backend interfaces receive verification *events*
   (issuer, vct, disclosed-claim *names*, timestamps, outcome) — never claim *values* —
   unless the relying party explicitly opts a backend into claim access in its own
   configuration. Log discipline follows the same rule.

## Interfaces (Python `Protocol`s; shipped with the session layer)

### 1. `TrustAnchorSource`
*Who do we trust to issue credentials?*
```python
class TrustAnchorSource(Protocol):
    def resolve(self, issuer: str, kid: str | None) -> dict:  # returns a public JWK
        ...
```
Default: `StaticTrustAnchors` (JWKs from config). Future implementations: EU trusted-list
resolvers, x5c chain validation, managed update feeds. This is the interface the trust-anchor
roadmap item lands behind.

### 2. `ReceiptSink`
*What record exists that this verification happened, and on what terms?*
```python
class ReceiptSink(Protocol):
    def record(self, event: VerificationEvent) -> None:  # fire-and-forget, must never block verification
        ...
```
Default: `NoopReceipts`. A local audit implementation (`JsonlReceipts`, claim-names-only) ships
with the core. Consent-infrastructure backends may implement `record` as the issuance of a
standards-based consent receipt (ISO/IEC 27560-shaped) into their own ledger — enabling an RP
to prove, later, what it verified and under which purpose. A `ReceiptSink` failure must never
fail or delay the verification result.

### 3. `SessionIssuer`
*How does a verified presentation become an application session?*
```python
class SessionIssuer(Protocol):
    def issue(self, credential: VerifiedCredential, *, context: SessionContext) -> Session:
        ...
```
Default: `LocalSessions` (signed cookie / app-managed). The OpenID4VP session layer (roadmap
item 2–3) builds exclusively against this interface.

## Configuration convention

```toml
[vouchkit]
trust_anchors = "static"      # or an installed backend's entry-point name
receipts      = "noop"        # "jsonl", or e.g. "lifecare"
sessions      = "local"
```
Resolution order: built-in defaults → installed entry points (`vouchkit.backends`). Unknown
names fail loudly at startup, never silently at request time.

## Non-goals

- No backend may alter verification semantics: what is accepted or rejected is decided by the
  core alone, identically for every deployment.
- No telemetry, no phone-home, no default-on network dependency — a backend is always an
  explicit operator choice.
