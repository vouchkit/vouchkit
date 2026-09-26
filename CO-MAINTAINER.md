# We're looking for a co-owner

vouchkit is young — a verification core, a test kit, and a roadmap toward the full
wallet-relying-party toolkit for the EU Digital Identity Wallet ecosystem. We want a second
maintainer to co-own it from early: someone who will shape the OpenID4VP transport layer,
review with an adversarial eye, and become a voice for the project in the German/EU digital
identity community.

## What the role is

- **Real co-ownership:** merge rights, release authority, roadmap voice. The goal is a bus
  factor of two, not a helper.
- **The work right now:** the OpenID4VP request/response layer (signed request objects,
  `direct_post.jwt`, DCQL), the Digital Credentials API front-end, trust-anchor resolution,
  and a live round-trip against the EUDI reference wallet.
- **Funding, stated plainly:** the project is **unfunded today**. No grant, corporate or
  institutional money has ever come in, and everything published so far was built on unpaid
  time. We are pursuing European public funding for open-source infrastructure for the wallet
  sign-in track; nothing is awarded, and we will say so here when that changes. Any funded
  deliverable lands in this repository under Apache-2.0. Until then this is part-time,
  mission-driven OSS work.

## Who we're looking for

- Python (the core is pure Python, `cryptography` only) and working knowledge of
  OAuth 2.0/OIDC; WebAuthn/passkey experience is a plus.
- EUDI / eIDAS 2.0 exposure is ideal: OpenID4VP/OpenID4VCI, SD-JWT VC, or wallet-ecosystem
  work.
- Open-source working style: PRs, review discipline, adversarial tests first, DCO.
- **Residency is not a requirement for the role.** Some of the public-funding routes open to a
  project like this one are German or EU-resident programmes, so residency there can matter for
  a future application. It has no bearing on co-ownership.

## Context

vouchkit is the open foundation under the LifeCare network (a commercial consent platform —
stated up front: this repo is Apache-2.0 forever and complete on its own; the commercial
network is a separate thing that builds on it). Placing this project under neutral-foundation
stewardship is our **intention**; no arrangement exists yet, and no steward has been engaged.

## Interested?

**Go to [lifecare.id](https://lifecare.id) and use the "Book a call" button** — a 15-minute
call with the founder. Mention vouchkit. Reading `src/vouchkit/sdjwt.py` and the test suite
first is the best possible preparation; opening an issue or a small PR before the call says
more than any CV.
