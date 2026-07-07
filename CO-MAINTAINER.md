# We're looking for a co-maintainer

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
- **Funded path:** we are preparing a German **Prototype Fund** application (up to €95k for a
  6-month team project, window Oct–Nov 2026) with vouchkit's wallet sign-in track as the work
  plan. A German-resident co-maintainer would be the application lead. All funded deliverables
  are open source. Until a grant lands, this is part-time, mission-driven OSS work — we say
  that plainly.

## Who we're looking for

- Python (the core is pure Python, `cryptography` only) and working knowledge of
  OAuth 2.0/OIDC; WebAuthn/passkey experience is a plus.
- EUDI / eIDAS 2.0 exposure is ideal: OpenID4VP/OpenID4VCI, SD-JWT VC, or wallet-ecosystem
  work.
- Open-source working style: PRs, review discipline, adversarial tests first, DCO.
- **German residency + freelance status** makes you eligible to lead the Prototype Fund
  application — valuable but not required for the role itself.

## Context

vouchkit is the open foundation under the LifeCare network (a commercial consent platform —
stated up front: this repo is Apache-2.0 forever and complete on its own; the commercial
network is a separate thing that builds on it). Neutral-foundation stewardship of this project
is planned.

## Interested?

**Go to [lifecare.id](https://lifecare.id) and use the "Book a call" button** — a 15-minute
call with the founder. Mention vouchkit. Reading `src/vouchkit/sdjwt.py` and the test suite
first is the best possible preparation; opening an issue or a small PR before the call says
more than any CV.
