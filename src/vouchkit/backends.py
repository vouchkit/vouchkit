"""Backend seam — optional extension interfaces (see docs/design/backends.md).

The verification core stays a pure function; everything with a lifecycle lives
behind one of these interfaces, each with a local-first default. Hard rules:
no backend may alter verification semantics, and a `ReceiptSink` failure must
never fail or delay verification. Event payloads carry claim *names*, never
claim values.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "TrustAnchorSource",
    "StaticTrustAnchors",
    "UnknownIssuer",
    "VerificationEvent",
    "ReceiptSink",
    "NoopReceipts",
]


class UnknownIssuer(Exception):
    """No trust anchor is configured for the presented issuer."""


@runtime_checkable
class TrustAnchorSource(Protocol):
    """Who do we trust to issue credentials? Resolves an issuer to a public JWK."""

    def resolve(self, issuer: str, kid: str | None = None) -> dict[str, Any]: ...


@dataclass(frozen=True)
class StaticTrustAnchors:
    """Local-first default: issuer → JWK from configuration."""

    anchors: dict[str, dict[str, Any]]

    def resolve(self, issuer: str, kid: str | None = None) -> dict[str, Any]:
        try:
            return self.anchors[issuer]
        except KeyError:
            raise UnknownIssuer(f"no trust anchor configured for issuer {issuer!r}") from None


@dataclass(frozen=True)
class VerificationEvent:
    """What a `ReceiptSink` sees: verification metadata, never claim values."""

    issuer: str
    vct: str | None
    claim_names: frozenset[str]
    outcome: str  # "verified" or the failure exception class name
    at: int = field(default_factory=lambda: int(time.time()))


@runtime_checkable
class ReceiptSink(Protocol):
    """What record exists that this verification happened? Fire-and-forget."""

    def record(self, event: VerificationEvent) -> None: ...


class NoopReceipts:
    """Local-first default: no record."""

    def record(self, event: VerificationEvent) -> None:  # pragma: no cover - trivial
        return None
