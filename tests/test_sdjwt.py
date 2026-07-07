"""SD-JWT VC verification core — adversarial-first test suite.

The verifier's value is what it rejects: every test ending in `_rejected` is a
forgery/misuse case a relying party must never accept.
"""

import pytest

from vouchkit import (
    DisclosureError,
    InvalidKeyBinding,
    InvalidSignature,
    SdJwtError,
    UnsupportedAlgorithm,
    verify_sd_jwt_vc,
)
from vouchkit.sdjwt import ExpiredCredential, _b64url_decode, _b64url_encode
from vouchkit.testkit import TestHolder, TestIssuer, _b64url_json, _sign_jwt

AUD = "https://rp.example"
NONCE = "nonce-123"


@pytest.fixture()
def issued():
    issuer = TestIssuer()
    holder = TestHolder()
    issuer_jwt, disclosures = issuer.issue(
        {"given_name": "Ada", "family_name": "Lovelace", "resident_country": "DE"},
        holder_jwk=holder.public_jwk,
    )
    return issuer, holder, issuer_jwt, disclosures


def test_happy_path_selective_disclosure(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    presentation = holder.present(
        issuer_jwt, disclosures, ["given_name"], aud=AUD, nonce=NONCE
    )
    result = verify_sd_jwt_vc(
        presentation, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE
    )
    assert result.claims == {"given_name": "Ada"}
    assert "family_name" not in result.claims  # undisclosed stays undisclosed
    assert result.key_binding_verified is True
    assert result.issuer == issuer.issuer
    assert result.vct == "urn:eudi:test:credential:1"


def test_wrong_issuer_key_rejected(issued):
    _, holder, issuer_jwt, disclosures = issued
    other = TestIssuer()
    presentation = holder.present(issuer_jwt, disclosures, ["given_name"], aud=AUD, nonce=NONCE)
    with pytest.raises(InvalidSignature):
        verify_sd_jwt_vc(presentation, other.public_jwk, expected_aud=AUD, expected_nonce=NONCE)


def test_tampered_disclosure_value_rejected(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    forged = _b64url_json(["salt", "given_name", "Mallory"])
    presentation = "~".join([issuer_jwt, forged]) + "~"
    with pytest.raises(DisclosureError):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, require_key_binding=False)


def test_dangling_disclosure_rejected(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    other_issuer_jwt, other_disclosures = TestIssuer().issue({"x": 1})
    presentation = "~".join([issuer_jwt, disclosures["given_name"], other_disclosures["x"]]) + "~"
    with pytest.raises(DisclosureError):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, require_key_binding=False)


def test_duplicate_disclosure_rejected(issued):
    issuer, _, issuer_jwt, disclosures = issued
    d = disclosures["given_name"]
    presentation = "~".join([issuer_jwt, d, d]) + "~"
    with pytest.raises(DisclosureError):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, require_key_binding=False)


def test_alg_none_rejected(issued):
    issuer, _, _, _ = issued
    header = _b64url_json({"alg": "none", "typ": "dc+sd-jwt"})
    payload = _b64url_json({"iss": issuer.issuer, "_sd": [], "_sd_alg": "sha-256"})
    presentation = f"{header}.{payload}." + "~"
    with pytest.raises(UnsupportedAlgorithm):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, require_key_binding=False)


def test_missing_key_binding_rejected_by_default(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    presentation = holder.present(issuer_jwt, disclosures, ["given_name"])  # no KB
    with pytest.raises(InvalidKeyBinding):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE)


def test_kb_wrong_nonce_rejected(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    presentation = holder.present(issuer_jwt, disclosures, ["given_name"], aud=AUD, nonce="stale")
    with pytest.raises(InvalidKeyBinding):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE)


def test_kb_wrong_audience_rejected(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    presentation = holder.present(
        issuer_jwt, disclosures, ["given_name"], aud="https://evil.example", nonce=NONCE
    )
    with pytest.raises(InvalidKeyBinding):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE)


def test_kb_replay_onto_other_presentation_rejected(issued):
    """sd_hash binds the KB-JWT to the exact disclosure set — swapping sets must fail."""
    issuer, holder, issuer_jwt, disclosures = issued
    p1 = holder.present(issuer_jwt, disclosures, ["given_name"], aud=AUD, nonce=NONCE)
    kb_jwt = p1.rsplit("~", 1)[1]
    replayed = "~".join([issuer_jwt, disclosures["family_name"]]) + "~" + kb_jwt
    with pytest.raises(InvalidKeyBinding):
        verify_sd_jwt_vc(replayed, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE)


def test_kb_signed_by_wrong_holder_rejected(issued):
    issuer, _, issuer_jwt, disclosures = issued
    thief = TestHolder()  # not the cnf.jwk holder
    presentation = thief.present(issuer_jwt, disclosures, ["given_name"], aud=AUD, nonce=NONCE)
    with pytest.raises(InvalidSignature):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE)


def test_expired_credential_rejected():
    issuer = TestIssuer()
    holder = TestHolder()
    issuer_jwt, disclosures = issuer.issue(
        {"a": 1}, holder_jwk=holder.public_jwk, lifetime=10, now=1_000
    )
    presentation = holder.present(issuer_jwt, disclosures, ["a"], aud=AUD, nonce=NONCE)
    with pytest.raises(ExpiredCredential):
        verify_sd_jwt_vc(
            presentation, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE, now=2_000
        )


def test_unknown_sd_alg_rejected():
    import json

    issuer = TestIssuer()
    issuer_jwt, _ = issuer.issue({"a": 1})
    payload = json.loads(_b64url_decode(issuer_jwt.split(".")[1]))
    payload["_sd_alg"] = "md5"
    forged = _sign_jwt({"alg": "ES256", "typ": "dc+sd-jwt"}, payload, issuer.key)
    with pytest.raises(UnsupportedAlgorithm):
        verify_sd_jwt_vc(forged + "~", issuer.public_jwk, require_key_binding=False)


def test_claim_name_collision_rejected():
    """A disclosure must not overwrite a claim already present in the payload."""
    import json

    from vouchkit.sdjwt import _sha256_b64url

    issuer = TestIssuer()
    issuer_jwt, disclosures = issuer.issue({"iss_shadow": "x"})
    payload = json.loads(_b64url_decode(issuer_jwt.split(".")[1]))
    collide = _b64url_json(["salt2", "iss_shadow", "evil"])
    payload["_sd"].append(_sha256_b64url(collide))
    forged = _sign_jwt({"alg": "ES256", "typ": "dc+sd-jwt"}, payload, issuer.key)
    presentation = "~".join([forged, disclosures["iss_shadow"], collide]) + "~"
    with pytest.raises(DisclosureError):
        verify_sd_jwt_vc(presentation, issuer.public_jwk, require_key_binding=False)


def test_presentation_without_kb_allowed_when_opted_out(issued):
    issuer, holder, issuer_jwt, disclosures = issued
    presentation = holder.present(issuer_jwt, disclosures, ["resident_country"])
    result = verify_sd_jwt_vc(presentation, issuer.public_jwk, require_key_binding=False)
    assert result.claims == {"resident_country": "DE"}
    assert result.key_binding_verified is False


def test_non_sdjwt_input_rejected(issued):
    issuer, *_ = issued
    with pytest.raises(SdJwtError):
        verify_sd_jwt_vc("garbage", issuer.public_jwk)
    assert _b64url_encode(b"x") == "eA"  # helper sanity
