"""Public tests for certificate transparency timestamp checks."""

import hashlib
import hmac

from ctlog import (
    check_log_id,
    check_signature,
    check_tree_size,
    leaf_hash,
    parse_sct,
    sct_batch,
    validate_sct,
)

VERSION = 1
LOG_ID = bytes(range(32))
UNKNOWN_LOG_ID = bytes(range(32, 64))
LOG_KEY = b"public-log-key-2026"
OTHER_KEY = b"other-log-key-2026"
CERT_A = b"certificate-alpha"
ISSUER_A = b"issuer-alpha"
CERT_B = b"certificate-beta"
ISSUER_B = b"issuer-beta"
TIMESTAMP = 1_750_000_000_000
NOT_BEFORE = 1_749_000_000_000
NOT_AFTER = 1_751_000_000_000


def _payload(version, log_id, timestamp, tree_size, leaf, extensions):
    return (
        bytes([version])
        + log_id
        + int(timestamp).to_bytes(8, "big")
        + int(tree_size).to_bytes(8, "big")
        + leaf
        + extensions
    )


def _make_sct(
    cert=CERT_A,
    issuer=ISSUER_A,
    *,
    log_id=LOG_ID,
    key=LOG_KEY,
    version=VERSION,
    timestamp=TIMESTAMP,
    tree_size=8,
    extensions=b"",
    leaf=None,
):
    if leaf is None:
        leaf = leaf_hash(cert, issuer)
    tag = hmac.new(
        key,
        _payload(version, log_id, timestamp, tree_size, leaf, extensions),
        hashlib.sha256,
    ).digest()
    return {
        "version": version,
        "log_id": log_id,
        "timestamp": timestamp,
        "tree_size": tree_size,
        "extensions": extensions,
        "leaf_hash": leaf,
        "signature": {
            "hash_algorithm": 4,
            "signature_algorithm": 4,
            "signature": tag,
        },
    }


def _raw(**kwargs):
    sct = _make_sct(**kwargs)
    tag = sct["signature"]["signature"]
    return (
        bytes([sct["version"]])
        + sct["log_id"]
        + int(sct["timestamp"]).to_bytes(8, "big")
        + int(sct["tree_size"]).to_bytes(8, "big")
        + len(sct["extensions"]).to_bytes(2, "big")
        + sct["extensions"]
        + sct["leaf_hash"]
        + b"\x04\x04"
        + len(tag).to_bytes(2, "big")
        + tag
    )


def _policy(
    *,
    cert=CERT_A,
    issuer=ISSUER_A,
    trusted=None,
    keys=None,
    not_before=NOT_BEFORE,
    not_after=NOT_AFTER,
    leaf_index=3,
):
    if trusted is None:
        trusted = [LOG_ID]
    if keys is None:
        keys = {LOG_ID: LOG_KEY}
    return {
        "supported_versions": [VERSION],
        "trusted_log_ids": trusted,
        "log_keys": keys,
        "cert": cert,
        "issuer": issuer,
        "cert_not_before": not_before,
        "cert_not_after": not_after,
        "leaf_index": leaf_index,
    }


def test_parse_signing_timestamp():
    sct = parse_sct(_raw(timestamp=TIMESTAMP))

    assert sct["version"] == VERSION
    assert sct["log_id"] == LOG_ID
    assert sct["timestamp"] == TIMESTAMP
    assert sct["tree_size"] == 8

    policy = _policy(
        not_before=TIMESTAMP - 10_000,
        not_after=TIMESTAMP - 1,
    )
    assert "signature_time_outside_cert_validity" in validate_sct(sct, policy)


def test_untrusted_log_id_is_rejected():
    sct = _make_sct(log_id=UNKNOWN_LOG_ID, key=OTHER_KEY)

    assert check_log_id(sct, [LOG_ID]) is False
    assert "unknown_log" in validate_sct(sct, _policy())


def test_tree_size_must_cover_leaf_index():
    sct = _make_sct(tree_size=3)

    assert check_tree_size(sct, {"leaf_index": 3}) is False
    assert "tree_size_too_small" in validate_sct(sct, _policy(leaf_index=3))


def test_signature_verification():
    sct = _make_sct(extensions=b"public-extension")
    assert check_signature(sct, LOG_KEY) is True

    broken = _make_sct(extensions=b"public-extension")
    tag = bytearray(broken["signature"]["signature"])
    tag[0] ^= 0x01
    broken["signature"]["signature"] = bytes(tag)
    assert check_signature(broken, LOG_KEY) is False

    assert "invalid_signature" not in validate_sct(sct, _policy())
    assert "invalid_signature" in validate_sct(broken, _policy())


def test_batch_keeps_certificates_independent():
    first = _make_sct(cert=CERT_A, issuer=ISSUER_A, tree_size=8)
    second = _make_sct(
        cert=CERT_B,
        issuer=ISSUER_B,
        log_id=UNKNOWN_LOG_ID,
        key=OTHER_KEY,
        tree_size=8,
        leaf=leaf_hash(CERT_A, ISSUER_A),
    )

    results = sct_batch(
        [
            {"sct": first, "cert": CERT_A, "issuer": ISSUER_A, "leaf_index": 2},
            {"sct": second, "cert": CERT_B, "issuer": ISSUER_B, "leaf_index": 2},
        ],
        _policy(),
    )

    assert results[0]["valid"] is True
    assert results[1]["valid"] is False
    assert results[0]["leaf_hash"] != results[1]["leaf_hash"]