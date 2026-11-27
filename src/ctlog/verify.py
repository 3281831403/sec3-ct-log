"""Signed Certificate Timestamp verification helpers.

The module exposes the eight functions used by the checking layer:

parse_sct, check_version, check_log_id, check_tree_size, leaf_hash,
check_signature, validate_sct and sct_batch.
"""

from __future__ import annotations

import hashlib
import hmac

HASH_SHA256 = 4
SIGNATURE_HMAC_SHA256 = 4

_LOG_ID_SIZE = 32
_LEAF_HASH_SIZE = 32
_SCT_VERSION = 1
_DEFAULT_SUPPORTED_VERSIONS = (_SCT_VERSION,)


def _as_bytes(value: bytes | bytearray | memoryview, *, name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes")


def _timestamp_bytes(value: int | None) -> bytes:
    if value is None:
        return b"\x00" * 8
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("timestamp must be a non-negative integer")
    return int(value).to_bytes(8, "big")


def _signed_payload(sct: dict) -> bytes:
    version = int(sct.get("version") or 0)
    log_id = _as_bytes(sct.get("log_id") or b"", name="log_id")
    tree_size = int(sct.get("tree_size") or 0)
    leaf = _as_bytes(sct.get("leaf_hash") or b"", name="leaf_hash")
    extensions = _as_bytes(sct.get("extensions") or b"", name="extensions")
    return (
        bytes([version & 0xFF])
        + log_id
        + _timestamp_bytes(sct.get("timestamp"))
        + tree_size.to_bytes(8, "big")
        + leaf
        + extensions
    )


def parse_sct(raw: bytes) -> dict:
    """Parse a compact signed certificate timestamp into its fields."""
    data = _as_bytes(raw, name="raw")
    minimum = 1 + _LOG_ID_SIZE + 8 + 8 + 2 + _LEAF_HASH_SIZE + 4
    if len(data) < minimum:
        raise ValueError("signed certificate timestamp is truncated")

    cursor = 0
    version = data[cursor]
    cursor += 1

    log_id = data[cursor : cursor + _LOG_ID_SIZE]
    cursor += _LOG_ID_SIZE

    timestamp = int.from_bytes(data[cursor : cursor + 8], "big")
    cursor += 8

    tree_size = int.from_bytes(data[cursor : cursor + 8], "big")
    cursor += 8

    extension_length = int.from_bytes(data[cursor : cursor + 2], "big")
    cursor += 2
    if cursor + extension_length + _LEAF_HASH_SIZE + 4 > len(data):
        raise ValueError("signed certificate timestamp is truncated")

    extensions = data[cursor : cursor + extension_length]
    cursor += extension_length

    leaf = data[cursor : cursor + _LEAF_HASH_SIZE]
    cursor += _LEAF_HASH_SIZE

    hash_algorithm = data[cursor]
    signature_algorithm = data[cursor + 1]
    signature_length = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
    cursor += 4

    if cursor + signature_length != len(data):
        raise ValueError("signed certificate timestamp has trailing data")

    return {
        "version": version,
        "log_id": log_id,
        "timestamp": timestamp,
        "tree_size": tree_size,
        "extensions": extensions,
        "leaf_hash": leaf,
        "signature": {
            "hash_algorithm": hash_algorithm,
            "signature_algorithm": signature_algorithm,
            "signature": data[cursor : cursor + signature_length],
        },
    }


def check_version(sct: dict, policy: dict) -> bool:
    """Return whether the timestamp carries a supported version."""
    version = sct.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        return False
    supported = (policy or {}).get("supported_versions")
    if supported is None:
        supported = _DEFAULT_SUPPORTED_VERSIONS
    return version in tuple(supported)


def check_log_id(sct: dict, trusted: list[bytes]) -> bool:
    """Return whether the timestamp was issued by a trusted log."""
    log_id = sct.get("log_id")
    if not isinstance(log_id, (bytes, bytearray, memoryview)):
        return False
    candidate = bytes(log_id)
    if len(candidate) != _LOG_ID_SIZE:
        return False
    for entry in trusted or ():
        try:
            candidate_id = _as_bytes(entry, name="trusted_log_id")
        except TypeError:
            continue
        if hmac.compare_digest(candidate_id, candidate):
            return True
    return False


def check_tree_size(sct: dict, proof: dict) -> bool:
    """Return whether the tree size covers the supplied leaf index."""
    size = int(sct.get("tree_size") or 0)
    index = int((proof or {}).get("leaf_index") or 0)
    if size == 0 or index < 0:
        return False
    return index < size


def leaf_hash(cert: bytes, issuer: bytes | None = None) -> bytes:
    """Return the Merkle leaf hash for a certificate and its issuer."""
    cert_bytes = _as_bytes(cert, name="cert")
    if issuer is None:
        entry = cert_bytes
    else:
        entry = _as_bytes(issuer, name="issuer") + cert_bytes
    framed = b"\x00" + len(entry).to_bytes(8, "big") + entry
    return hashlib.sha256(framed).digest()


def check_signature(sct: dict, log_key: bytes) -> bool:
    """Return whether the timestamp signature verifies under the log key."""
    signature = sct.get("signature") or {}
    try:
        hash_algorithm = int(signature.get("hash_algorithm"))
        signature_algorithm = int(signature.get("signature_algorithm"))
        tag = _as_bytes(signature.get("signature") or b"", name="signature")
        key = _as_bytes(log_key, name="log_key")
    except (TypeError, ValueError):
        return False

    if hash_algorithm != HASH_SHA256 or signature_algorithm != SIGNATURE_HMAC_SHA256:
        return False

    try:
        payload = _signed_payload(sct)
    except (TypeError, ValueError, OverflowError):
        return False

    expected = hmac.new(key, payload, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)


def _lookup_log_key(log_id: bytes, log_keys) -> bytes | None:
    """Return the key registered for ``log_id``, or ``None`` when absent."""
    if not isinstance(log_keys, dict):
        return None
    for candidate, key in log_keys.items():
        try:
            if isinstance(candidate, str):
                candidate_bytes = bytes.fromhex(candidate)
            else:
                candidate_bytes = _as_bytes(candidate, name="log_id")
            if candidate_bytes != log_id:
                continue
            return _as_bytes(key, name="log_key")
        except (TypeError, ValueError):
            continue
    return None


def validate_sct(sct: dict, policy: dict) -> list[str]:
    """Return the problem codes for one timestamp under a verification policy."""
    settings = dict(policy or {})
    problems: list[str] = []

    if not check_version(sct, settings):
        problems.append("unsupported_version")

    timestamp = sct.get("timestamp")
    missing_timestamp = timestamp is None
    if missing_timestamp:
        problems.append("missing_timestamp")

    log_id = sct.get("log_id")
    if not check_log_id(sct, settings.get("trusted_log_ids") or ()):
        problems.append("unknown_log")

    proof = {"leaf_index": int(settings.get("leaf_index") or 0)}
    if not check_tree_size(sct, proof):
        if not sct.get("tree_size"):
            problems.append("tree_size_zero")
        else:
            problems.append("tree_size_too_small")

    cert = settings.get("cert")
    if cert is not None:
        computed = leaf_hash(cert, settings.get("issuer"))
        expected = sct.get("leaf_hash")
        try:
            expected_bytes = _as_bytes(expected, name="leaf_hash")
        except TypeError:
            expected_bytes = None
        if expected_bytes != computed:
            problems.append("leaf_hash_mismatch")

    log_key = None
    if isinstance(log_id, (bytes, bytearray, memoryview)):
        log_key = _lookup_log_key(bytes(log_id), settings.get("log_keys"))
    if log_key is None:
        problems.append("signature_key_missing")
    elif not check_signature(sct, log_key):
        problems.append("invalid_signature")

    not_before = settings.get("cert_not_before")
    not_after = settings.get("cert_not_after")
    if (
        not missing_timestamp
        and isinstance(timestamp, int)
        and not isinstance(timestamp, bool)
    ):
        if not_before is not None and timestamp < not_before:
            problems.append("signature_time_outside_cert_validity")
        elif not_after is not None and timestamp > not_after:
            problems.append("signature_time_outside_cert_validity")

    return problems


def sct_batch(items: list[dict], policy: dict) -> dict:
    """Verify a batch of timestamps and return one result per certificate."""
    settings = dict(policy or {})
    results: dict[int, dict] = {}

    for position, item in enumerate(items):
        item_policy = dict(settings)
        item_policy.update(item.get("policy") or {})
        item_policy["cert"] = item["cert"]
        item_policy["issuer"] = item.get("issuer")
        item_policy["leaf_index"] = item.get(
            "leaf_index", item_policy.get("leaf_index", 0)
        )

        problems = validate_sct(item["sct"], item_policy)
        computed = leaf_hash(item["cert"], item.get("issuer"))
        results[position] = {
            "valid": not problems,
            "problems": problems,
            "leaf_hash": computed.hex(),
        }

    return results
