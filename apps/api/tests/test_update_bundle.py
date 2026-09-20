from datetime import datetime, timezone

import pytest

from cyberaudit.update_bundle import (
    TrustedKeyStore,
    UpdateBundleService,
    UpdateManifest,
    generate_signing_keypair,
    sign_manifest,
)


def _manifest(**overrides) -> UpdateManifest:
    base = dict(
        bundle_id="knowledge-pack-2026-09",
        bundle_type="knowledge_pack",
        version="2026.09.0",
        created_at=datetime.now(timezone.utc),
        min_compatible_app_version="0.1.0",
        max_compatible_app_version=None,
        checksums={"pack.json": "a" * 64},
    )
    base.update(overrides)
    return UpdateManifest(**base)


def test_a_correctly_signed_bundle_with_matching_checksums_is_accepted():
    private_key, public_pem = generate_signing_keypair()
    manifest = _manifest(checksums={"pack.json": _sha256_of(b"hello world")})
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="0.1.0")
    result = service.validate(
        manifest.model_dump_json().encode(), signature, {"pack.json": b"hello world"}
    )
    assert result.accepted is True
    assert result.bundle_id == "knowledge-pack-2026-09"
    assert result.reasons == []


def test_a_bundle_signed_by_an_untrusted_key_is_rejected():
    private_key, _ = generate_signing_keypair()
    _, some_other_public_pem = generate_signing_keypair()
    manifest = _manifest()
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(
        TrustedKeyStore([some_other_public_pem]), current_app_version="0.1.0"
    )
    result = service.validate(manifest.model_dump_json().encode(), signature, {})
    assert result.accepted is False
    assert any("trusted key" in reason for reason in result.reasons)


def test_a_bundle_is_never_trusted_merely_because_it_was_uploaded():
    """No public key at all configured means nothing can ever verify."""
    private_key, _ = generate_signing_keypair()
    manifest = _manifest()
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(TrustedKeyStore([]), current_app_version="0.1.0")
    result = service.validate(manifest.model_dump_json().encode(), signature, {})
    assert result.accepted is False


def test_tampering_with_the_manifest_after_signing_is_detected():
    private_key, public_pem = generate_signing_keypair()
    manifest = _manifest()
    signature = sign_manifest(manifest, private_key)

    tampered = _manifest(version="9999.0.0")  # same signature, different content
    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="0.1.0")
    result = service.validate(tampered.model_dump_json().encode(), signature, {})
    assert result.accepted is False
    assert any("trusted key" in reason for reason in result.reasons)


def test_a_checksum_mismatch_is_rejected_even_with_a_valid_signature():
    private_key, public_pem = generate_signing_keypair()
    manifest = _manifest(checksums={"pack.json": _sha256_of(b"expected content")})
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="0.1.0")
    result = service.validate(
        manifest.model_dump_json().encode(), signature, {"pack.json": b"tampered content"}
    )
    assert result.accepted is False
    assert any("Checksum mismatch" in reason for reason in result.reasons)


def test_a_referenced_file_that_is_missing_is_rejected():
    private_key, public_pem = generate_signing_keypair()
    manifest = _manifest()
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="0.1.0")
    result = service.validate(manifest.model_dump_json().encode(), signature, {})
    assert result.accepted is False
    assert any("missing file" in reason for reason in result.reasons)


def test_an_incompatible_bundle_is_rejected():
    private_key, public_pem = generate_signing_keypair()
    manifest = _manifest(
        min_compatible_app_version="99.0.0", checksums={"pack.json": _sha256_of(b"x")}
    )
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="0.1.0")
    result = service.validate(manifest.model_dump_json().encode(), signature, {"pack.json": b"x"})
    assert result.accepted is False
    assert any("not compatible" in reason for reason in result.reasons)


def test_a_bundle_above_the_max_compatible_version_is_rejected():
    private_key, public_pem = generate_signing_keypair()
    manifest = _manifest(
        min_compatible_app_version="0.1.0",
        max_compatible_app_version="0.1.0",
        checksums={"pack.json": _sha256_of(b"x")},
    )
    signature = sign_manifest(manifest, private_key)

    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="9.0.0")
    result = service.validate(manifest.model_dump_json().encode(), signature, {"pack.json": b"x"})
    assert result.accepted is False


def test_malformed_manifest_json_is_rejected_without_raising():
    service = UpdateBundleService(TrustedKeyStore([]), current_app_version="0.1.0")
    result = service.validate(b"not json at all", b"irrelevant-signature")
    assert result.accepted is False
    assert result.bundle_id is None


def test_only_ed25519_public_keys_are_accepted_for_the_trust_store():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_pem = rsa_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError, match="Ed25519"):
        TrustedKeyStore([rsa_public_pem])


def _sha256_of(content: bytes) -> str:
    import hashlib

    return hashlib.sha256(content).hexdigest()
