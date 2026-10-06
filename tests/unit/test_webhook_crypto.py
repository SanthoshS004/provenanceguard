"""Unit tests for AES-256-GCM webhook secret encryption engine."""

import pytest

from provenanceguard.infrastructure.webhooks.webhook_crypto import (
    WebhookCrypto,
    WebhookCryptoError,
)


def test_aes256_gcm_encryption_decryption_success():
    """Validates encryption and decryption cycle with AES-256-GCM."""
    secret = WebhookCrypto.generate_secret()
    version, nonce, ciphertext, fingerprint = WebhookCrypto.encrypt_secret(secret, version=1)

    assert version == 1
    assert len(nonce) == 12
    assert len(ciphertext) > 0
    assert len(fingerprint) == 64

    # Decrypt
    decrypted = WebhookCrypto.decrypt_secret(version, nonce, ciphertext)
    assert decrypted == secret


def test_ciphertext_is_not_plaintext():
    """Verifies ciphertext contains no plaintext secret bytes."""
    secret = "super_secret_webhook_signing_key_12345"
    _, _, ciphertext, _ = WebhookCrypto.encrypt_secret(secret)
    assert secret.encode("utf-8") not in ciphertext


def test_tampered_ciphertext_fails_authentication():
    """Verifies modified ciphertext triggers decryption failure (AEAD tag mismatch)."""
    secret = WebhookCrypto.generate_secret()
    version, nonce, ciphertext, _ = WebhookCrypto.encrypt_secret(secret)

    # Tamper with the last byte
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[-1] ^= 0xFF

    with pytest.raises(WebhookCryptoError, match="tampered ciphertext or wrong key"):
        WebhookCrypto.decrypt_secret(version, nonce, bytes(tampered_ciphertext))


def test_nonce_uniqueness_per_encryption():
    """Verifies unique 12-byte nonces are generated for identical secrets."""
    secret = "identical_secret_string"
    _, nonce1, cipher1, _ = WebhookCrypto.encrypt_secret(secret)
    _, nonce2, cipher2, _ = WebhookCrypto.encrypt_secret(secret)

    assert nonce1 != nonce2
    assert cipher1 != cipher2
