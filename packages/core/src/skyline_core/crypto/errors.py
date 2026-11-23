"""Crypto errors. Messages are generic on purpose: they never include key material or data."""


class CryptoError(Exception):
    """Base class for envelope-encryption failures."""


class DecryptionError(CryptoError):
    """Authentication failed: wrong key, wrong context, or tampered ciphertext."""

    def __init__(self) -> None:
        super().__init__("decryption failed")


class KeyNotFoundError(CryptoError):
    """The key ID named by a wrapped data key is not available to this provider."""

    def __init__(self) -> None:
        super().__init__("key not available")
