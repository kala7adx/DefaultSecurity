"""Envelope encryption behind a KeyProvider interface (ADR-0006, ARCHITECTURE §10).

The API side only *seals* secrets (:class:`SecretSealer`, needs a :class:`DataKeyGenerator`).
The worker side only *opens* them (:class:`SecretOpener`, needs a :class:`DataKeyUnwrapper`).
With a cloud KMS the key policy enforces that split; the local provider can't, so it is
documented as a development and single-VM provider.
"""

from skyline_core.crypto.context import EncryptionContext, SecretPurpose
from skyline_core.crypto.envelope import SealedSecret, SecretOpener, SecretSealer
from skyline_core.crypto.errors import CryptoError, DecryptionError, KeyNotFoundError
from skyline_core.crypto.keyprovider import (
    DataKey,
    DataKeyGenerator,
    DataKeyUnwrapper,
    KeyProvider,
)
from skyline_core.crypto.local import LocalKeyProvider, create_kek_file

__all__ = [
    "CryptoError",
    "DataKey",
    "DataKeyGenerator",
    "DataKeyUnwrapper",
    "DecryptionError",
    "EncryptionContext",
    "KeyNotFoundError",
    "KeyProvider",
    "LocalKeyProvider",
    "SealedSecret",
    "SecretOpener",
    "SecretPurpose",
    "SecretSealer",
    "create_kek_file",
]
