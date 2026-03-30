"""SHA-256 hash generation using the cryptography library."""

from cryptography.hazmat.primitives import hashes


def sha256_digest(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
