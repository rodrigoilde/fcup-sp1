"""AES-CTR encryption and decryption using the cryptography library."""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ctr_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256 in CTR mode.

    Returns:
        (nonce, ciphertext)
    """
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt ciphertext using AES-256 in CTR mode."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
