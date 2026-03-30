"""RSA-based encryption scheme as specified in the assignment.

Enc(m; r) = (RSA(r), H(0, r) XOR m_0, ..., H(n, r) XOR m_n)

Where:
- r is a uniform random value
- H = SHA-256 (output size l = 32 bytes)
- n = ceil(|m| / l)
- RSA key size: 2048 bits
"""

import os
import math
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes


HASH_LEN = 32  # SHA-256 output size in bytes


def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def _h(index: int, r: bytes) -> bytes:
    """Compute H(index, r) = SHA-256(index || r)."""
    return hashlib.sha256(index.to_bytes(4, "big") + r).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (result length = len(a))."""
    return bytes(x ^ y for x, y in zip(a, b))


def _rsa_raw_encrypt(public_key, data: bytes) -> bytes:
    """Apply raw RSA (textbook) via OAEP would change semantics.

    We use the public key's raw numbers to compute RSA(r) = r^e mod n.
    """
    pub_numbers = public_key.public_numbers()
    e = pub_numbers.e
    n = pub_numbers.n
    # r must be < n; with 2048-bit key, n is 256 bytes
    r_int = int.from_bytes(data, "big")
    c_int = pow(r_int, e, n)
    return c_int.to_bytes(256, "big")


def _rsa_raw_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Compute RSA^{-1}(c) = c^d mod n."""
    priv_numbers = private_key.private_numbers()
    d = priv_numbers.d
    n = priv_numbers.public_numbers.n
    c_int = int.from_bytes(ciphertext, "big")
    r_int = pow(c_int, d, n)
    return r_int.to_bytes(256, "big")


def rsa_encrypt(plaintext: bytes, public_key) -> tuple[bytes, bytes]:
    """Encrypt using the RSA-based scheme.

    Returns:
        (rsa_r, encrypted_blocks) where rsa_r is RSA(r) and
        encrypted_blocks is the concatenation of H(i,r) XOR m_i.
    """
    # r is a random 256-byte value (must be < n for RSA)
    # Use 255 bytes of randomness padded with a leading zero byte to ensure r < n
    r = b'\x00' + os.urandom(255)

    # RSA(r)
    rsa_r = _rsa_raw_encrypt(public_key, r)

    # Split plaintext into blocks of HASH_LEN bytes
    n_blocks = math.ceil(len(plaintext) / HASH_LEN) if len(plaintext) > 0 else 1
    encrypted_blocks = bytearray()

    for i in range(n_blocks):
        block = plaintext[i * HASH_LEN : (i + 1) * HASH_LEN]
        h_val = _h(i, r)
        # XOR block with hash (handle last block which may be shorter)
        xored = _xor_bytes(block, h_val[:len(block)])
        encrypted_blocks.extend(xored)

    return rsa_r, bytes(encrypted_blocks)


def rsa_decrypt(rsa_r: bytes, encrypted_blocks: bytes, private_key) -> bytes:
    """Decrypt using the RSA-based scheme."""
    # Recover r = RSA^{-1}(rsa_r)
    r = _rsa_raw_decrypt(private_key, rsa_r)

    # Decrypt blocks
    n_blocks = math.ceil(len(encrypted_blocks) / HASH_LEN) if len(encrypted_blocks) > 0 else 1
    plaintext = bytearray()

    for i in range(n_blocks):
        block = encrypted_blocks[i * HASH_LEN : (i + 1) * HASH_LEN]
        h_val = _h(i, r)
        xored = _xor_bytes(block, h_val[:len(block)])
        plaintext.extend(xored)

    return bytes(plaintext)
