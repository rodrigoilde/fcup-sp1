"""
RSA-based encryption scheme:
Enc(m; r) = (RSA(r), H(0, r) XOR m_0, ..., H(n, r) XOR m_n)

r is uniform random, H = SHA-256 (l = 32 bytes), n = ceil(|m| / l)
RSA key size: 2048 bits
"""

import os
import math
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes

HASH_LEN = 32  # SHA-256 output


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def _h(index, r):
    # H(i, r) = SHA-256(i || r), i as 4-byte big-endian
    return hashlib.sha256(index.to_bytes(4, "big") + r).digest()


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _rsa_raw_encrypt(public_key, data):
    # RSA(r) = r^e mod n
    pub_numbers = public_key.public_numbers()
    e, n = pub_numbers.e, pub_numbers.n
    r_int = int.from_bytes(data, "big")
    c_int = pow(r_int, e, n)
    return c_int.to_bytes(256, "big")


def _rsa_raw_decrypt(private_key, ciphertext):
    # RSA^{-1}(c) = c^d mod n
    priv_numbers = private_key.private_numbers()
    d = priv_numbers.d
    n = priv_numbers.public_numbers.n
    c_int = int.from_bytes(ciphertext, "big")
    r_int = pow(c_int, d, n)
    return r_int.to_bytes(256, "big")


def rsa_encrypt(plaintext, public_key):
    # r random, with leading zero byte to guarantee r < n
    r = b'\x00' + os.urandom(255)

    rsa_r = _rsa_raw_encrypt(public_key, r)

    n_blocks = math.ceil(len(plaintext) / HASH_LEN) if len(plaintext) > 0 else 1
    encrypted_blocks = bytearray()

    for i in range(n_blocks):
        block = plaintext[i * HASH_LEN : (i + 1) * HASH_LEN]
        h_val = _h(i, r)
        xored = _xor_bytes(block, h_val[:len(block)])
        encrypted_blocks.extend(xored)

    return rsa_r, bytes(encrypted_blocks)


def rsa_decrypt(rsa_r, encrypted_blocks, private_key):
    r = _rsa_raw_decrypt(private_key, rsa_r)

    n_blocks = math.ceil(len(encrypted_blocks) / HASH_LEN) if len(encrypted_blocks) > 0 else 1
    plaintext = bytearray()

    for i in range(n_blocks):
        block = encrypted_blocks[i * HASH_LEN : (i + 1) * HASH_LEN]
        h_val = _h(i, r)
        xored = _xor_bytes(block, h_val[:len(block)])
        plaintext.extend(xored)

    return bytes(plaintext)
