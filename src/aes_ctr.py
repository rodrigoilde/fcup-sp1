import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ctr_encrypt(plaintext, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext


def aes_ctr_decrypt(ciphertext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
