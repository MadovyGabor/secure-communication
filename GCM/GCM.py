"""
Advanced Encryption Standard - Galois/Counter Mode 
Oliver Synak 
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from GCM.gcm_utils import xor_bytes, inc32
from GCM.gf import GHASH
import hmac


# Galois Counter Mode
def gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    if len(data) == 0:
        return b""

    counter = icb
    blocks_out = []

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        encryptor = cipher.encryptor()
        keystream = encryptor.update(counter) + encryptor.finalize()

        blocks_out.append(xor_bytes(block, keystream[:len(block)]))
        counter = inc32(counter)

    return b"".join(blocks_out)


def aes_gcm_encrypt(nonce: bytes, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    if len(nonce) != 12:
        raise ValueError("Nonce must be 96 bits")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    H = encryptor.update(b'\x00' * 16) + encryptor.finalize()

    Y0 = nonce + b'\x00\x00\x00\x01'
    Y1 = inc32(Y0)

    ciphertext = gctr(key, Y1, plaintext)

    S = GHASH(H, b"", ciphertext)

    tag = gctr(key, Y0, S)

    return ciphertext, tag


def aes_gcm_decrypt(nonce: bytes, key: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("Nonce must be 96 bits")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    H = encryptor.update(b'\x00' * 16) + encryptor.finalize()

    Y0 = nonce + b'\x00\x00\x00\x01'
    Y1 = inc32(Y0)

    S = GHASH(H, b"", ciphertext)
    T_calc = gctr(key, Y0, S)

    if not hmac.compare_digest(T_calc, tag):
        raise ValueError("Authentication failed")

    plaintext = gctr(key, Y1, ciphertext)

    return plaintext