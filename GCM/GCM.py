"""
Advaned Encryption Standard - Galois/Counter Mode 
Oliver Synak 
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gcm_utils import xor_bytes, inc32, split_blocks_no_padding
from gf import GHASH

# Testovacie premenné
key = b'\x00' * 16
nonce = b'\x00' * 12
plaintext = b'Hello AES GCM mode test!!!'

# Gallois 
def GCTR(key: bytes, icb: bytes, data: bytes) -> bytes:
    if len(data) == 0:
        return b""

    blocks = split_blocks_no_padding(data, 16)
    counter = icb
    result = b""

    for block in blocks:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()

        encrypted_counter = encryptor.update(counter)
        encryptor.finalize()

        xored = xor_bytes(block, encrypted_counter[:len(block)])
        result += xored

        counter = inc32(counter)

    return result


def AES_GCM(nonce, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:

    # Hash subkey
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    H = encryptor.update(b'\x00' * 16)
    encryptor.finalize()

    # Counters
    Y0 = nonce + b'\x00\x00\x00\x01'
    Y1 = inc32(Y0)
    
    # Encryption
    ciphertext = GCTR(key, Y1, plaintext)

    # GHASH math
    GHASH_result = GHASH(H, b"", ciphertext)

    # tag
    tag = GCTR(key, Y0, GHASH_result)

    return ciphertext, tag

C, T = AES_GCM(nonce, key, plaintext)
print(f"Šifra: {C}\nTag: {T}")
