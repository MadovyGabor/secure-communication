"""
Advaned Encryption Standard - Galois/Counter Mode 
Oliver Synak 
"""




from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gcm_utils import xor_bytes, inc32
from gf import GHASH





"""
--- Testovacie premenné ---

key = b'\x00' * 16
noonce = b'\x00' * 12
plaintext = b'Hello AES GCM mode test!!!'

"""




# Gallois Counter Mode
def gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    if len(data) == 0:
        return b""

    counter = icb
    blocks_out = []

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        encryptor = cipher.encryptor()
        encrypted_counter = encryptor.update(counter)

        xored = xor_bytes(block, encrypted_counter[:len(block)])
        blocks_out.append(xored)

        counter = inc32(counter)

    return b"".join(blocks_out)


def aes_gcm_encrypt(nonce: bytes, key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    if len(nonce) != 12:
        raise ValueError("Nonce must be 96 bits")

    # H = AES(key, 0^128)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    H = encryptor.update(b'\x00' * 16)

    # Counters
    Y0 = nonce + b'\x00\x00\x00\x01'
    Y1 = inc32(Y0)

    # Encrypt
    ciphertext = gctr(key, Y1, plaintext)

    # GHASH
    ghash_result = GHASH(H, b"", ciphertext)

    # Tag
    tag = gctr(key, Y0, ghash_result)

    return nonce, ciphertext, tag




"""
C, T = AES_GCM(nonce, key, plaintext)
print(f"Šifra: {C}\nTag: {T}")

"""