"""

Advaned Encryption Standard - Galois/Counter Mode 
Oliver Synak 
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys, math, numpy

data = b'\x01\x02\x03\x04\x05'

key = b'\x00' * 16

icb = b'\x00' * 12 + b'\x00\x00\x00\x01'  # 96-bit nonce + counter=1

plaintext = b'Hello AES GCM mode test!!!'

# Operácie XOR
def xor_bytes(a: bytes, b: bytes) -> bytes:
    result = []
    if len(a) == len(b):
        for x,y in zip(a,b):
            result.append(x ^ y)
        return bytes(result)
    else:
        print("Chyba: Rozdiel v dĺžke")
        return -1
    
def inc32(counter: bytes) -> bytes:
    prefix = counter[:-4]
    last4 = counter[-4:]

    number = int.from_bytes(last4, byteorder='big')
    number = (number + 1) % (2**32)

    new_last4 = number.to_bytes(4, byteorder='big')

    return prefix + new_last4

def split_blocks(data: bytes, block_size=16) -> List[bytes]:
    result = []
    for i in range(0,len(data),block_size):
        block = data[i:i+16]
        if len(block) < 16:
            missing = 16 - len(block)
            block += (missing * b'\x00')
        result.append(block)
    return result


def gctr(key, icb, data) -> bytes:  # data = plaintext / ciphertext
    if len(data) == 0:
        return b""

    blocks = split_blocks(data, 16)
    counter = icb
    result = b""

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    for block in blocks:
        encrypted_counter = encryptor.update(counter)
        xored = xor_bytes(block, encrypted_counter[:len(block)])
        result += xored
        counter = inc32(counter)

    return result

def ghash(hash_subkey , aad: bytes, cipher):
    pass


def GCM(nonce, key: bytes, plaintext: str) -> str:



    pass

ciphertext = gctr(key, icb, plaintext)
decrypted = gctr(key, icb, ciphertext)

print(ciphertext)
print(decrypted)