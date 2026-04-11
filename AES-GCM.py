"""

Advaned Encryption Standard - Galois/Counter Mode 
Oliver Synak 
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys, math, numpy

data = b'\x01\x02\x03\x04\x05'

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


def gtcr(key, icb, data): # data = plaintext/ ciphertext
    pass


def GCM(nonce, key: bytes, plaintext: str) -> str:



    pass

print(split_blocks(data))
