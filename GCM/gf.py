from gcm_utils import xor_bytes, split_blocks

def gf_multiply(x: bytes, h: bytes) -> bytes:
    R = 0xe1000000000000000000000000000000

    X = int.from_bytes(x, 'big')
    V = int.from_bytes(h, 'big')
    result = 0

    for _ in range(128):
        if (X >> 127) == 1:
            result ^= V

        if (V & 1) == 0:
            V >>= 1
        else:
            V = (V >> 1) ^ R

        X = (X << 1) & ((1 << 128) - 1)

    return result.to_bytes(16, 'big')


def GHASH(hash_subkey: bytes ,aad: bytes, cipher: bytes):
    result = b'\x00' * 16
    A,C = split_blocks(aad, 16), split_blocks(cipher, 16)
    len_A, len_C = len(aad) * 8, len(cipher) * 8

    for block in A:
        result = xor_bytes(result, block)
        result = gf_multiply(result, hash_subkey)

    for block in C:
        result = xor_bytes(result, block)
        result = gf_multiply(result, hash_subkey)

    length_block = len_A.to_bytes(8, 'big') + len_C.to_bytes(8, 'big')

    result = xor_bytes(result, length_block)
    result = gf_multiply(result, hash_subkey)

    return result