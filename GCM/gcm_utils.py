"""Byte helpers for AES-GCM: XOR, 32-bit counter increment and zero-padded block splitting."""

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))
    
def inc32(counter: bytes) -> bytes:
    prefix = counter[:-4]
    last4 = counter[-4:]

    number = int.from_bytes(last4, 'big')
    number = (number + 1) % (2**32)

    return prefix + number.to_bytes(4, 'big')

def split_blocks(data: bytes, block_size=16) -> list[bytes]:
    result = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < block_size:
            block += b'\x00' * (block_size - len(block))
        result.append(block)
    return result
