import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 3526 MODP Group 14 (2048-bit)
# These are cryptographically vetted "Safe Primes" used as an industry standard.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

def get_dh_parameters() -> tuple[int, int]:
    """
    Returns the fixed RFC 3526 DH parameters (P, G).
    """
    return DH_P, DH_G

def generate_private_key(p: int) -> int:
    """
    Generates a cryptographically secure random private key in the safe range [2, p-2].
    """
    while True:
        private_key = secrets.randbelow(p - 1)
        if private_key >= 2:
            return private_key

def is_valid_public_key(public_key: int, p: int) -> bool:
    """
    Validates the received public key to prevent Small Subgroup Attacks.
    """
    return 1 < public_key < p - 1

def generate_public_key(private_key: int, g: int, p: int) -> int:
    """
    Calculates the public key to be shared over the network.
    Formula: A = g^a mod p
    """
    return pow(g, private_key, p)

def generate_shared_secret(private_key: int, peer_public_key: int, p: int) -> int:
    """
    Calculates the raw shared secret using the peer's public key.
    Formula: K = B^a mod p
    """
    return pow(peer_public_key, private_key, p)

def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derives a 32-byte (256-bit) AES key from the raw DH shared secret using HKDF.
    
    Args:
        shared_secret (int): The raw integer resulting from DH math.
        
    Returns:
        bytes: The derived 32-byte symmetric key.
    """
    # Convert integer to bytes (256 bytes for a 2048-bit number)
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    
    # Use HKDF to derive a strong symmetric key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dh key exchange'
    )
    key = hkdf.derive(shared_secret_bytes)
    return key