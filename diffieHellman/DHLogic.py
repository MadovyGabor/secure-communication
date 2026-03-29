from cryptography.hazmat.primitives.asymmetric import dh
import secrets

def generate_dh_parameters() -> tuple[int, int]:
    """
    Generates the parameters for the Diffie-Hellman key exchange (RFC 3526).

    Returns:
        tuple[int, int]: A tuple containing (p, g) where:
            - p is a large prime number (modulus).
            - g is the generator (primitive root modulo p).
    """
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    return p, g


def generate_private_key(p: int) -> int:
    """
    Generates a cryptographically secure random private key.

    Args:
        p (int): The modulus (large prime number).

    Returns:
        int: The secret private key (a or b), strictly less than p.
    """
    private_key = secrets.randbelow(p)
    return private_key


def generate_public_key(private_key: int, g: int, p: int) -> int:
    """
    Calculates the public key to be shared over the network.
    Formula: A = g^a mod p

    Args:
        private_key (int): The user's secret private key.
        g (int): The generator.
        p (int): The modulus.

    Returns:
        int: The public key (A or B) to send to the peer.
    """
    public_key = pow(g, private_key, p)
    return public_key


def generate_shared_secret(private_key: int, peer_public_key: int, p: int) -> int:
    """
    Calculates the final shared secret using the peer's public key.
    Formula: K = B^a mod p (or K = A^b mod p)

    Args:
        private_key (int): The user's own secret private key.
        peer_public_key (int): The public key received from the network.
        p (int): The modulus.

    Returns:
        int: The final shared secret (K) which will be identical on both sides.
    """
    shared_secret = pow(peer_public_key, private_key, p)
    return shared_secret