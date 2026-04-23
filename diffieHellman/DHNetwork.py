from diffieHellman import DHLogic

def build_init_packet() -> tuple[str, int, int, int]:
    """
    Called by the Initiator: Retrieves fixed DH parameters and builds the initial DH_INIT packet.
    """
    print("[DH Protocol] Retrieving fixed DH parameters (RFC 3526 Group 14)...")
    p, g = DHLogic.get_dh_parameters()

    print("[DH Protocol] Generating secure private key...")
    private_key = DHLogic.generate_private_key(p)

    print("[DH Protocol] Generating public key (A)...")
    public_key = DHLogic.generate_public_key(private_key, g, p)

    raw_packet = f"DH_INIT:{p}:{g}:{public_key}"
    print("[DH Protocol] DH_INIT packet built successfully. Ready to send.")

    return raw_packet, p, g, private_key


def process_init_packet(message: str) -> tuple[str, int, bytes]:
    """
    Called by the Responder: Parses DH_INIT, validates keys, generates local keys, 
    derives AES key, and builds DH_ACCEPT response.
    """
    print("[DH Protocol] Parsing parameters...")

    try:
        parts = message.split(":")
        if len(parts) != 4 or parts[0] != "DH_INIT":
            raise ValueError("Malformed DH_INIT packet format.")
            
        p = int(parts[1])
        g = int(parts[2])
        peer_public_key = int(parts[3])
    except (ValueError, IndexError) as e:
        raise ValueError(f"[DH Protocol] Failed to parse DH_INIT packet: {e}")

    if not DHLogic.is_valid_public_key(peer_public_key, p):
        raise ValueError("[DH Protocol] FATAL: Invalid peer public key received!")

    print(f"[DH Protocol] Extracted Peer's Public Key: {str(peer_public_key)[:15]}...")
    print("[DH Protocol] Generating local private and public keys...")
    
    my_private_key = DHLogic.generate_private_key(p)
    my_public_key = DHLogic.generate_public_key(my_private_key, g, p)

    print("[DH Protocol] Calculating the SHARED SECRET (K) and deriving AES key...")
    shared_secret = DHLogic.generate_shared_secret(my_private_key, peer_public_key, p)
    aes_key = DHLogic.derive_aes_key(shared_secret)

    raw_accept = f"DH_ACCEPT:{my_public_key}"
    print("[DH Protocol] DH_ACCEPT packet built successfully. Ready to send.")

    return raw_accept, shared_secret, aes_key


def process_accept_packet(message: str, p: int, private_key: int) -> tuple[int, bytes]:
    """
    Called by the Initiator: Parses DH_ACCEPT, validates key, and derives the final AES key.
    """
    print("[DH Protocol] Extracting Peer's Public Key...")

    try:
        parts = message.split(":")
        if len(parts) != 2 or parts[0] != "DH_ACCEPT":
            raise ValueError("Malformed DH_ACCEPT packet format.")
            
        peer_public_key = int(parts[1])
    except (ValueError, IndexError) as e:
        raise ValueError(f"[DH Protocol] Failed to parse DH_ACCEPT packet: {e}")

    if not DHLogic.is_valid_public_key(peer_public_key, p):
        raise ValueError("[DH Protocol] FATAL: Invalid peer public key received!")

    print(f"[DH Protocol] Extracted Peer's Public Key: {str(peer_public_key)[:15]}...")
    print("[DH Protocol] Calculating the SHARED SECRET (K) and deriving AES key...")
    
    shared_secret = DHLogic.generate_shared_secret(private_key, peer_public_key, p)
    aes_key = DHLogic.derive_aes_key(shared_secret)

    print("[DH Protocol] Handshake complete! 32-byte AES key derived securely.")

    return shared_secret, aes_key