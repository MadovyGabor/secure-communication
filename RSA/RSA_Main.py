import hashlib

import protocol
from . import RSA_Math as RSALogic

def process_rsa_init_packet(message: str) -> tuple[int, int]:

    # Parses the received RSA_INIT packet

    print("[RSA Protocol] Received RSA_INIT packet. Parsing parameters...")

    e, n = protocol.parse_rsa_init(message)

    print(f"[RSA Protocol] Extracted Peer's Public Key: (e={e}, n={str(n)[:15]}...)")

    peer_public_key = (e, n)
    return peer_public_key


def build_rsa_auth_packet(text_message: str, my_private_key: tuple[int, int]) -> str:
    print("[RSA Protocol] Signing outgoing message for authentication...")
    message_bytes = text_message.encode('utf-8')
    message_hash = hashlib.sha256(message_bytes).digest()
    message_int = int.from_bytes(message_hash, 'big')

    signature = RSALogic.rsa_sign(message_int, my_private_key)

    packet = protocol.build_rsa_auth(text_message, signature)
    return packet


def process_rsa_auth_packet(message: str, peer_public_key: tuple[int, int]) -> tuple[bool, str]:
    print("[RSA Protocol] Received RSA_AUTH packet. Verifying signature...")

    text_message, signature = protocol.parse_rsa_auth(message)

    message_bytes = text_message.encode('utf-8')
    message_hash = hashlib.sha256(message_bytes).digest()
    message_int = int.from_bytes(message_hash, 'big')

    is_valid = RSALogic.rsa_verify(message_int, signature, peer_public_key)

    if is_valid:
        print("[RSA Protocol] AUTHENTICATION SUCCESS")
    else:
        print("[RSA Protocol] WARNING: Signature invalid!")

    return is_valid, text_message

def load_or_create_keys(filename = None) -> tuple[tuple[int, int], tuple[int, int]]:

    # Loads existing keys from JSON, or generates and saves new ones if none exist.

    public_key, private_key = None, None
    if(filename is not None):
        public_key, private_key = RSALogic.load_keys_from_json(filename)

    if public_key is None or private_key is None:
        print("[RSA Protocol] Generating RSA parameters (this might take a few seconds)...")
        public_key, private_key = RSALogic.generate_rsa_parameters(1024)
        if(filename is not None):
            RSALogic.save_keys_to_json(public_key, private_key, filename)

    return public_key, private_key

def build_rsa_init_packet(public_key: tuple[int, int]) -> str:

    # the initial packet to share this nodes public key.

    e, n = public_key

    packet = protocol.build_rsa_init(e, n)
    print("[RSA Protocol] RSA_INIT packet built successfully. Ready to send.")

    return packet