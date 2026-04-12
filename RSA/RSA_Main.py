import sympy
import json
import os
import hashlib

from . import RSA_Math as RSALogic

def build_rsa_init_packet() -> tuple[str, tuple[int, int]]:

    #  the initial packet to share this nodes public key.

    print("[RSA Protocol] Generating RSA parameters (this might take a few seconds)...")
    public_key, private_key = RSALogic.generate_rsa_parameters(1024)
    e, n = public_key

    packet = f"RSA_INIT:{e}:{n}"
    print("[RSA Protocol] RSA_INIT packet built successfully. Ready to send.")

    return packet, private_key


def process_rsa_init_packet(message: str) -> tuple[int, int]:

    # Examines the recieved the RSAbpacket

    print("[RSA Protocol] Received RSA_INIT packet. Parsing parameters...")

    # Split the message by colons to extract the values
    parts = message.split(":")
    e = int(parts[1])
    n = int(parts[2])

    print(f"[RSA Protocol] Extracted Peer's Public Key: (e={e}, n={str(n)[:15]}...)")

    peer_public_key = (e, n)
    return peer_public_key


def build_rsa_auth_packet(text_message: str, my_private_key: tuple[int, int]) -> str:
    print(f"[RSA Protocol] Signing outgoing message for authentication...")
    message_bytes = text_message.encode('utf-8')
    message_hash = hashlib.sha256(message_bytes).digest()
    message_int = int.from_bytes(message_hash, 'big')

    signature = RSALogic.rsa_sign(message_int, my_private_key)

    packet = f"RSA_AUTH:{text_message}|{signature}"
    return packet


def process_rsa_auth_packet(message: str, peer_public_key: tuple[int, int]) -> tuple[bool, str]:
    print("[RSA Protocol] Received RSA_AUTH packet. Verifying signature...")

    data = message[9:]
    text_message, signature_str = data.rsplit("|", 1)
    signature = int(signature_str)

    message_bytes = text_message.encode('utf-8')
    message_hash = hashlib.sha256(message_bytes).digest()
    message_int = int.from_bytes(message_hash, 'big')

    is_valid = RSALogic.rsa_verify(message_int, signature, peer_public_key)

    if is_valid:
        print(f"[RSA Protocol] AUTHENTICATION SUCCESS")
    else:
        print(f"[RSA Protocol] WARNING: Signature invalid!")

    return is_valid, text_message

def build_rsa_init_packet() -> tuple[str, tuple[int, int]]:

    # the initial packet to share this nodes public key.
    # Loads existing keys from JSON, or generates and saves new ones if none exist.

    public_key, private_key = RSALogic.load_keys_from_json()

    if public_key is None or private_key is None:
        print("[RSA Protocol] Generating RSA parameters (this might take a few seconds)...")
        public_key, private_key = RSALogic.generate_rsa_parameters(1024)
        RSALogic.save_keys_to_json(public_key, private_key)

    e, n = public_key

    packet = f"RSA_INIT:{e}:{n}"
    print("[RSA Protocol] RSA_INIT packet built successfully. Ready to send.")

    return packet, private_key