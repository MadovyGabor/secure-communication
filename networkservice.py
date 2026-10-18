"""Shared base class for the client, server and attacker, with AES-GCM payload helpers."""
import os
import socket
from abc import ABC, abstractmethod

import protocol
from GCM.GCM import aes_gcm_encrypt, aes_gcm_decrypt

class NetworkService(ABC):
    def __init__(self, host : str, port : int):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @abstractmethod
    def loop(self):
        pass

    def decrypt_payload(self, encrypted_data, secret):
        nonce, tag, ciphertext = protocol.parse_encrypted(encrypted_data)
        return aes_gcm_decrypt(nonce, secret, ciphertext, tag)

    def encrypt_payload(self, plaintext_bytes, secret):
        nonce = os.urandom(protocol.NONCE_SIZE)
        ciphertext, tag = aes_gcm_encrypt(nonce, secret, plaintext_bytes)
        return protocol.build_encrypted(nonce, tag, ciphertext)

    # helper function for decrypting and decoding received data
    def decrypt_and_decode(self, encrypted_data, secret):
        decrypted_data = self.decrypt_payload(encrypted_data, secret)
        return decrypted_data.decode("utf-8", errors="replace")


    @abstractmethod
    def shutdown(self):
        pass
