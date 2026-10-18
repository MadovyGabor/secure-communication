import unittest
import os

from diffieHellman import DHLogic
from RSA import RSA_Math, RSA_Main
from GCM.GCM import aes_gcm_encrypt, aes_gcm_decrypt
from diffieHellman import DHNetwork

class TestCryptoSystem(unittest.TestCase):
    
    def test_dh_logic(self):
        # Test DH parameter generation
        p, g = DHLogic.get_dh_parameters()
        self.assertIsNotNone(p)
        self.assertEqual(g, 2)
        
        # Test keypair generation
        priv1 = DHLogic.generate_private_key(p)
        pub1 = DHLogic.generate_public_key(priv1, g, p)
        
        priv2 = DHLogic.generate_private_key(p)
        pub2 = DHLogic.generate_public_key(priv2, g, p)
        
        # Test shared secret
        secret1 = DHLogic.generate_shared_secret(priv1, pub2, p)
        secret2 = DHLogic.generate_shared_secret(priv2, pub1, p)
        self.assertEqual(secret1, secret2)
        
        # Test AES key derivation
        aes_key1 = DHLogic.derive_aes_key(secret1)
        aes_key2 = DHLogic.derive_aes_key(secret2)
        self.assertEqual(aes_key1, aes_key2)
        self.assertEqual(len(aes_key1), 32) # 256-bit key

    def test_aes_gcm(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        message = b"Secret Message 123"
        
        # Encrypt
        ciphertext, tag = aes_gcm_encrypt(nonce, key, message)
        self.assertNotEqual(ciphertext, message)
        
        # Decrypt
        decrypted = aes_gcm_decrypt(nonce, key, ciphertext, tag)
        self.assertEqual(decrypted, message)

    def test_rsa_signatures(self):
        import hashlib
        # Generate keys
        public_key, private_key = RSA_Math.generate_rsa_parameters(1024)
        message = b"Test Message for Signature"
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        
        # Sign
        signature = RSA_Math.rsa_sign(message_hash, private_key)
        
        # Verify Valid
        is_valid = RSA_Math.rsa_verify(message_hash, signature, public_key)
        self.assertTrue(is_valid)
        
        # Verify Invalid (tampered message)
        tampered_message = b"Test Message for signature"
        tampered_hash = int.from_bytes(hashlib.sha256(tampered_message).digest(), 'big')
        is_invalid = RSA_Math.rsa_verify(tampered_hash, signature, public_key)
        self.assertFalse(is_invalid)

    def test_rsa_auth_packet(self):
        public_key, private_key = RSA_Math.generate_rsa_parameters(1024)
        
        dh_packet = "DH_INIT:123:456:789"
        
        # Build auth packet
        auth_packet = RSA_Main.build_rsa_auth_packet(dh_packet, private_key)
        self.assertTrue(auth_packet.startswith("RSA_AUTH:"))
        
        # Process valid auth packet
        is_valid, extracted_dh = RSA_Main.process_rsa_auth_packet(auth_packet, public_key)
        self.assertTrue(is_valid)
        self.assertEqual(extracted_dh, dh_packet)
        
        # Process tampered packet
        tampered_auth = auth_packet.replace("789", "999")
        is_invalid, _ = RSA_Main.process_rsa_auth_packet(tampered_auth, public_key)
        self.assertFalse(is_invalid)

if __name__ == "__main__":
    unittest.main()
