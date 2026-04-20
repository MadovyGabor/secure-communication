import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from diffieHellman import DHLogic
from diffieHellman import DHNetwork
from RSA import RSA_Main
from RSA import RSA_Math

print("--- Testing DH Robustness ---")

print("\n[Setup] Generating RSA keys for Alice and Bob...")
alice_rsa_pub, alice_rsa_priv = RSA_Math.generate_rsa_parameters(1024)
bob_rsa_pub, bob_rsa_priv = RSA_Math.generate_rsa_parameters(1024)

print("\n--- Test 1: Successful Handshake ---")
try:
    # Initiator (Alice)
    raw_init, p, g, alice_dh_priv = DHNetwork.build_init_packet()
    signed_init = RSA_Main.build_rsa_auth_packet(raw_init, alice_rsa_priv)
    
    # Responder (Bob)
    is_valid, inner_init = RSA_Main.process_rsa_auth_packet(signed_init, alice_rsa_pub)
    if not is_valid: raise Exception("Bob rejected Alice's signature")
    raw_accept, bob_aes_key = DHNetwork.process_init_packet(inner_init)
    signed_accept = RSA_Main.build_rsa_auth_packet(raw_accept, bob_rsa_priv)
    
    # Initiator (Alice)
    is_valid, inner_accept = RSA_Main.process_rsa_auth_packet(signed_accept, bob_rsa_pub)
    if not is_valid: raise Exception("Alice rejected Bob's signature")
    alice_aes_key = DHNetwork.process_accept_packet(inner_accept, p, alice_dh_priv)
    
    if alice_aes_key == bob_aes_key:
        print(f"[SUCCESS] Handshake complete. Both derived AES keys match!")
    else:
        print("[FAIL] AES keys do not match!")
except Exception as e:
    print(f"[FAIL] Unexpected error: {e}")

print("\n--- Test 2: MitM Attack Simulation ---")
try:
    raw_init, p, g, alice_dh_priv = DHNetwork.build_init_packet()
    signed_init = RSA_Main.build_rsa_auth_packet(raw_init, alice_rsa_priv)
    
    parts = signed_init.split("|")
    payload = parts[0]
    signature = parts[1]
    
    dh_parts = payload.split(":")
    dh_parts[3] = str(int(dh_parts[3]) + 1)
    modified_payload = ":".join(dh_parts)
    
    malicious_packet = f"{modified_payload}|{signature}"
    
    is_valid, _ = RSA_Main.process_rsa_auth_packet(malicious_packet, alice_rsa_pub)
    if not is_valid:
        print(f"[SUCCESS] Caught invalid signature/MitM attack.")
    else:
        print("[FAIL] MitM attack succeeded (should have been caught!)")
except Exception as e:
    print(f"[FAIL] Error in Test 2: {e}")
    
print("\n--- Test 3: Invalid Public Key Simulation ---")
try:
    p, g = DHLogic.get_dh_parameters()
    malicious_dh_payload = f"DH_INIT:{p}:{g}:1"
    
    print("[Test] Attempting to process packet with weak DH key (1)...")
    DHNetwork.process_init_packet(malicious_dh_payload)
    print("[FAIL] Weak key accepted (should have been caught!)")
except ValueError as e:
    print(f"[SUCCESS] Caught invalid DH public key: {e}")

print("\n--- Tests Completed ---")
