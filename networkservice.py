from diffieHellman import DHNetwork
from diffieHellman import DHLogic
from RSA import RSA_Main
from RSA import RSA_Math as RSA_Logic
from GCM.GCM import aes_gcm_encrypt, aes_gcm_decrypt
import socket, threading, time, os
from abc import ABC, abstractmethod

import networkstack

class NetworkService(ABC):
    def __init__(self, host : str, port : int):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @abstractmethod
    def loop(self):
        pass

    def decrypt_payload(self, encrypted_data, secret):
        packet = encrypted_data[4:]
        nonce = packet[:12]
        tag = packet[12:28]
        ciphertext = packet[28:]
        return aes_gcm_decrypt(nonce, secret, ciphertext, tag)

    def encrypt_payload(self, plaintext_bytes, secret):
        nonce = os.urandom(12)
        ciphertext, tag = aes_gcm_encrypt(nonce, secret, plaintext_bytes)
        packet = nonce + tag + ciphertext
        length = len(packet).to_bytes(4, 'big')
        return length + packet

    # helper function for decrypting and decoding received data
    def decrypt_and_decode(self, encrypted_data, secret):
        decrypted_data = self.decrypt_payload(encrypted_data, secret)
        return decrypted_data.decode("utf-8", errors="ignore")


    @abstractmethod
    def shutdown(self):
        pass

class Client(NetworkService):
    def __init__(self, host : str, port : int, instance : str = "default", secure=False):
        super().__init__(host, port)
        self.secure = secure
        self.instance = instance
        self.socket.connect((self.host, self.port))
        self.client_socket = networkstack.ClientSocket(self.socket)

        # --- DH parameters ---
        self.p = None
        self.g = None
        self.private_key = None
        self.raw_dh_secret = None
        self.aes_session_key = None

        # --- RSA parameters ---
        self.peer_rsa_pub = None
        self.my_rsa_priv = None

        self.lock = threading.Lock()
        self.network_thread = threading.Thread(target = self.network_loop)
        self.network_thread.start()

    def loop(self):
        print("\n[Client] Napište 'help' pro seznam příkazů.")
        while self.network_thread.is_alive():
            input_ = input()

            if input_ == "help":
                print("\n[Client] Dostupné příkazy:")
                print("  rsa    - Započne výměnu RSA veřejných klíčů se serverem (autentizace).")
                print("  dh     - Zahájí Diffie-Hellman výměnu klíčů pro šifrování (AES-GCM).")
                print("  exit   - Ukončí připojení a vypne klienta.")
                print("  help   - Zobrazí tuto nápovědu.")
                print("  <text> - Jakýkoliv jiný text bude odeslán jako zpráva do chatu.\n")
                continue

            if input_ == "exit":
                with self.lock:
                    self.client_socket.shutdown()
                return

            elif input_ == "rsa":
                if not self.secure:
                    print("[Client] Error: Insecure mode. Run 'dh' directly.")
                    continue
                # RSA handshake!
                try:
                    packet, self.my_rsa_priv = RSA_Main.build_rsa_init_packet(self.instance + "_client_key.json")
                except ValueError as e:
                    print(f"[Client] Error: {e}")
                    continue
                if self.network_thread.is_alive():
                    self.send(packet.encode("utf-8"))

            elif input_ == "dh":
                if self.secure and (not self.my_rsa_priv or not self.peer_rsa_pub):
                    print("[Client] Error: You must run 'rsa' to exchange keys first!")
                    continue

                dh_packet, self.p, self.g, self.private_key = DHNetwork.build_init_packet()

                if self.secure:
                    auth_packet = RSA_Main.build_rsa_auth_packet(dh_packet, self.my_rsa_priv)
                    if self.network_thread.is_alive():
                        self.send(auth_packet.encode("utf-8"))
                else:
                    if self.network_thread.is_alive():
                        self.send(dh_packet.encode("utf-8"))

            else:
                if(self.network_thread.is_alive()):
                    self.send_chat(input_)

    def send_chat(self, text : str):
        encoded_message = text.encode("utf-8")

        if(self.aes_session_key is not None):
            self.send_encrypted_to_server(encoded_message, self.aes_session_key)
        elif(self.secure):
            print("[Client] Error: No session key yet. Run 'rsa' and 'dh' before chatting in secure mode.")
        else:
            print("[Client] Sending unencrypted message...")
            self.send(encoded_message)

    def network_loop(self):
        while self.client_socket.socket is not None:
            with self.lock:
                if self.client_socket.socket is None:
                    return
                try:
                    connected = self.client_socket.process(self.receive_handler, timeout=0.1)
                except OSError:
                    connected = False
            if(not connected):
                self.client_socket.shutdown()
                print("[Client] Server connection lost.")
                return

            time.sleep(0.01) # let the input thread take the lock

    def send(self, data):
        self.client_socket.send(data)

    def send_encrypted_to_server(self, data, aes_session_key):
        packet = self.encrypt_payload(data, aes_session_key)
        self.send(packet)

    def receive_handler(self, sender_socket, data : bytes):
        try:
            self.handle_packet(data)
        except Exception as e:
            print(f"[Client] Error: dropping malformed packet from server: {e}")

    def handle_packet(self, data : bytes):
        try:
            message = data.decode("utf-8")
        except UnicodeDecodeError:
            message = None

        if message is not None and message.startswith("RSA_INIT:"):
            saved_public, _ = RSA_Logic.load_keys_from_json(self.instance + "_server_key.json")
            received_public = RSA_Main.process_rsa_init_packet(message)
            if(saved_public is not None):
                if(saved_public != received_public):
                    print("[Security] WARNING: Received and saved server public keys do not match! An attacker might be involved...")
                    return
            
            self.peer_rsa_pub = received_public
            RSA_Logic.save_keys_to_json(self.peer_rsa_pub, tuple([None, None]), self.instance + "_server_key.json")
            print("[RSA Protocol] SUCCESS: Exchanged RSA Public Keys with the Server!")
            return

        authenticated = False
        if message is not None and message.startswith("RSA_AUTH:"):
            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, self.peer_rsa_pub)
            if not is_valid:
                print("[Security] HACKER DETECTED! Signature invalid. Dropping packet.")
                return

            message = inner_message
            authenticated = True

        if message is not None and message.startswith("DH_ACCEPT:"):
            if self.secure and not authenticated:
                print("[Security] HACKER DETECTED! Unsigned DH_ACCEPT in secure mode. Dropping packet.")
                return
            if self.p is None or self.private_key is None:
                print("[Security] Ignoring DH_ACCEPT: no Diffie-Hellman exchange in progress.")
                return
            self.raw_dh_secret, self.aes_session_key = DHNetwork.process_accept_packet(message, self.p, self.private_key)
            self.private_key = None
            print(f"[DH Protocol] Raw DH Secret: {str(self.raw_dh_secret)[:15]}...")
            print(f"[DH Protocol] AES Session Key Derived: {self.aes_session_key.hex()[:15]}...")
            return

        # received encrypted message
        if(self.aes_session_key is not None):
            try:
                decrypted_message = self.decrypt_and_decode(data, self.aes_session_key)
            except ValueError as e:
                print(f"[Security] Decryption failed: {e}")
                return
            print(f"[Message from Server]: {decrypted_message}")
        else:
            print("[Warning] Received unencrypted message!")
            print(f"[Message from Server]: {message}")

    def shutdown(self):
        self.client_socket.shutdown()

class Server(NetworkService):
    def __init__(self, host : str, port : int, secure=False):
        super().__init__(host, port)
        self.secure = secure
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.listen(1)
        
        self.server_socket = networkstack.ServerSocket(self.socket, on_disconnect=self.forget_client)

        #DH handling: port -> keys
        self.client_aes_keys = {}
        self.client_raw_dh_secrets = {}

        # RSA handling
        self.client_rsa_keys = {}
        # Load server's keys
        _, self.my_rsa_priv = RSA_Main.build_rsa_init_packet("server_key.json")

        print(f"[Server] Started listening on port {port}")

    def forget_client(self, port):
        # a later client reusing the port must not inherit keys of the previous one
        self.client_aes_keys.pop(port, None)
        self.client_raw_dh_secrets.pop(port, None)
        self.client_rsa_keys.pop(port, None)

    def loop(self):
        while True:
            self.server_socket.process(self.receive_handler)

    def receive_handler(self, sender, data: bytes):
        try:
            self.handle_packet(sender, data)
        except Exception as e:
            print(f"[Server] Error: dropping malformed packet from client {sender.port}: {e}")

    def handle_packet(self, sender, data: bytes):
        try:
            message = data.decode("utf-8")
        except UnicodeDecodeError:
            message = None

        # 1. Incoming Client RSA Key
        if message is not None and message.startswith("RSA_INIT:"):
            client_pub = RSA_Main.process_rsa_init_packet(message)
            self.client_rsa_keys[sender.port] = client_pub

            packet, _ = RSA_Main.build_rsa_init_packet("server_key.json")
            sender.send(packet.encode("utf-8"))
            return

        # 2. authenticated Client Messages
        if message is not None and message.startswith("RSA_AUTH:"):
            client_pub = self.client_rsa_keys.get(sender.port)
            if not client_pub:
                print("[Server] Error: Client has not exchanged RSA keys yet.")
                return

            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, client_pub)
            if not is_valid:
                print("[Security] HACKER DETECTED! Signature invalid. Dropping packet.")
                return

            # If authentic
            if inner_message.startswith("DH_INIT:"):
                dh_reply_packet, raw_dh_secret, aes_session_key = DHNetwork.process_init_packet(inner_message)
                self.client_raw_dh_secrets[sender.port] = raw_dh_secret
                self.client_aes_keys[sender.port] = aes_session_key

                auth_reply = RSA_Main.build_rsa_auth_packet(dh_reply_packet, self.my_rsa_priv)
                sender.send(auth_reply.encode("utf-8"))

                print(f"[DH Protocol] Raw DH Secret: {str(raw_dh_secret)[:15]}...")
                print(f"[DH Protocol] AES Session Key Derived: {aes_session_key.hex()[:15]}...")
                return

            print("[Server] Error: unsupported authenticated message.")
            return

        # 2.5 Unauthenticated Client Messages
        if message is not None and message.startswith("DH_INIT:"):
            if self.secure:
                print("[Security] HACKER DETECTED! Dropping unauthenticated packet.")
                return

            dh_reply_packet, raw_dh_secret, aes_session_key = DHNetwork.process_init_packet(message)
            self.client_raw_dh_secrets[sender.port] = raw_dh_secret
            self.client_aes_keys[sender.port] = aes_session_key

            sender.send(dh_reply_packet.encode("utf-8"))

            print(f"[DH Protocol] Raw DH Secret: {str(raw_dh_secret)[:15]}...")
            print(f"[DH Protocol] AES Session Key Derived: {aes_session_key.hex()[:15]}...")
            return
        
        # 3. encrypted client messages
        if(sender.port not in self.client_aes_keys):
            sender.send("Type 'rsa' and then 'dh' to start communicating securely".encode("utf-8"))
            return
        
        # decrypt incoming správu
        try:
            plaintext = self.decrypt_and_decode(data, self.client_aes_keys[sender.port])
            print(f"[Message from Client {sender.port}]: {plaintext}")
        except Exception as e:
            print(f"[Security] Decryption failed: {e}")
            return
        
        out = "{}: {}".format(sender.port, plaintext).encode("utf-8")

        for client_port in self.server_socket.clients:
            if (client_port != sender.port and client_port in self.client_aes_keys):
                client_socket = self.server_socket.clients[client_port]
                client_aes_key = self.client_aes_keys[client_port]
        
                self.send_encrypted_to_client(client_socket, out, client_aes_key)
    
    # helper function for encrypting data and sending it to a client
    def send_encrypted_to_client(self, client_socket, data: bytes, secret: bytes, handler = None, handler_args = ()):
        # AES-GCM
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")

        if not isinstance(secret, bytes):
            raise TypeError("key must be bytes")

        if len(secret) not in (16, 24, 32):
            raise ValueError("Invalid AES key length")

        packet = self.encrypt_payload(data, secret)
        client_socket.send(packet)
    
    def shutdown(self):
        self.server_socket.shutdown()

class Attacker(NetworkService):
    def __init__(self, host, port, secure=False):
        # Target server
        self.target_host = host
        self.target_port = port
        
        # We listen on target_port + 1
        self.proxy_port = port + 1
        super().__init__('127.0.0.1', self.proxy_port)
        
        self.mitm_active = False
        self.spoof_active = False
        self.tamper_text = None
        self.secure = secure
        
        # Map: RealClientPort -> { 'server_socket': ClientSocket, 'client_socket': ClientSocket }
        self.relays = {}
        
        # Setup proxy server socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', self.proxy_port))
        self.socket.listen(5)
        self.server_stack = networkstack.ServerSocket(self.socket, on_disconnect=self.victim_disconnected)
        
        print(f"\n[MITM] Attacker Proxy started on 127.0.0.1:{self.proxy_port}")
        print(f"[MITM] Relaying traffic to {host}:{port}")
        print("[MITM] Napište 'help' pro seznam příkazů.\n")

    def loop(self):
        # Start proxy processing in a background thread
        threading.Thread(target=self.proxy_thread, daemon=True).start()
        
        # Main thread handles CLI commands
        while True:
            try:
                cmd = input()
                if cmd == "help":
                    print("\n[MITM] Dostupné příkazy:")
                    print("  attack        - Zapne/vypne aktivní MITM útok (podvržení DH klíčů).")
                    print("  tamper <text> - Nahradí obsah další zachycené dešifrované zprávy zadaným textem.")
                    print("  spoof         - Zapne/vypne generování falešných zpráv oběma stranám.")
                    print("  exit          - Ukončí proxy server a odpojí klienty.")
                    print("  help          - Zobrazí tuto nápovědu.\n")
                elif cmd == "attack":
                    self.mitm_active = not self.mitm_active
                    print(f"MITM Attack Mode: {'ENABLED' if self.mitm_active else 'DISABLED'}")
                elif cmd == "spoof":
                    self.spoof_active = not self.spoof_active
                    print(f"Spoofing Mode: {'ENABLED' if self.spoof_active else 'DISABLED'}")
                elif cmd.startswith("tamper "):
                    self.tamper_text = cmd[7:]
                    print(f"Next intercepted message will be replaced with: '{self.tamper_text}'")
                elif cmd == "exit":
                    print("Shutting down attacker proxy...")
                    break
            except EOFError:
                break

    def proxy_thread(self):
        while True:
            try:
                self.process_once()
            except Exception:
                pass
            time.sleep(0.01)

    def process_once(self):
        # 1. Accept and process data from Clients connecting to the proxy
        self.server_stack.process(self.receive_from_client, timeout=0)

        # 2. Process data coming from the Real Server back to the proxy
        disconnected_ports = []
        for port, relay in self.relays.items():
            if not relay['server_socket'].process(self.receive_from_server, (relay['client_socket'],), timeout=0):
                disconnected_ports.append(port)

        for port in disconnected_ports:
            print(f"[MITM] Relay for client port {port} disconnected.")
            self.drop_relay(port)

    def victim_disconnected(self, port):
        if port in self.relays:
            print(f"[MITM] Client {port} disconnected, closing its relay.")
            self.drop_relay(port)

    def drop_relay(self, port):
        relay = self.relays.pop(port, None)
        if relay is not None:
            relay['server_socket'].shutdown()

    def receive_from_client(self, client_socket, data):
        # Data from REAL CLIENT -> PROXY
        port = client_socket.port
        if port not in self.relays:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.target_host, self.target_port))
                server_sock = networkstack.ClientSocket(s)
                self.relays[port] = {
                    'client_socket': client_socket,
                    'server_socket': server_sock,
                    'mitm_state': {
                        'k_client': None,
                        'k_server': None,
                        'p': None,
                        'attacker_priv': None,
                        'attacker_pub': None
                    }
                }
                print(f"[MITM] New relay established for client {port}")
            except Exception as e:
                print(f"[MITM] Failed to connect to target server: {e}")
                return

        tampered = self.intercept(data, "CLIENT -> SERVER", port)
        self.relays[port]['server_socket'].send(tampered)

    def receive_from_server(self, real_client_socket, server_socket, data):
        # From REAL SERVER -> PROXY
        port = real_client_socket.port
        tampered = self.intercept(data, "SERVER -> CLIENT", port)
        real_client_socket.send(tampered)

    def intercept(self, data, direction, port):
        # Logging raw data
        hex_data = data.hex()
        print(f"[MITM INTERCEPT {direction}] Data: {hex_data[:30]}{'...' if len(hex_data) > 30 else ''}")
        
        state = self.relays[port]['mitm_state']

        if self.spoof_active:
            if "CLIENT -> SERVER" in direction:
                print("[MITM] Spoofing message to server.")
                if state['k_server']:
                    return self.encrypt_payload(b"i totally sent this lol", state['k_server'])
                return b"i totally sent this lol"
            else:
                print("[MITM] Spoofing message to client.")
                if state['k_client']:
                    return self.encrypt_payload(b"you totally received this", state['k_client'])
                return b"you totally received this"

        # 1. Plaintext Handshake Tampering
        if self.mitm_active:
            try:
                msg = data.decode("utf-8")
                
                if "DH_INIT:" in msg and "CLIENT -> SERVER" in direction:
                    print("[MITM] Intercepted DH_INIT! Deriving keys and injecting MITM public key...")
                    parts = msg.split("DH_INIT:")
                    dh_string = parts[1]
                    
                    signature_part = ""
                    if "|" in dh_string:
                        dh_core, signature_part = dh_string.split("|", 1)
                        signature_part = "|" + signature_part
                    else:
                        dh_core = dh_string
                        
                    dh_parts = dh_core.split(":")
                    if len(dh_parts) >= 3:
                        p = int(dh_parts[0])
                        g = int(dh_parts[1])
                        client_pub = int(dh_parts[2])
                        
                        state['p'] = p
                        state['attacker_priv'] = DHLogic.generate_private_key(p)
                        state['attacker_pub'] = DHLogic.generate_public_key(state['attacker_priv'], g, p)
                        
                        raw_k_client = DHLogic.generate_shared_secret(state['attacker_priv'], client_pub, p)
                        state['k_client'] = DHLogic.derive_aes_key(raw_k_client)
                        
                        dh_parts[2] = str(state['attacker_pub'])
                        new_dh_core = ":".join(dh_parts)
                        parts[1] = new_dh_core + signature_part
                        fake_msg = "DH_INIT:".join(parts)
                        return fake_msg.encode("utf-8")

                elif "DH_ACCEPT:" in msg and "SERVER -> CLIENT" in direction:
                    print("[MITM] Intercepted DH_ACCEPT! Deriving keys and injecting MITM public key...")
                    parts = msg.split("DH_ACCEPT:")
                    dh_string = parts[1]
                    
                    signature_part = ""
                    if "|" in dh_string:
                        dh_core, signature_part = dh_string.split("|", 1)
                        signature_part = "|" + signature_part
                    else:
                        dh_core = dh_string
                        
                    dh_parts = dh_core.split(":")
                    if len(dh_parts) >= 1 and state['p'] is not None:
                        server_pub = int(dh_parts[0])
                        
                        raw_k_server = DHLogic.generate_shared_secret(state['attacker_priv'], server_pub, state['p'])
                        state['k_server'] = DHLogic.derive_aes_key(raw_k_server)
                        
                        dh_parts[0] = str(state['attacker_pub'])
                        new_dh_core = ":".join(dh_parts)
                        parts[1] = new_dh_core + signature_part
                        fake_msg = "DH_ACCEPT:".join(parts)
                        
                        print(f"[MITM] K_client derived: {state['k_client'].hex()[:15]}...")
                        print(f"[MITM] K_server derived: {state['k_server'].hex()[:15]}...")
                        return fake_msg.encode("utf-8")
                        
            except Exception:
                pass

        # 2. Encrypted Message Translation
        if self.mitm_active and state['k_client'] and state['k_server']:
            try:
                if "CLIENT -> SERVER" in direction:
                    plaintext = self.decrypt_payload(data, state['k_client'])
                    print(f"[MITM] Extracted Plaintext: {plaintext.decode('utf-8', errors='ignore')}")
                    
                    if self.tamper_text:
                        print(f"[MITM] TAMPERING MESSAGE! Replacing with '{self.tamper_text}'")
                        plaintext = self.tamper_text.encode("utf-8")
                        self.tamper_text = None
                        
                    return self.encrypt_payload(plaintext, state['k_server'])
                elif "SERVER -> CLIENT" in direction:
                    plaintext = self.decrypt_payload(data, state['k_server'])
                    print(f"[MITM] Extracted Plaintext: {plaintext.decode('utf-8', errors='ignore')}")
                    
                    if self.tamper_text:
                        print(f"[MITM] TAMPERING MESSAGE! Replacing with '{self.tamper_text}'")
                        plaintext = self.tamper_text.encode("utf-8")
                        self.tamper_text = None
                        
                    return self.encrypt_payload(plaintext, state['k_client'])
            except Exception:
                pass

        return data

    def shutdown(self):
        for port in self.relays:
            self.relays[port]['server_socket'].shutdown()
        self.server_stack.shutdown()