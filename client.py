"""Chat client: RSA key exchange, Diffie-Hellman handshake and AES-GCM encrypted chat."""
import threading
import time

import networkstack
import protocol
from diffieHellman import DHNetwork
from networkservice import NetworkService
from RSA import RSA_Main
from RSA import RSA_Math as RSA_Logic

class Client(NetworkService):
    """Interactive chat client: reads commands from stdin and talks to the server on a network thread."""

    def __init__(self, host : str, port : int, name : str = None, secure=False):
        # the username is shown in the chat and names the key files; None = let the server pick
        # an Anonymous#N name and use the "default" key files. Checked before any socket is opened.
        self.name = None
        if name is not None:
            self.name = protocol.normalize_name(name)
            if self.name is None:
                raise ValueError(f"invalid username {name!r} (1-{protocol.MAX_NAME_LENGTH} letters, digits, '_' or '-')")
        self.instance = self.name or "default"

        super().__init__(host, port)
        self.secure = secure
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
        print("\n[Client] Type 'help' for a list of commands.")
        while self.network_thread.is_alive():
            input_ = input()

            if input_ == "help":
                print("\n[Client] Available commands:")
                print("  rsa    - Exchange RSA public keys with the server (authentication).")
                print("  dh     - Run the Diffie-Hellman key exchange for encryption (AES-GCM).")
                print("  exit   - Close the connection and quit the client.")
                print("  help   - Show this help.")
                print("  <text> - Any other text is sent as a chat message.\n")
                continue

            if input_ == "exit":
                with self.lock:
                    self.client_socket.shutdown()
                return

            elif input_ == "rsa":
                if not self.secure:
                    print("[Client] Error: Insecure mode. Run 'dh' directly.")
                    continue
                try:
                    my_rsa_pub, self.my_rsa_priv = RSA_Main.load_or_create_keys(self.instance + "_client_key.json")
                    packet = RSA_Main.build_rsa_init_packet(my_rsa_pub)
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
        message = protocol.decode_text(data)

        if message is not None and message.startswith(protocol.RSA_INIT):
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
        if message is not None and message.startswith(protocol.RSA_AUTH):
            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, self.peer_rsa_pub)
            if not is_valid:
                print("[Security] HACKER DETECTED! Signature invalid. Dropping packet.")
                return

            message = inner_message
            authenticated = True

        if message is not None and message.startswith(protocol.DH_ACCEPT):
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
            # introduce ourselves; the name travels encrypted, never in the plaintext handshake
            self.send_encrypted_to_server(protocol.build_name(self.name).encode("utf-8"), self.aes_session_key)
            return

        # chat message: decrypted once a session key exists, otherwise shown as plaintext
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
