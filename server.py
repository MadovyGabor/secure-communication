"""Chat server: authenticates clients, answers the Diffie-Hellman handshake and relays encrypted chat.

Clients are shown in the chat by username ("[Alice]: hi"), never by their TCP port. The username
arrives in the first encrypted frame after the key exchange; a client without a usable name gets
a sequential "Anonymous#N".
"""
import socket

import networkstack
import protocol
from diffieHellman import DHNetwork
from networkservice import NetworkService
from RSA import RSA_Main

class Server(NetworkService):
    """Chat server: keeps RSA and AES keys per client and forwards each message to the other clients."""

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

        # naming: port -> username; ports whose next encrypted frame should be a NAME packet
        self.client_names = {}
        self.awaiting_name = set()
        self.anonymous_count = 0
        self.my_rsa_pub, self.my_rsa_priv = RSA_Main.load_or_create_keys("server_key.json")

        print(f"[Server] Started listening on port {port}")

    def forget_client(self, port):
        # a later client reusing the port must not inherit keys of the previous one
        self.client_aes_keys.pop(port, None)
        self.client_raw_dh_secrets.pop(port, None)
        self.client_rsa_keys.pop(port, None)
        self.client_names.pop(port, None)
        self.awaiting_name.discard(port)

    def loop(self):
        while True:
            self.server_socket.process(self.receive_handler)

    def receive_handler(self, sender, data: bytes):
        try:
            self.handle_packet(sender, data)
        except Exception as e:
            print(f"[Server] Error: dropping malformed packet from client {sender.port}: {e}")

    def handle_packet(self, sender, data: bytes):
        message = protocol.decode_text(data)

        # 1. Incoming Client RSA Key
        if message is not None and message.startswith(protocol.RSA_INIT):
            client_pub = RSA_Main.process_rsa_init_packet(message)
            self.client_rsa_keys[sender.port] = client_pub

            packet = RSA_Main.build_rsa_init_packet(self.my_rsa_pub)
            sender.send(packet.encode("utf-8"))
            return

        # 2. authenticated Client Messages
        if message is not None and message.startswith(protocol.RSA_AUTH):
            client_pub = self.client_rsa_keys.get(sender.port)
            if not client_pub:
                print("[Server] Error: Client has not exchanged RSA keys yet.")
                return

            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, client_pub)
            if not is_valid:
                print("[Security] HACKER DETECTED! Signature invalid. Dropping packet.")
                return

            # If authentic
            if inner_message.startswith(protocol.DH_INIT):
                self.respond_to_dh_init(sender, inner_message, sign=True)
                return

            print("[Server] Error: unsupported authenticated message.")
            return

        # 2.5 Unauthenticated Client Messages
        if message is not None and message.startswith(protocol.DH_INIT):
            if self.secure:
                print("[Security] HACKER DETECTED! Dropping unauthenticated packet.")
                return

            self.respond_to_dh_init(sender, message, sign=False)
            return
        
        # 3. encrypted client messages
        if(sender.port not in self.client_aes_keys):
            sender.send("Type 'rsa' and then 'dh' to start communicating securely".encode("utf-8"))
            return
        
        # decrypt the incoming message
        try:
            plaintext = self.decrypt_and_decode(data, self.client_aes_keys[sender.port])
        except Exception as e:
            print(f"[Security] Decryption failed: {e}")
            return

        # the first frame after a key exchange names the client
        if sender.port in self.awaiting_name:
            self.awaiting_name.discard(sender.port)
            if plaintext.startswith(protocol.NAME):
                self.assign_name(sender, protocol.parse_name(plaintext))
                return
        if sender.port not in self.client_names:
            self.assign_name(sender, None)  # client sent chat without introducing itself

        name = self.client_names[sender.port]
        print(f"[Message from {name}]: {plaintext}")
        out = f"[{name}]: {plaintext}".encode("utf-8")

        for client_port in self.server_socket.clients:
            if (client_port != sender.port and client_port in self.client_aes_keys):
                client_socket = self.server_socket.clients[client_port]
                client_aes_key = self.client_aes_keys[client_port]
        
                self.send_encrypted_to_client(client_socket, out, client_aes_key)
    
    def assign_name(self, sender, requested):
        """Store the client's username (or a fresh Anonymous#N) and tell the client which one it got."""
        name = self.client_names.get(sender.port)
        notice = None
        if name is None:
            taken = {n.lower() for n in self.client_names.values()}
            if requested is not None and requested.lower() in taken:
                notice = f"The name '{requested}' is already taken."
                requested = None
            if requested is None:
                self.anonymous_count += 1
                requested = f"{protocol.ANONYMOUS_PREFIX}{self.anonymous_count}"
            name = self.client_names[sender.port] = requested
            print(f"[Server] Client joined the chat as {name}")

        # a client that re-keys keeps the name it already has
        text = f"[Server]: {notice + ' ' if notice else ''}You are chatting as {name}."
        self.send_encrypted_to_client(sender, text.encode("utf-8"), self.client_aes_keys[sender.port])

    def respond_to_dh_init(self, sender, dh_init: str, sign: bool):
        dh_reply_packet, raw_dh_secret, aes_session_key = DHNetwork.process_init_packet(dh_init)
        self.client_raw_dh_secrets[sender.port] = raw_dh_secret
        self.client_aes_keys[sender.port] = aes_session_key
        self.awaiting_name.add(sender.port)

        if sign:
            dh_reply_packet = RSA_Main.build_rsa_auth_packet(dh_reply_packet, self.my_rsa_priv)
        sender.send(dh_reply_packet.encode("utf-8"))

        print(f"[DH Protocol] Raw DH Secret: {str(raw_dh_secret)[:15]}...")
        print(f"[DH Protocol] AES Session Key Derived: {aes_session_key.hex()[:15]}...")

    # helper function for encrypting data and sending it to a client
    def send_encrypted_to_client(self, client_socket, data: bytes, secret: bytes, handler = None, handler_args = ()):
        # argument type and key length checks before encrypting
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
