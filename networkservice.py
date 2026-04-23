from diffieHellman import DHNetwork
from RSA import RSA_Main
from RSA import RSA_Math as RSA_Logic
from GCM.GCM import aes_gcm_encrypt, aes_gcm_decrypt
import socket, threading, time, os
from abc import abstractmethod

import networkstack

class NetworkService():
    def __init__(self, host : str, port : int):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @abstractmethod
    def loop(self):
        pass

    # helper function for decrypting and decoding received data
    @staticmethod
    def decrypt_and_decode(encrypted_data, secret):
        length = int.from_bytes(encrypted_data[:4], 'big')
        packet = encrypted_data[4:]

        nonce = packet[:12]
        tag = packet[12:28]
        ciphertext = packet[28:]

        decrypted_data = aes_gcm_decrypt(nonce, secret, ciphertext, tag)
        return decrypted_data.decode("utf-8", errors="ignore")


    @abstractmethod
    def shutdown(self):
        pass

class Client(NetworkService):
    def __init__(self, host : str, port : int, instance : str = "default", attack_send_handler = None, attack_recv_handler = None):
        super().__init__(host, port)
        self.instance = instance
        self.socket.connect((self.host, self.port))
        self.client_socket = networkstack.ClientSocket(self.socket)

        self.attack_send_handler = attack_send_handler
        self.attack_recv_handler = attack_recv_handler

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
        while self.network_thread.is_alive():
            input_ = input()

            if input_ == "exit":
                self.lock.acquire()
                self.client_socket.shutdown()
                self.lock.release()
                return

            elif input_ == "rsa":
                # RSA handshake!
                packet, self.my_rsa_priv = RSA_Main.build_rsa_init_packet(self.instance + "_client_key.json")
                if self.network_thread.is_alive():
                    self.send(packet.encode("utf-8"))

            elif input_ == "dh":
                if not self.my_rsa_priv or not self.peer_rsa_pub:
                    print("Error: You must run 'rsa' to exchange keys first!")
                    continue

                dh_packet, self.p, self.g, self.private_key = DHNetwork.build_init_packet()

                auth_packet = RSA_Main.build_rsa_auth_packet(dh_packet, self.my_rsa_priv)

                if self.network_thread.is_alive():
                    self.send(auth_packet.encode("utf-8"))

            else:
                if(self.network_thread.is_alive()):
                    encoded_message = input_.encode("utf-8")
                    
                    if(self.aes_session_key is not None):
                        self.send_encrypted_to_server(encoded_message, self.aes_session_key)
                    else:
                        print("sending unencrypted message")
                        self.send(encoded_message)  
    
    def network_loop(self):
        while self.client_socket.socket is not None:
            self.lock.acquire()
            connected = self.client_socket.process(self.recv)
            self.lock.release()
            if(not connected):
                self.client_socket.shutdown()
                print("server shut down")
                return

            time.sleep(0.1)

    def send(self, data):
        if(self.attack_send_handler is None):
            self.client_socket.send(data)
        else:
            self.attack_send_handler(self.client_socket, self.receive_handler, data)

    def send_encrypted_to_server(self, data, aes_session_key):
        nonce = os.urandom(12)
        ciphertext, tag = aes_gcm_encrypt(nonce, aes_session_key, data)

        packet = nonce + tag + ciphertext
        length = len(packet).to_bytes(4, 'big')

        self.send(length + packet)

    def recv(self, sender_socket, data : bytes):
        if(self.attack_recv_handler is None):
            self.receive_handler(sender_socket, data)
        else:
            self.attack_recv_handler(self.client_socket, self.receive_handler, data)

    def receive_handler(self, sender_socket, data : bytes):
        try:
            message = data.decode("utf-8")
        except:
            message = None

        if message is not None and message.startswith("RSA_INIT:"):
            saved_public, _ = RSA_Logic.load_keys_from_json(self.instance + "_server_key.json")
            received_public = RSA_Main.process_rsa_init_packet(message)
            if(saved_public is not None):
                if(saved_public != received_public):
                    print("Received and saved server public keys do not match! An attacker might be involved....")
                    return
            
            self.peer_rsa_pub = received_public
            RSA_Logic.save_keys_to_json(self.peer_rsa_pub, tuple([None, None]), self.instance + "_server_key.json")
            print("SUCCESS: Exchanged RSA Public Keys with the Server!")
            return

        if message is not None and message.startswith("RSA_AUTH:"):
            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, self.peer_rsa_pub)
            if not is_valid:
                print("HACKER DETECTED! Dropping packet.")
                return

            message = inner_message

        if message is not None and message.startswith("DH_ACCEPT:"):
            self.raw_dh_secret, self.aes_session_key = DHNetwork.process_accept_packet(message, self.p, self.private_key)
            print(f"raw DH secret: {str(self.raw_dh_secret)[:15]}...")
            return

        # received encrypted message
        if(self.aes_session_key is not None):
            decrypted_message = self.decrypt_and_decode(data, self.aes_session_key)
            print(decrypted_message)
        else:
            print("Received unencrypted message!")
            print(message)

    def shutdown(self):
        self.client_socket.shutdown()

class Server(NetworkService):
    def __init__(self, host : str, port : int):
        super().__init__(host, port)
        self.socket.bind((host, port))
        self.socket.listen(1)
        
        self.server_socket = networkstack.ServerSocket(self.socket)

        #DH handling: port -> keys
        self.client_aes_keys = {}
        self.client_raw_dh_secrets = {}

        # RSA handling
        self.client_rsa_keys = {}
        # Load server's keys
        _, self.my_rsa_priv = RSA_Main.build_rsa_init_packet("server_key.json")

        print("server started")

    def loop(self):
        while True:
            self.server_socket.process(self.receive_handler)

    def receive_handler(self, sender, data: bytes):
        try:
            message = data.decode("utf-8")
        except:
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
                print("Error: Client has not exchanged RSA keys yet.")
                return

            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, client_pub)
            if not is_valid:
                print("HACKER DETECTED! Dropping packet.")
                return

            # If authentic
            if inner_message.startswith("DH_INIT:"):
                dh_reply_packet, raw_dh_secret, aes_session_key = DHNetwork.process_init_packet(inner_message)
                self.client_raw_dh_secrets[sender.port] = raw_dh_secret
                self.client_aes_keys[sender.port] = aes_session_key

                auth_reply = RSA_Main.build_rsa_auth_packet(dh_reply_packet, self.my_rsa_priv)
                sender.send(auth_reply.encode("utf-8"))

                print(f"raw DH secret: {str(raw_dh_secret)[:15]}...")
                return
        
        # 3. encrypted client messages
        if(sender.port not in self.client_aes_keys):
            sender.send("Type 'rsa' and then 'dh' to start communicating securely".encode("utf-8"))
            return
        
        # decrypt incoming správu
        try:
            plaintext = self.decrypt_and_decode(data, self.client_aes_keys[sender.port])
        except Exception as e:
            print("Decryption failed:", e)
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

        nonce = os.urandom(12)

        ciphertext, tag = aes_gcm_encrypt(nonce, secret, data)

        packet = nonce + tag + ciphertext
        length = len(packet).to_bytes(4, 'big')

        client_socket.send(length + packet)
    
    def shutdown(self):
        self.server_socket.shutdown()

class Attacker():
    def send_handler(self, client_socket, client_receive_handler, data):
        try:
            message = data.decode("utf-8")
        except:
            message = None

        # klient si snaží se serverem vyměnit RSA klíč. podstrčím jim vlastní ;)
        if message is not None and message.startswith("RSA_INIT:"):
            self.client_public = RSA_Main.process_rsa_init_packet(message)
            attacker_packet, self.attacker_rsa_priv = RSA_Main.build_rsa_init_packet()
            attacker_packet = attacker_packet.encode("utf-8")
            
            # poslat klientovi
            client_receive_handler(client_socket, attacker_packet)
            
            # poslat serveru
            client_socket.send(attacker_packet)
            return

        if message is not None and message.startswith("RSA_AUTH:"):
            _, inner_message = RSA_Main.process_rsa_auth_packet(message, self.client_public)
            if inner_message.startswith("DH_INIT:"):
                # vytvořit shared secret mezi útočníkem a klientem
                dh_attacker_reply_packet, self.attacker_client_shared_secret = DHNetwork.process_init_packet(inner_message)
                attacker_client_auth_reply = RSA_Main.build_rsa_auth_packet(dh_attacker_reply_packet, self.attacker_rsa_priv)
                client_receive_handler(client_socket, attacker_client_auth_reply.encode("utf-8"))

                # vytvořit shared secret mezi úročníkem a serverem
                attacker_server_dh_packet, self.attacker_server_p, self.attacker_server_g, self.attacker_server_private_key = DHNetwork.build_init_packet()
                attacker_server_auth_packet = RSA_Main.build_rsa_auth_packet(attacker_server_dh_packet, self.attacker_rsa_priv)
                client_socket.send(attacker_server_auth_packet.encode("utf-8"))
            
            return

        if(self.attacker_client_shared_secret is not None):
            # šifrovaná komunikace
            decrypted_message = NetworkService.decrypt_and_decode(data, self.attacker_client_shared_secret)
            print("attacker sees from client: ", decrypted_message)
            
            # zašifrovat shared secretem mezi útočníkem a sevrerem a poslat serveru
            nonce = os.urandom(12)
            ciphertext, tag = aes_gcm_encrypt(nonce, self.attacker_server_shared_secret, decrypted_message.encode("utf-8"))

            packet = nonce + tag + ciphertext
            length = len(packet).to_bytes(4, 'big')

            # přeposlat serveru
            client_socket.send(length + packet)
        else:
            client_socket.send(data)

    def recv_handler(self, client_socket, client_receive_handler, data):
        try:
            message = data.decode("utf-8")
        except:
            message = None

        # server odpovídá klientovi (útočníkovi) na jeho RSA_INIT dotaz svým veřejným klíčem
        if message is not None and message.startswith("RSA_INIT:"):
            self.server_public = RSA_Main.process_rsa_init_packet(message)
            return
        
        if message is not None and message.startswith("RSA_AUTH:"):
            _, inner_message = RSA_Main.process_rsa_auth_packet(message, self.server_public)
            message = inner_message

        if message is not None and message.startswith("DH_ACCEPT:"):
            self.attacker_server_shared_secret = DHNetwork.process_accept_packet(message, self.attacker_server_p, self.attacker_server_private_key)
            print(f"mam secret mezi utocnikem a serverem {self.attacker_server_shared_secret}")
            return
        
        if(self.attacker_server_shared_secret is not None):
            # šifrovaná komunikace
            decrypted_message = NetworkService.decrypt_and_decode(data, self.attacker_server_shared_secret)
            print("attacker sees from server: ", decrypted_message)
            
            nonce = os.urandom(12)
            ciphertext, tag = aes_gcm_encrypt(nonce, self.attacker_client_shared_secret, decrypted_message.encode("utf-8"))

            packet = nonce + tag + ciphertext
            length = len(packet).to_bytes(4, 'big')

            # přeposlat klientovi
            client_receive_handler(client_socket, length + packet)
        else:
            client_receive_handler(client_socket, data)
    
    def __init__(self, host : str, port : int, instance : str):
        self.client = Client(host, port, instance, self.send_handler, self.recv_handler)
        self.attacker_server_shared_secret = None
        self.attacker_client_shared_secret = None

    def get_service(self):
        return self.client