from diffieHellman import DHNetwork
from RSA import RSA_Main
import socket
import threading
import time
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
    def decrypt_and_decode(self, encrypted_data, secret):
        # tady přijde AES-GCM dešifrování
        decrypted_data = encrypted_data
        decoded_message = decrypted_data.decode("utf-8")

        return decoded_message
    
    @abstractmethod
    def shutdown(self):
        pass

class Client(NetworkService):
    def __init__(self, host : str, port : int, attack_send_handler = None, attack_recv_handler = None):
        super().__init__(host, port)
        self.socket.connect((self.host, self.port))
        self.client_socket = networkstack.ClientSocket(self.socket)

        self.attack_send_handler = attack_send_handler
        self.attack_recv_handler = attack_recv_handler

        # --- DH parameters ---
        self.p = None
        self.g = None
        self.private_key = None
        self.shared_secret = None

        # --- RSA parameters ---
        self.peer_rsa_pub = None
        self.my_rsa_priv = None

        self.lock = threading.Lock()
        self.network_thread = threading.Thread(target = self.network_loop)
        self.network_thread.start()

    def loop(self):
        while self.network_thread.is_alive():
            input_ = input()
            if(input_ == "exit"):
                self.lock.acquire()
                self.client_socket.shutdown()
                self.lock.release()
                return

            elif input_ == "rsa":
                # RSA handshake!
                packet, self.my_rsa_priv = RSA_Main.build_rsa_init_packet()
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
                    
                    if(self.shared_secret is not None):
                        self.send_encrypted_to_server(encoded_message, self.shared_secret)
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
            self.attack_send_handler(self.client_socket, data)

    def send_encrypted_to_server(self, data, shared_secret):
        # Tady přijde AES-GCM šifrování
        encrypted_data = data # AES_GCM(data, shared_secret)
        self.send(encrypted_data)

    def recv(self, sender_socket, data : bytes):
        if(self.attack_recv_handler is None):
            self.receive_handler(sender_socket, data)
        else:
            self.attack_recv_handler(self.client_socket, self.receive_handler, data)

    def receive_handler(self, sender_socket, data : bytes):
        message = data.decode("utf-8")

        if message.startswith("RSA_INIT:"):
            self.peer_rsa_pub = RSA_Main.process_rsa_init_packet(message)
            print("SUCCESS: Exchanged RSA Public Keys with the Server!")
            return

        if message.startswith("RSA_AUTH:"):
            is_valid, inner_message = RSA_Main.process_rsa_auth_packet(message, self.peer_rsa_pub)
            if not is_valid:
                print("HACKER DETECTED! Dropping packet.")
                return

            message = inner_message

        if message.startswith("DH_ACCEPT:"):
            self.shared_secret = DHNetwork.process_accept_packet(message, self.p, self.private_key)
            print(f"shared secret: {str(self.shared_secret)[:15]}...")
            return

        # received encrypted message
        if(self.shared_secret is not None):
            decrypted_message = self.decrypt_and_decode(data, self.shared_secret)
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

        #DH handling: port -> shared secret
        self.client_secrets = {}

        # RSA handling
        self.client_rsa_keys = {}
        # Load server's keys
        _, self.my_rsa_priv = RSA_Main.build_rsa_init_packet()

        print("server started")

    def loop(self):
        while True:
            self.server_socket.process(self.receive_handler)

    def receive_handler(self, sender, data: bytes):
        message = data.decode("utf-8")

        # 1. Incoming Client RSA Key
        if message.startswith("RSA_INIT:"):
            client_pub = RSA_Main.process_rsa_init_packet(message)
            self.client_rsa_keys[sender.port] = client_pub

            packet, _ = RSA_Main.build_rsa_init_packet()
            sender.send(packet.encode("utf-8"))
            return

        # 2. authenticated Client Messages
        if message.startswith("RSA_AUTH:"):
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
                dh_reply_packet, shared_secret = DHNetwork.process_init_packet(inner_message)
                self.client_secrets[sender.port] = shared_secret

                auth_reply = RSA_Main.build_rsa_auth_packet(dh_reply_packet, self.my_rsa_priv)
                sender.send(auth_reply.encode("utf-8"))

                print(f"shared secret: {str(shared_secret)[:15]}...")
                return
        
        # 3. encrypted client messages
        if(sender.port not in self.client_secrets):
            sender.send("Type 'rsa' and then 'dh' to start communicating securely".encode("utf-8"))
            return

        resend = "{}: {}".format(sender.port, message)
        for client_port in self.server_socket.clients:
            if (client_port != sender.port and client_port in self.client_secrets):
                client_socket = self.server_socket.clients[client_port]
                encoded_message = resend.encode("utf-8")
                client_secret = self.client_secrets[client_port]
                
                self.send_encrypted_to_client(client_socket, encoded_message, client_secret)
    
    # helper function for encrypting data and sending it to a client
    def send_encrypted_to_client(self, client_socket, data, secret, handler = None, handler_args = ()):
        # tady přijde AES-GCM šifrování
        encrypted_data = data
        client_socket.send(encrypted_data, handler, handler_args)
    
    def shutdown(self):
        self.server_socket.shutdown()

class Attacker():
    def send_handler(self, client_socket, data):
        print("sent", data)
        client_socket.send(b"i totally sent this lol")

    def recv_handler(self, client_socket, client_receive_handler, data):
        print("received", data)
        client_socket.send(b"this is a totally authentic reply")
        client_receive_handler(client_socket, b"you totally received this")
    
    def __init__(self, host : str, port : int):
        self.client = Client(host, port, self.send_handler, self.recv_handler)

    def get_service(self):
        return self.client