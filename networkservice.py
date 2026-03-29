from diffieHellman import DHNetwork
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
            elif input_ == "dh":

                packet, self.p, self.g, self.private_key = DHNetwork.build_init_packet()

                if self.network_thread.is_alive():
                    self.send(packet.encode("utf-8"))

            else:
                if(self.network_thread.is_alive()):
                    self.send(input_.encode("utf-8"))  
    
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

    def recv(self, sender_socket, data : bytes):
        if(self.attack_recv_handler is None):
            self.receive_handler(sender_socket, data)
        else:
            self.attack_recv_handler(self.client_socket, self.receive_handler, data)

    def receive_handler(self, sender_socket, data : bytes):
        message = data.decode("utf-8")

        if message.startswith("DH_ACCEPT:"):
            self.shared_secret = DHNetwork.process_accept_packet(message, self.p, self.private_key)
            print(f"shared secret: {str(self.shared_secret)[:15]}...")
            return

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

        print("server started")

    def loop(self):
        while True:
            self.server_socket.process(self.receive_handler)
        
    def receive_handler(self, sender, data : bytes):
        message = data.decode("utf-8")

        if message.startswith("DH_INIT:"):

            packet, shared_secret = DHNetwork.process_init_packet(message)
            self.client_secrets[sender.port] = shared_secret
            sender.send(packet.encode("utf-8"))
            print(f"shared secret: {str(shared_secret)[:15]}...")

            return

        resend = "{}: {}".format(sender.port, message)

        for client_port in self.server_socket.clients:
            if(client_port != sender.port):
                self.server_socket.clients[client_port].send(resend.encode("utf-8"))

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