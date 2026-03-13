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
    def __init__(self, host : str, port : int):
        super().__init__(host, port)
        self.socket.connect((self.host, self.port))
        self.client_socket = networkstack.ClientSocket(self.socket)
        
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
            else:
                if(self.network_thread.is_alive()):
                    self.client_socket.send(input_.encode("utf-8"))  
    
    def network_loop(self):
        while self.client_socket.socket is not None:
            self.lock.acquire()
            connected = self.client_socket.process(self.receive_handler)
            self.lock.release()
            if(not connected):
                self.client_socket.shutdown()
                print("server shut down")
                return

            time.sleep(0.1)

    def receive_handler(self, sender_socket, data : bytes):
        message = data.decode("utf-8")
        print(message)

    def shutdown(self):
        self.client_socket.shutdown()

class Server(NetworkService):
    def __init__(self, host : str, port : int):
        super().__init__(host, port)
        self.socket.bind((host, port))
        self.socket.listen(1)
        
        self.server_socket = networkstack.ServerSocket(self.socket)
        print("server started")

    def loop(self):
        while True:
            self.server_socket.process(self.receive_handler)
        
    def receive_handler(self, sender, data : bytes):
        message = data.decode("utf-8")
        resend = "{}: {}".format(sender.port, message)

        for client_port in self.server_socket.clients:
            if(client_port != sender.port):
                self.server_socket.clients[client_port].send(resend.encode("utf-8"))

    def shutdown(self):
        self.server_socket.shutdown()