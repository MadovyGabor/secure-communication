import socket
import json
import select

MSG_PREFIX_SIZE = 4

class SendState():
    def __init__(self, buff = bytes(), handler = None):
        self.buff = buff
        self.handler = handler

class RecvState():
    def __init__(self, header_buff = bytes(), data_len = -1, data_buff = bytes()):
        self.header_buff = header_buff
        self.data_len = data_len
        self.data_buff = data_buff

class ClientSocket():
    def __init__(self, sock = None):
        self.socket = sock
        self.send_queue = []
        self.recv_queue = []

    def send(self, data, handler):
        if(len(data) > 2**(4 * 8)):
            print("Data too big")
            return False
        
        header_buff = (len(data)).to_bytes(4, 'big')
        buff = bytearray()
        buff.extend(header_buff)
        buff.extend(data)

        state = SendState(bytes(buff), handler)
        self.send_queue.append(state)

        return True

    # blocking!
    def process(self, recv_handler):
        result = True
        ready_to_read, ready_to_write, in_error = select.select([self.socket], [self.socket], [self.socket], 60)
        if(len(ready_to_read) != 0):
            result = self.process_reading(recv_handler)
        if(len(ready_to_write) != 0):
            self.process_writing()
        if(len(in_error) != 0):
            print("erroooor")

        return result

    def process_writing(self):
        if(len(self.send_queue) == 0):
            return

        state = self.send_queue[0]
        sent = self.socket.send(state.buff)
        state.buff = state.buff[sent :]
        
        if(len(state.buff) == 0):
            if(state.handler is not None):
                state.handler()
            self.send_queue.pop(0)
    
    def process_reading(self, recv_handler):
        recv_len = MSG_PREFIX_SIZE
        state = None
        reading_header = True
        if(len(self.recv_queue) == 0):
            state = RecvState()
            self.recv_queue.append(state)
        else:
            state = self.recv_queue[0]
            if(len(state.header_buff) == MSG_PREFIX_SIZE):
                recv_len = state.data_len - len(state.data_buff)
                reading_header = False
            else:
                recv_len = MSG_PREFIX_SIZE - len(state.header_buff)

        received = self.socket.recv(MSG_PREFIX_SIZE)
        if(received == b""):
            self.recv_queue.pop(0)
            return False # disconnected
        else:
            if(reading_header):
                state.header_buff = state.header_buff + received
                if(len(state.header_buff) == MSG_PREFIX_SIZE):
                    state.data_len = int.from_bytes(state.header_buff, "big")
            else:
                state.data_buff = state.data_buff + received
                if(len(state.data_buff) == state.data_len):
                    recv_handler(state.data_buff)
                    self.recv_queue.pop(0)

        return True

    def shutdown(self):
        self.socket.close()
        self.socket = None

class ServerSocket():
    def __init__(self, server_socket):
        self.server_socket = server_socket
        self.clients = {}

    # blocking
    def process(self, recv_handler):
        sockets_to_read = [self.server_socket]
        sockets_to_write = []
        for key in self.clients:
            socket = self.clients[key].socket
            sockets_to_read.append(socket)
            sockets_to_write.append(socket)

        ready_to_read, ready_to_write, in_error = select.select(sockets_to_read, sockets_to_write, [], 60)
        for socket in ready_to_read:
            if(self.server_socket == socket):
                conn, address = self.server_socket.accept()
                print(conn.getpeername()[1], address)
                if(conn.getpeername()[1] in self.clients):
                    print("bruuuh")
                    return

                client = ClientSocket(conn)
                self.clients[conn.getpeername()[1]] = client
                client.send(b"hatsune miku", lambda : print("finished sending a message"))
            else:
                client = self.clients[socket.getpeername()[1]]
                if(not client.process_reading(recv_handler)): # a client disconnected
                    print("client", socket.getpeername()[1], "disconnected")
                    del self.clients[socket.getpeername()[1]]
                    client.shutdown()
                    if(socket in sockets_to_write):
                        sockets_to_write.remove(socket)
        
        for socket in sockets_to_write:
            self.clients[socket.getpeername()[1]].process_writing()

    def shutdown(self):
        for client in self.clients:
            client.shutdown()
        self.server_socket.close()
