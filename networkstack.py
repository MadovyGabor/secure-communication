import socket
import json
import select

MSG_PREFIX_SIZE = 4

class SendState():
    def __init__(self, buff = bytes(), handler = None, handler_args = ()):
        self.buff = buff
        self.handler = handler
        self.handler_args = handler_args

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
        self.port = -1

        if(sock is not None):
            self.port = self.socket.getpeername()[1]

    def send(self, data, handler = None, handler_args = ()):
        if(len(data) >= 2**(4 * 8)):
            print("Data too big")
            return False
        elif(len(data) == 0):
            return True
        
        header_buff = (len(data)).to_bytes(4, 'big')
        buff = bytearray()
        buff.extend(header_buff)
        buff.extend(data)

        state = SendState(bytes(buff), handler, handler_args)
        self.send_queue.append(state)

        return True

    # blocks until the socket is readable, queued data can be written, or timeout (seconds)
    def process(self, recv_handler, recv_handler_args = (), timeout = 60):
        result = True
        to_write = [self.socket] if self.send_queue else []
        ready_to_read, ready_to_write, in_error = select.select([self.socket], to_write, [self.socket], timeout)
        if(len(ready_to_read) != 0):
            result = self.process_reading(recv_handler, recv_handler_args)
        if(len(ready_to_write) != 0):
            self.process_writing()
        if(len(in_error) != 0):
            print("socket error condition on connection", self.port)

        return result

    def process_writing(self):
        if(len(self.send_queue) == 0):
            return

        state = self.send_queue[0]
        sent = self.socket.send(state.buff)
        state.buff = state.buff[sent :]
        
        if(len(state.buff) == 0):
            if(state.handler is not None):
                state.handler(*state.handler_args, self)
            self.send_queue.pop(0)
    
    def process_reading(self, recv_handler, recv_handler_args = ()):
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

        try:
            received = self.socket.recv(recv_len)
        except ConnectionError:
            received = b"" # reset by peer is a disconnect too
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
                    recv_handler(*recv_handler_args, self, state.data_buff) # TODO: event
                    self.recv_queue.pop(0)

        return True

    def shutdown(self):
        if(self.socket is not None):
            self.socket.close()
            self.socket = None

class ServerSocket():
    def __init__(self, server_socket, on_disconnect = None):
        self.server_socket = server_socket
        self.clients = {}
        self.on_disconnect = on_disconnect # called with the client's port

    # blocks until a socket is readable, queued data can be written, or timeout (seconds)
    def process(self, recv_handler, recv_handler_args = (), timeout = 60):
        sockets_to_read = [self.server_socket]
        sockets_to_write = []
        socket_ports = {}
        for port, client in self.clients.items():
            socket_ports[client.socket] = port
            sockets_to_read.append(client.socket)
            if(client.send_queue): # only wait for writability when there is something to send
                sockets_to_write.append(client.socket)

        ready_to_read, ready_to_write, in_error = select.select(sockets_to_read, sockets_to_write, [], timeout)

        # a socket error on one client (e.g. connection reset) disconnects only that client
        disconnected = set()
        for sock in ready_to_read:
            if(sock is self.server_socket):
                self.accept_client()
                continue

            port = socket_ports[sock]
            try:
                connected = self.clients[port].process_reading(recv_handler, recv_handler_args)
            except OSError:
                connected = False
            if(not connected):
                disconnected.add(port)

        for sock in ready_to_write:
            port = socket_ports[sock]
            if(port in disconnected):
                continue
            try:
                self.clients[port].process_writing()
            except OSError:
                disconnected.add(port)

        for port in disconnected:
            print("client", port, "disconnected")
            self.clients.pop(port).shutdown()
            if(self.on_disconnect is not None):
                self.on_disconnect(port)

    def accept_client(self):
        try:
            conn, address = self.server_socket.accept()
            port = conn.getpeername()[1]
        except OSError as e:
            print("failed to accept connection:", e)
            return

        if(port in self.clients):
            print("rejected connection from", address, "- port", port, "already in use by another client")
            conn.close()
            return

        client = ClientSocket(conn)
        self.clients[port] = client
        client.send(b"welcome to the server") # TODO: event
        print("client", port, "connected")

    def shutdown(self):
        for client in self.clients.values():
            client.shutdown()
        self.clients.clear()
        self.server_socket.close()
