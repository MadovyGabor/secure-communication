import sys
import networkstack
import socket

def recv_handler(data):
    print(data)

def main(sock, mode, host, port):
    if(mode == "client"):
        sock.connect((host, port))
        client = networkstack.ClientSocket(sock)
        while True:
            if(not client.process(recv_handler)):
                print("server shut down")
                break
    elif(mode == "server"):
        sock.bind(("127.0.0.1", port))
        sock.listen(1)
        server = networkstack.ServerSocket(sock)
        while True:
            server.process(recv_handler)
    elif(mode == "attack"):
        pass
    else:
        exit()

if(len(sys.argv) < 3 + 1):
    exit()

mode : str = sys.argv[1]
host : str = sys.argv[2]
port : int = int(sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    main(sock, mode, host, port)
except KeyboardInterrupt:
    sock.close()