import sys

import networkservice

service = None
def main(mode, host, port):
    if(mode == "client"):
        service = networkservice.Client(host, port)
    elif(mode == "server"):
        service = networkservice.Server(host, port)
    elif(mode == "attack"):
        pass
    else:
        exit()

    service.loop()

if(len(sys.argv) < 3 + 1):
    exit()

mode : str = sys.argv[1]
host : str = sys.argv[2]
port : int = int(sys.argv[3])

try:
    main(mode, host, port)
except KeyboardInterrupt:
    if(service is not None):
        service.shutdown()
        service = None