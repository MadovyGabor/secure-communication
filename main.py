import sys

import networkservice

attacker = None
service = None
def main(mode, host, port, instance):
    if(mode == "client"):
        service = networkservice.Client(host, port, instance)
    elif(mode == "server"):
        service = networkservice.Server(host, port)
    elif(mode == "attacker"):
        attacker = networkservice.Attacker(host, port, instance)
        service = attacker.get_service()
    else:
        exit()

    service.loop()

if(len(sys.argv) < 3 + 1):
    exit()

mode : str = sys.argv[1]
host : str = sys.argv[2]
port : int = int(sys.argv[3])
instance : str = "default"

if(mode == "client" or mode == "attacker"):
    if(len(sys.argv) >= 4 + 1):
        instance = sys.argv[4]

try:
    main(mode, host, port, instance)
except KeyboardInterrupt:
    if(service is not None):
        service.shutdown()
        service = None