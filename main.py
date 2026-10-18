import sys

import networkservice

attacker = None
service = None
def main(mode, host, port, instance, secure):
    if(mode == "client"):
        service = networkservice.Client(host, port, instance, secure=secure)
    elif(mode == "server"):
        service = networkservice.Server(host, port, secure=secure)
    elif(mode == "attack"):
        attacker = networkservice.Attacker(host, port, secure=secure)
        service = attacker.get_service()
    else:
        exit()

    service.loop()

if(len(sys.argv) < 3 + 1):
    exit()

mode : str = sys.argv[1]
host : str = sys.argv[2]
port : int = int(sys.argv[3])

secure = "--unsecure" not in sys.argv
sys.argv = [arg for arg in sys.argv if arg != "--unsecure"]

instance : str = "default"
if(mode == "client" and len(sys.argv) >= 4 + 1):
    instance = sys.argv[4]

try:
    main(mode, host, port, instance, secure)
except KeyboardInterrupt:
    if(service is not None):
        service.shutdown()
        service = None