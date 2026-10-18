import argparse
import sys

import networkservice


def port_number(value: str) -> int:
    port = int(value)
    if not 0 < port < 65536:
        raise argparse.ArgumentTypeError(f"port must be 1-65535, got {port}")
    return port


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure chat playground (server, client, MITM attacker).")
    parser.add_argument("mode", choices=["server", "client", "attack"])
    parser.add_argument("host", help="server: address to listen on; client/attack: address to connect to")
    parser.add_argument("port", type=port_number, help="server: port to listen on; client/attack: port to connect to")
    parser.add_argument("instance", nargs="?", default="default", help="client instance name (selects key files)")
    parser.add_argument("--unsecure", dest="secure", action="store_false", help="disable RSA authentication")
    return parser.parse_args(argv)


def build_service(args: argparse.Namespace):
    if args.mode == "client":
        return networkservice.Client(args.host, args.port, args.instance, secure=args.secure)
    if args.mode == "server":
        return networkservice.Server(args.host, args.port, secure=args.secure)
    return networkservice.Attacker(args.host, args.port, secure=args.secure)


def run(service) -> None:
    try:
        service.loop()
    except KeyboardInterrupt:
        service.shutdown()


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        service = build_service(args)
    except (OSError, ValueError) as e:
        print(f"Error: cannot start {args.mode} on {args.host}:{args.port}: {e}", file=sys.stderr)
        return 1
    run(service)
    return 0


if __name__ == "__main__":
    sys.exit(main())
