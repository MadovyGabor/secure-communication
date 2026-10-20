"""Packet formats exchanged inside networkstack's length-prefixed frames.

Handshake packets are UTF-8 text:
    RSA_INIT:<e>:<n>                public RSA key
    RSA_AUTH:<message>|<signature>  message signed with the sender's RSA key
    DH_INIT:<p>:<g>:<A>             Diffie-Hellman offer
    DH_ACCEPT:<B>                   Diffie-Hellman answer
Chat messages after the handshake are binary AES-GCM frames:
    <length:4> <nonce:12> <tag:16> <ciphertext>
The first encrypted frame after each Diffie-Hellman exchange carries the username:
    NAME:<username>                 empty username = stay anonymous
"""

RSA_INIT = "RSA_INIT:"
RSA_AUTH = "RSA_AUTH:"
DH_INIT = "DH_INIT:"
DH_ACCEPT = "DH_ACCEPT:"
NAME = "NAME:"

LENGTH_SIZE = 4
NONCE_SIZE = 12
TAG_SIZE = 16

MAX_NAME_LENGTH = 32
ANONYMOUS_PREFIX = "Anonymous#"


def decode_text(data: bytes):
    """Return the packet as text, or None for binary (encrypted) data."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _fields(message: str, prefix: str, count: int) -> list[int]:
    if not message.startswith(prefix):
        raise ValueError(f"expected {prefix} packet")
    parts = message[len(prefix):].split(":")
    if len(parts) != count:
        raise ValueError(f"malformed {prefix[:-1]} packet: expected {count} fields, got {len(parts)}")
    return [int(part) for part in parts]


def build_rsa_init(e: int, n: int) -> str:
    return f"{RSA_INIT}{e}:{n}"


def parse_rsa_init(message: str) -> tuple[int, int]:
    e, n = _fields(message, RSA_INIT, 2)
    return e, n


def build_rsa_auth(text: str, signature: int) -> str:
    return f"{RSA_AUTH}{text}|{signature}"


def parse_rsa_auth(message: str) -> tuple[str, int]:
    if not message.startswith(RSA_AUTH):
        raise ValueError(f"expected {RSA_AUTH} packet")
    text, separator, signature = message[len(RSA_AUTH):].rpartition("|")
    if not separator:
        raise ValueError("malformed RSA_AUTH packet: missing signature")
    return text, int(signature)


def build_dh_init(p: int, g: int, public_key: int) -> str:
    return f"{DH_INIT}{p}:{g}:{public_key}"


def parse_dh_init(message: str) -> tuple[int, int, int]:
    p, g, public_key = _fields(message, DH_INIT, 3)
    return p, g, public_key


def build_dh_accept(public_key: int) -> str:
    return f"{DH_ACCEPT}{public_key}"


def parse_dh_accept(message: str) -> int:
    (public_key,) = _fields(message, DH_ACCEPT, 1)
    return public_key


def normalize_name(name: str):
    """Return the username without surrounding whitespace, or None if it cannot be used.

    Rejected names (the client then stays anonymous): empty, longer than MAX_NAME_LENGTH,
    containing control characters or brackets (they would break the "[name]: text" format)
    and names starting with ANONYMOUS_PREFIX, which is reserved for server-assigned names.
    """
    name = name.strip()
    if not name or len(name) > MAX_NAME_LENGTH:
        return None
    if not name.isprintable() or "[" in name or "]" in name:
        return None
    if name.lower().startswith(ANONYMOUS_PREFIX.lower()):
        return None
    return name


def build_name(name) -> str:
    return f"{NAME}{name or ''}"


def parse_name(message: str):
    """Return the username from a NAME packet, or None for an anonymous client."""
    if not message.startswith(NAME):
        raise ValueError(f"expected {NAME} packet")
    return normalize_name(message[len(NAME):])


def split_dh_message(message: str, prefix: str) -> tuple[str, list[str], str]:
    """Split a DH packet, possibly wrapped in RSA_AUTH, into (head, fields, tail).

    head ends with the DH prefix, fields are the ':'-separated values and tail is
    '|<signature>' or ''. join_dh_message() reassembles the parts, which lets a
    proxy replace a public key while keeping the rest of the packet intact.
    """
    index = message.index(prefix) + len(prefix)
    core, separator, signature = message[index:].partition("|")
    return message[:index], core.split(":"), separator + signature


def join_dh_message(head: str, fields: list[str], tail: str) -> str:
    return head + ":".join(fields) + tail


def build_encrypted(nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    packet = nonce + tag + ciphertext
    return len(packet).to_bytes(LENGTH_SIZE, "big") + packet


def parse_encrypted(data: bytes) -> tuple[bytes, bytes, bytes]:
    packet = data[LENGTH_SIZE:]
    nonce = packet[:NONCE_SIZE]
    tag = packet[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = packet[NONCE_SIZE + TAG_SIZE:]
    return nonce, tag, ciphertext
