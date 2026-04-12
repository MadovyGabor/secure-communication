import sympy
import sympy
import json
import os


def generate_rsa_parameters(key_size: int = 2048) -> tuple[tuple[int, int], tuple[int, int]]:

    # p and q are the large prime numbers
    p = sympy.randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
    q = sympy.randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
    while p == q:
        q = sympy.randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))

    n = p * q
    phi = (p - 1) * (q - 1)

    # 65537 is the standard
    e = 65537
    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def rsa_sign(message_int: int, private_key: tuple[int, int]) -> int:

    d, n = private_key
    signature = pow(message_int, d, n)
    return signature


def rsa_verify(message_int: int, signature_int: int, public_key: tuple[int, int]) -> bool:

    e, n = public_key
    # Unpack the signature using the public key
    expected_message = pow(signature_int, e, n)

    # If the unpacked signature matches the actual message, it's authentic!
    return expected_message == message_int

def save_keys_to_json(public_key: tuple[int, int], private_key: tuple[int, int],
                      filename: str = "rsa_keys.json") -> None:

    e, n = public_key
    d, _ = private_key  # The 'n' is the same for both, so we only need it once

    key_data = {
        "public_key": {"e": e, "n": n},
        "private_key": {"d": d, "n": n}
    }

    with open(filename, 'w') as json_file:
        json.dump(key_data, json_file, indent=4)

    print(f"[RSA Protocol] Keys successfully saved locally to '{filename}'.")


def load_keys_from_json(filename: str = "rsa_keys.json") -> tuple[tuple[int, int], tuple[int, int]]:

    if not os.path.exists(filename):
        print(f"[RSA Protocol] Warning: Key file '{filename}' not found.")
        return None, None

    print(f"[RSA Protocol] Loading existing keys from '{filename}'...")

    with open(filename, 'r') as json_file:
        key_data = json.load(json_file)

    e = key_data["public_key"]["e"]
    n = key_data["public_key"]["n"]
    d = key_data["private_key"]["d"]

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key