import random
import socket
import string
import sys
import crypto_helpers as helpers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def Main():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 8888
    max_buffer_size = 5120

    try:
        soc.connect((host, port))
    except:
        print("Connection error")
        sys.exit()

    server_public_key = soc.recv(max_buffer_size)
    server_public_key = serialization.load_pem_public_key(
        server_public_key,
        backend=default_backend()
    )

    sym_key, iv = helpers.gen_sym_key()
    encrypted_sym_key = helpers.encrypt_asym(sym_key, server_public_key)
    soc.send(encrypted_sym_key)
    soc.send(iv)

    print("Initialized tunnel mode with key ", sym_key)

    certificate = helpers.decrypt_sym(soc.recv(max_buffer_size), sym_key, iv)
    user_data = helpers.decrypt_sym(soc.recv(max_buffer_size), sym_key, iv)

    if certificate != helpers.get_hash(user_data):
        raise Exception("Hash doesn't match the certificate")

    print("User certificate received: ", certificate)
    print("Enter 'quit' to exit")

    paywords = generate_payword_chain(100)
    c0 = paywords[len(paywords) - 1]

    # TODO continue with commitment to pay towards V

    message = raw_input(" -> ")

    while message != 'quit':
        soc.sendall(helpers.encrypt_sym(message, sym_key, iv))
        if helpers.decrypt_sym(soc.recv(max_buffer_size), sym_key, iv).decode("utf-8") == "-":
            pass        # null operation

        message = raw_input(" -> ")

    soc.send(helpers.encrypt_sym(b'--quit--', sym_key, iv))


def generate_payword_chain(chain_size=100):
    result = list()
    current_hash = helpers.get_hash(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50)))

    result.append(current_hash)
    count = 1
    while count < chain_size:
        current_hash = helpers.get_hash(current_hash)
        result.append(current_hash)
        count += 1

    return result


if __name__ == "__main__":
    Main()
    generate_payword_chain()