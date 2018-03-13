import random
import socket
import string
import sys

import datetime

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

    public_key, private_key = helpers.gen_asym_keys()

    server_public_key = soc.recv(max_buffer_size)
    server_public_key = serialization.load_pem_public_key(
        server_public_key,
        backend=default_backend()
    )

    sym_key, iv = helpers.gen_sym_key()
    encrypted_sym_key = helpers.encrypt_asym(sym_key, server_public_key)
    soc.send(encrypted_sym_key)
    soc.send(iv)

    soc.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    print("Initialized tunnel mode with key ", sym_key)

    certificate = helpers.decrypt_sym(soc.recv(max_buffer_size), sym_key, iv)
    user_data = helpers.decrypt_sym(soc.recv(max_buffer_size), sym_key, iv)

    if certificate != helpers.get_hash(user_data):
        raise Exception("Hash doesn't match the certificate")

    print("User certificate received: ", certificate)
    print("Enter 'quit' to exit")


    # generating paywords
    paywords = generate_payword_chain(100)
    c0 = paywords[len(paywords) - 1]

    # new commitment
    seller_commitment = commitment("PLACEHOLDER-FOR-A-SELLER-IDENTITY", certificate, paywords[len(paywords) - 1])

    soc.send(helpers.encrypt_sym(helpers.get_hash(seller_commitment).encode("utf-8"), sym_key, iv))
    soc.send(helpers.encrypt_sym(seller_commitment.encode("utf-8"), sym_key, iv))

    print("commitment sent", seller_commitment)

    payment_value = 10

    for i in range(1, payment_value + 1):
        soc.send(helpers.encrypt_sym(paywords[len(paywords) - i], sym_key, iv))
    soc.send(helpers.encrypt_sym("END", sym_key, iv))

    print("payment of " + str(payment_value) + " made")

    new_payment_value = 10

    soc.send(helpers.encrypt_sym("CONTINUE", sym_key, iv))
    for i in range(1, new_payment_value + 1):
        soc.send(helpers.encrypt_sym(paywords[len(paywords) - i - payment_value], sym_key, iv))
    soc.send(helpers.encrypt_sym("END", sym_key, iv))

    soc.send(helpers.encrypt_sym("QUIT", sym_key, iv))

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


def commitment(seller_public_key, certificate, c0, credit_limitation=100):
    #current date
    d = datetime.date.today() + datetime.timedelta(days=1)
    return str(seller_public_key) + " " + certificate + " " + c0 + " " + str(d) + " " + str(credit_limitation)


if __name__ == "__main__":
    Main()
