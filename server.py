import socket
import sys
import traceback
import datetime
from threading import Thread
from strgen import StringGenerator

import crypto_helpers as helpers
from cryptography.hazmat.primitives import serialization


def Main():
    start_server()


def start_server():
    host = "127.0.0.1"
    port = 8888
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")
    public_key, private_key = helpers.gen_asym_keys()

    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(5)
    print("Socket now listening")

    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        print("Connected with " + ip + ":" + port)

        try:
            Thread(target=client_thread, args=(connection, ip, port, public_key, private_key)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

    soc.close()


def client_thread(connection, ip, port, public_key, private_key, max_buffer_size = 5120):
    is_active = True
    sym_key, iv = initiate_tunnel_mode(connection, public_key, private_key)
    print("Initialized tunnel mode with key ", sym_key)

    user_data = user_certificate()
    certificate = helpers.get_hash(user_data)
    connection.send(helpers.encrypt_sym(certificate.encode("utf-8"), sym_key, iv))
    connection.send(helpers.encrypt_sym(user_data.encode("utf-8"), sym_key, iv))

    print("User certificate sent: ", str(certificate))

    while is_active:
        client_input = helpers.decrypt_sym(connection.recv(max_buffer_size), sym_key, iv).decode("utf-8")

        if client_input == "--quit--":
            print("Client is requesting to quit")
            connection.close()
            print("Connection " + ip + ":" + port + " closed")
            is_active = False
        else:
            print("Processed result: {}".format(client_input))
            connection.sendall("-".encode("utf8"))


def receive_input(connection, max_buffer_size):
    client_input = connection.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        print("The input size is greater than expected {}".format(client_input_size))

    decoded_input = client_input.decode("utf8").rstrip()
    result = process_input(decoded_input)

    return result


def process_input(input_str):
    print("Processing the input received from client")

    return str(input_str)


def initiate_tunnel_mode(connection, public_key, private_key, max_buffer_size=5120):
    connection.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    hashed_sym_key = connection.recv(max_buffer_size)
    iv = connection.recv(max_buffer_size)

    decrypted = helpers.decrypt_asym(hashed_sym_key, private_key)

    return decrypted, iv


def user_certificate():

    broker_identity = StringGenerator('[\l\d]{4:18}&[\d]&[\p]').render()
    user_identity = StringGenerator('[\l\d]{4:18}&[\d]&[\p]').render()

    current_date = datetime.date.today()
    exp = current_date + datetime.timedelta(days=30)
    credit_limitation = str(100)

    return broker_identity + " " + user_identity + " " + str(exp) + " " + credit_limitation


if __name__ == "__main__":
    Main()
