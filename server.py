import socket
import sys
import traceback
import datetime
from threading import Thread

import crypto_helpers as helpers
from cryptography.hazmat.backends import default_backend
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
    sym_key, iv, client_public_key = initiate_tunnel_mode(connection, public_key, private_key)
    print("Initialized tunnel mode with key ", sym_key)

    user_data = user_certificate(public_key, client_public_key)
    certificate = helpers.get_hash(user_data)
    connection.send(helpers.encrypt_sym(certificate.encode("utf-8"), sym_key, iv))
    connection.send(helpers.encrypt_sym(user_data.encode("utf-8"), sym_key, iv))

    print("User certificate sent: ", str(certificate))

    new_commitment = helpers.decrypt_sym(connection.recv(max_buffer_size), sym_key, iv)
    commitment_data = helpers.decrypt_sym(connection.recv(max_buffer_size), sym_key, iv)

    print("Received commitment ", new_commitment)
    print(commitment_data)
    array_commitment_data = commitment_data.split()

    paywords_archive = list()

    # if datetime.datetime.strptime(array_commitment_data[3], "%Y-%m-%d") < datetime.datetime.now():
    #    raise Exception("Commitment Expired")

    data = ""
    previous = ""
    connectionClosed = False

    while not connectionClosed:
        value = 0

        while data != "END":

            if value == int(array_commitment_data[4]):
                raise Exception("Chain limit reached")

            data = helpers.decrypt_sym(connection.recv(max_buffer_size), sym_key, iv).decode("utf-8")

            if data == "QUIT":
                raise Exception("Y U no exit?")

            if data != "END":

                if previous == "":
                    if data.encode("utf-8") != array_commitment_data[2]:
                        raise Exception("Payword doesn't match the one from the Commitment!")

                else:
                    if helpers.get_hash(data) != previous:
                        raise Exception("Hash doesn't match the previous Payword")
                    if data in paywords_archive:
                        raise Exception("Payword already used")

                paywords_archive.append(data.encode("utf-8"))
                previous = data
                data = data
                value += 1

        print(array_commitment_data[0].decode("utf-8") + " received " + str(value) + " money")

        data = helpers.decrypt_sym(connection.recv(max_buffer_size), sym_key, iv).decode("utf-8")

        if data != "CONTINUE":
            return



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

    client_public_key = connection.recv(max_buffer_size)
    client_public_key = serialization.load_pem_public_key(
        client_public_key,
        backend=default_backend()
    )

    decrypted = helpers.decrypt_asym(hashed_sym_key, private_key)

    return decrypted, iv, client_public_key


def user_certificate(server_public_key, client_public_key):

    current_date = datetime.date.today()
    exp = current_date + datetime.timedelta(days=30)
    credit_limitation = str(100)

    return str(server_public_key) + " " + str(client_public_key) + " " + str(exp) + " " + credit_limitation


if __name__ == "__main__":
    Main()
