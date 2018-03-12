import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend, default_backend
from cryptography.hazmat.primitives.asymmetric import padding as pad1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_hash(message):
    m = hashlib.sha256()
    m.update(message.encode('utf-8'))
    return m.hexdigest()


def gen_sym_key():
    return str(os.urandom(32)), str(os.urandom(16))


def encrypt_sym(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()


def decrypt_sym(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def gen_asym_keys():

    # public_key_file = open('public_key.pem', 'w')
    # private_key_file = open('private_key.pem', 'w')

    private_key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return public_key, private_key


def encrypt_asym(message, public_key):
    return public_key.encrypt(
        message,
        pad1.OAEP(
            mgf=pad1.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


def decrypt_asym(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        pad1.OAEP(
            mgf=pad1.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
