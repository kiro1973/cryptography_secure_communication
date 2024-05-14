import socket
import json
import base64
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from utils.aes import AESEncryptor, AESDecryptor
from utils.hashing import Hashing
from socket_utils.send import send
from socket_utils.receive import receive_texts
from authentication_utils import *


def main():

    login_response = ""

    while True:
        print("1. Register")
        print("2. Login")
        choice = input("Enter your choice (1/2/3): ")
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            login_response = register(username, password)
            if '{"response": "Registered successfully"}' in login_response:
                print("Registered successfully")
                break  # Exit the loop if successfully registered
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            login_response = login(username, password)
            if '{"response": "Successfully logged in"}' in login_response:
                print("Successfully logged in")
                break  # Exit the loop if successfully logged in

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = 12345
    s.bind(("", port))
    print("Socket binded to %s" % (port))
    s.listen(5)
    print("Socket is listening")

    parameters = dh.generate_parameters(generator=2, key_size=2048)
    server_private_key = parameters.generate_private_key()

    if (
        '{"response": "Successfully logged in"}' in login_response
        or '{"response": "Registered successfully"}' in login_response
    ):

        c, addr = s.accept()
        print("Got connection from", addr)

        parameters_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        )
        server_public_key = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        data = {
            "parameters": parameters_bytes.decode(),
            "server_public_key": server_public_key.decode(),
        }
        c.send(json.dumps(data).encode())

        data = c.recv(4096)
        if not data:
            exit
        print("Client Public Key:", data.decode())
        client_public_key = serialization.load_pem_public_key(
            data, backend=default_backend()
        )
        shared_key = server_private_key.exchange(client_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        print("Derived Key (server):", derived_key.hex())

        thread1 = threading.Thread(target=receive_texts, args=(c, derived_key))
        thread2 = threading.Thread(target=send, args=(c, derived_key))

        thread1.start()
        thread2.start()


if __name__ == "__main__":
    main()
