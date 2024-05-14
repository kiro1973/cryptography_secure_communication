import socket
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils.aes import AESEncryptor
from utils.hashing import Hashing
import os
import hashlib


# Function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function for client registration
def register(username, password):
    hashed_password = hash_password(password)
    request_data = {
        "action": "register",
        "username": username,
        "password": password,
        "hashed_password": hashed_password,
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(("localhost", 43445))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print(response)
        return response


# Function for client login
def login(username, password):
    request_data = {"action": "login", "username": username, "password": password}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(("localhost", 43445))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print(response)
        return response


login_response = None
print("1. Register")
print("2. Login")
choice = input("Enter your choice (1/2/3): ")
if choice == "1":
    username = input("Enter username: ")
    password = input("Enter password: ")
    login_response = register(username, password)
elif choice == "2":
    username = input("Enter username: ")
    password = input("Enter password: ")
    login_response = login(username, password)

if login_response == "Successfully logged in" or "Registered successfully":
    # Create a socket object
    s = socket.socket()

    # Connect to the server
    s.connect(("127.0.0.1", 12345))

    # Receive data from the server
    data = s.recv(4096)
    received_data = json.loads(data)

    # Extract parameters and server's public key
    parameters_bytes = received_data["parameters"].encode()
    server_public_key_bytes = received_data["server_public_key"].encode()

    # Deserialize server's public key and DH parameters
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes, backend=default_backend()
    )
    parameters = serialization.load_pem_parameters(
        parameters_bytes, backend=default_backend()
    )

    # Generate client private key
    client_private_key = parameters.generate_private_key()

    # Send client's public key to the server
    s.sendall(
        client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Exchange keys
    shared_key = client_private_key.exchange(server_public_key)

    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)

    print("Derived Key (client):", derived_key.hex())

    # Encrypt the message using AES
    message = b"Hello from client!"
    aes_encryptor = AESEncryptor(derived_key)
    aes_encrypted = aes_encryptor.encrypt(message)
    print("aes_encrypted tuple ", aes_encrypted)
    # Convert bytes to hexadecimal strings
    # aes_encrypted_hex = [part.hex() for part in aes_encrypted]

    # Convert the list of hexadecimal strings to JSON
    # json_data = json.dumps(aes_encrypted).encode()

    aes_encrypted_base64 = [base64.b64encode(part).decode() for part in aes_encrypted]

    # Convert the list of base64-encoded strings to JSON
    json_data = json.dumps(aes_encrypted_base64).encode()

    # Send the JSON data over the network
    s.sendall(json_data)
    # print("aes_encrypted",*aes_encrypted)

    # Send the encrypted message to the server
    # s.sendall(*aes_encrypted)

    # Close the connection with the server
    s.close()
