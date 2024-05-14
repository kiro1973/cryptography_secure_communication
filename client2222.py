import socket
import json
import base64
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils.aes import AESEncryptor,AESDecryptor
from utils.hashing import Hashing
from socket_utils.send import send
from socket_utils.receive import receive_texts


# Create a socket object
s = socket.socket()

# Connect to the server
s.connect(('127.0.0.1', 12345))

# Receive data from the server
data = s.recv(4096)
received_data = json.loads(data)

# Extract parameters and server's public key
parameters_bytes = received_data['parameters'].encode()
server_public_key_bytes = received_data['server_public_key'].encode()

# Deserialize server's public key and DH parameters
server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
parameters = serialization.load_pem_parameters(parameters_bytes, backend=default_backend())

# Generate client private key
client_private_key = parameters.generate_private_key()

# Send client's public key to the server
s.sendall(client_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# Exchange keys
shared_key = client_private_key.exchange(server_public_key)

# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

print("Derived Key (client):", derived_key.hex())

# Create threads for sending and receiving messages
thread2 = threading.Thread(target=receive_texts, args=(s, derived_key))
thread1 = threading.Thread(target=send, args=(s, derived_key))


# Start the threads
thread1.start()
thread2.start()

# Wait for both threads to finish
thread1.join()
thread2.join()

# Close the connection with the server
#s.close()
