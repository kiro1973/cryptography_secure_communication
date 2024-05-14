import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from utils.aes import  AESDecryptor
from utils.hashing import Hashing
# Create a socket object
s = socket.socket()

# Set SO_REUSEADDR option
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

print("Socket successfully created")

# Reserve a port on your computer
port = 12345

# Bind to the port
s.bind(('', port))
print("Socket binded to %s" % (port))

# Put the socket into listening mode
s.listen(5)
print("Socket is listening")

# Generate parameters and serialize them
parameters = dh.generate_parameters(generator=2, key_size=2048)
server_private_key = parameters.generate_private_key()

while True:
    # Establish connection with client
    c, addr = s.accept()
    print('Got connection from', addr)
    
    # Serialize parameters and server public key
    parameters_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    server_public_key = server_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    data = {
        'parameters': parameters_bytes.decode(),
        'server_public_key': server_public_key.decode()
    }

    # Send JSON data to the client
    c.send(json.dumps(data).encode())
  
    # Receive data from the client
    data = c.recv(4096)
    if not data:
        break
    print("Client Public Key :", data.decode())
 
    # Load the PEM-encoded DH public key directly as a DHPublicKey object
    client_public_key = serialization.load_pem_public_key(data, backend=default_backend())
 
    shared_key = server_private_key.exchange(client_public_key)
   
    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print("Derived Key (server):", derived_key.hex())

    # Receive encrypted message from client
    #encrypted_message = c.recv(4096)
    # Receive the JSON data
    json_data = b''
    while True:
        chunk = c.recv(4096)
        if not chunk:
            break
        json_data += chunk
    print("json_data",json_data)
    # Deserialize the JSON data
    aes_encrypted_base64 = json.loads(json_data.decode())

    # Decode each base64 string back to bytes
    aes_encrypted = tuple(base64.b64decode(part.encode()) for part in aes_encrypted_base64)
    # json_data = s.recv(4096)
    # aes_encrypted = json.loads(json_data.decode())
    # Decrypt the message using AES
    # Decrypt the message
    aes_decryptor = AESDecryptor(derived_key)
    #aes_decrypted_parts = [aes_decryptor.decrypt(part) for part in aes_encrypted]

    aes_decrypted = aes_decryptor.decrypt(*aes_encrypted)
    print("aes_decrypted",aes_decrypted)
    input_string_str = aes_decrypted.decode('utf-8')

    # Split the string based on whitespace
    words = input_string_str.split()

    # Get the last word
    last_word = words[-1]

    # Get the remaining part of the string without the last word
    remaining_string = input_string_str.rsplit(last_word, 1)[0].strip()
    remaining_string_binary=remaining_string.encode('ascii')
    sha256_hashed = Hashing.sha256_hash(remaining_string_binary)
    if (sha256_hashed==last_word):
        print("the sent message passed the integrity check")
    else:
        print("the sent message did not pass the integrity check")
    print("Last word:", last_word)
    print("Remaining string:", remaining_string)
    # Close the connection with the client
    c.close()

# Close the server socket
s.close()
