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

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = 12345
    s.bind(('', port))
    print("Socket binded to %s" % (port))
    s.listen(5)
    print("Socket is listening")

    parameters = dh.generate_parameters(generator=2, key_size=2048)
    server_private_key = parameters.generate_private_key()

    c, addr = s.accept()
    print('Got connection from', addr)

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
    c.send(json.dumps(data).encode())

    data = c.recv(4096)
    if not data:
        exit
    print("Client Public Key:", data.decode())
    client_public_key = serialization.load_pem_public_key(data, backend=default_backend())
    shared_key = server_private_key.exchange(client_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print("Derived Key (server):", derived_key.hex())

    thread1 = threading.Thread(target=receive_texts, args=(c, derived_key))
    thread2 = threading.Thread(target=send, args=(c, derived_key))

    thread1.start()
    thread2.start()

if __name__ == "__main__":
    main()
