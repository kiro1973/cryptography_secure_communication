import json
import base64
from utils.aes import AESEncryptor
from utils.hashing import Hashing


def send(s, derived_key):
    # Encrypt the message using AES
    while True:
        message_initial = input("enter the message to send: ")
        message = message_initial.encode("ascii")
        sha256_hashed = Hashing.sha256_hash(message)
        concatinated_msg = message_initial + " " + sha256_hashed
        binary_concatinated_msg = concatinated_msg.encode("ascii")
        aes_encryptor = AESEncryptor(derived_key)
        aes_encrypted = aes_encryptor.encrypt(binary_concatinated_msg)

        # print("sha256_hashed",sha256_hashed)
        # print("aes_encrypted tuple ",aes_encrypted)
        # Convert bytes to hexadecimal strings
        # aes_encrypted_hex = [part.hex() for part in aes_encrypted]

        # Convert the list of hexadecimal strings to JSON
        # json_data = json.dumps(aes_encrypted).encode()

        aes_encrypted_base64 = [
            base64.b64encode(part).decode() for part in aes_encrypted
        ]

        # Convert the list of base64-encoded strings to JSON
        json_data = json.dumps(aes_encrypted_base64).encode()

        # Send the JSON data over the network
        s.sendall(json_data)
        end = "end"
        s.send(end.encode())
        # print("aes_encrypted",*aes_encrypted)

        # Send the encrypted message to the server
        # s.sendall(*aes_encrypted)
