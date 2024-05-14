import json
import base64
from utils.aes import  AESDecryptor
from utils.hashing import Hashing

def receive_texts(c,derived_key):
    while True:
        json_data = b''
        while True:
            chunk = c.recv(4096)
            #print("chunk: ",chunk)
            if  chunk.decode()=="end":
                break
            json_data += chunk
        #print("json_data",json_data)
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
        #print("aes_decrypted",aes_decrypted)
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
        #print("Last word:", last_word)
        print("received message:", remaining_string)


