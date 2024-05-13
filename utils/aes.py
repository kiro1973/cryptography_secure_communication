# aes.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return (ciphertext, tag, cipher.nonce)

class AESDecryptor:
    def __init__(self, key):
        self.key = key

    def decrypt(self, ciphertext, tag, nonce):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
