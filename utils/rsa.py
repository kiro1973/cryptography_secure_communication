# rsa.py
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class RSAEncryptor:
    def __init__(self, public_key):
        self.public_key = public_key

    def encrypt(self, plaintext):
        public_key = RSA.import_key(self.public_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_message = cipher_rsa.encrypt(plaintext)
        return enc_message

class RSADecryptor:
    def __init__(self, private_key):
        self.private_key = private_key

    def decrypt(self, enc_message):
        private_key = RSA.import_key(self.private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        message = cipher_rsa.decrypt(enc_message)
        return message
