# des.py
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

class DESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = DES.new(self.key, DES.MODE_ECB)
        length = DES.block_size - (len(plaintext) % DES.block_size)
        padded_plaintext = plaintext + bytes([length]) * length
        return cipher.encrypt(padded_plaintext)

    def decrypt(self, ciphertext):
        cipher = DES.new(self.key, DES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        return decrypted[:-decrypted[-1]]
