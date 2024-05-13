# key_generator.py
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class KeyGenerator:
    @staticmethod
    def generate_rsa_keys():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        public_key_str = str(public_key, 'utf-8')
    
    # Remove headers, footers, and newlines from public key
        public_key_str = public_key_str.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
    
        print("Public Key:", public_key_str)
        return private_key, public_key

    @staticmethod
    def generate_des_key():
        return get_random_bytes(8) # DES key must be 8 bytes long

    @staticmethod
    def generate_aes_key():
        return get_random_bytes(16) # DES key must be 8 bytes long
