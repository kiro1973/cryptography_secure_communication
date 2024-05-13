# ecies.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ECIES:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve

    def encrypt(self, plaintext, recipient_public_key):
        # Generate ephemeral key pair
        private_key = ec.generate_private_key(self.curve, default_backend())
        public_key = private_key.public_key()

        # Derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), recipient_public_key)

        # Derive encryption key and IV using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()
        ).derive(shared_secret)

        derived_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'iv',
            backend=default_backend()
        ).derive(shared_secret)

        # Encrypt plaintext with AES in CBC mode
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        plaintext_padded = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

        # Serialize public key
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Return encrypted ciphertext along with ephemeral public key
        return ciphertext, serialized_public_key

    def decrypt(self, ciphertext, sender_public_key, private_key):
        # Deserialize sender's public key
        sender_public_key = serialization.load_der_public_key(sender_public_key, backend=default_backend())

        # Derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), sender_public_key)

        # Derive encryption key and IV using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()
        ).derive(shared_secret)

        derived_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'iv',
            backend=default_backend()
        ).derive(shared_secret)

        # Decrypt ciphertext with AES in CBC mode
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad decrypted plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

        return plaintext
