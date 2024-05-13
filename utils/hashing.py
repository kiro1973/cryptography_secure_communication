# hashing.py
from Crypto.Hash import SHA256, MD5

class Hashing:
    @staticmethod
    def sha256_hash(message):
        hash_object = SHA256.new(data=message)
        return hash_object.hexdigest()

    @staticmethod
    def md5_hash(message):
        hash_object = MD5.new(data=message)
        return hash_object.hexdigest()
