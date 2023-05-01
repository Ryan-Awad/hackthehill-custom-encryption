from hashlib import sha256
from math import ceil

def encrypt(file_path, key) -> None:
    encrypted_bytes = []
    with open(file_path, mode='rb') as file:
        file_bytes = file.read()
        key += key * ceil((len(file_bytes) - len(key)) / len(key))
        for i in range(len(file_bytes)):
            encrypted_bytes.append(file_bytes[i] ^ ord(key[i]))
        
    with open(file_path, mode='wb') as file_w:
        file_w.write(bytes(encrypted_bytes))

def compute_checksum(encrypted_file) -> str:
    with open(encrypted_file, mode='rb') as file:
        encrypted_bytes = file.read()
        return sha256(encrypted_bytes).hexdigest()

def decrypt(file_path, key) -> None:
    encrypt(file_path, key) # the file encryption algorithm is a symmetric-key algorithm

