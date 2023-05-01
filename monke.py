# Monke Cipher - A cipher algorithm we came up with during the hackathon
# XOR(
#   XOR(<DATA>, KEY1) + 
#   \x00 + 
#   XOR(MD5(<DATA>), KEY2),
# KEY3)

from hashlib import md5
from math import ceil
from secrets import token_hex

def xor(msg, key) -> 'list[int]':
    key += key * ceil((len(msg) - len(key)) / len(key))
    out = []
    for i in range(len(msg)):
        out.append(msg[i] ^ ord(key[i]))
    return out

def hex_digest(cipher) -> str:
    hexdigest_output = ''
    for c in cipher:
        hexdigest = format(c, 'x')
        hexdigest_output += '0'*(len(hexdigest) == 1) + hexdigest
    return hexdigest_output

def hex_digest2ascii(digest) -> 'list[int]':
    asciis = []
    curr = ''
    for i in range(len(digest)):
        if i != 0 and i % 2 == 0:
            asciis.append(int(curr, 16))
            curr = ''
        curr += digest[i]
    asciis.append(int(curr, 16))
    return asciis

def compute_checksum(msg):
    return md5(msg.encode('utf-8')).hexdigest()

def encrypt(msg, key1, key2, key3) -> str:
    msg_ascii = [ord(x) for x in msg]
    cipher1 = xor(msg_ascii, key1)

    checksum = compute_checksum(msg)
    checksum = [ord(x) for x in checksum]

    checksum_cipher = xor(checksum, key2)

    SEPARATOR = '\x00'

    final_cipher = cipher1 + [ord(SEPARATOR)] + checksum_cipher
    final_cipher = xor(final_cipher, key3)
    final_cipher = hex_digest(final_cipher)
    return final_cipher

def decrypt(cipher, key1, key2, key3):
    final_cipher = hex_digest2ascii(cipher)
    final_cipher = xor(final_cipher, key3)

    separator_position = final_cipher.index(0)
    cipher1 = final_cipher[:separator_position]
    checksum_cipher = final_cipher[separator_position+1:]

    received_checksum = xor(checksum_cipher, key2)
    received_checksum = ''.join([chr(x) for x in received_checksum])

    received_data = xor(cipher1, key1)
    received_data = ''.join([chr(x) for x in received_data])

    valid_checksum = False
    calculated_checksum = compute_checksum(received_data)
    if (calculated_checksum == received_checksum):
        valid_checksum = True
    
    return received_data, valid_checksum

if __name__ == "__main__":
    # 32/2 because each byte is composed of 2 characters, ex: 2e. So len(token_hex(32)) = 64 -> Therefore len(token_hex(32/2)) = 32
    KEY1 = token_hex(32//2)
    KEY2 = token_hex(32//2)
    KEY3 = token_hex(32//2)

    msg = input("Input plaintext string: ")

    print(f"""
    ---[ The Monke Cipher ]---

    Keys generated:
    Key 1: {KEY1} ->\t Length: {len(KEY1)} bytes = {len(KEY1) * 8} bits
    Key 2: {KEY2} ->\t Length: {len(KEY2)} bytes = {len(KEY2) * 8} bits
    Key 3: {KEY3} ->\t Length: {len(KEY3)} bytes = {len(KEY3) * 8} bits
    """)
    cipher = encrypt(msg, KEY1, KEY2, KEY3)
    print("Cipher:", cipher)

    decrypted_data, valid_checksum = decrypt(cipher, KEY1, KEY2, KEY3)
    print(f"\n\nDECRYPTION:\nDecrypted data: {decrypted_data}\nVALID CHECKSUM? -> {valid_checksum}")
