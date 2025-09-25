from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def des_ecb_encrypt(key, msg):
    cipher = DES.new(key, DES.MODE_ECB)
    message = pad(msg.encode(), DES.block_size)
    encrypted = cipher.encrypt(message)
    return encrypted.hex()

def des_ecb_decrypt(key, encrypted_hex):
    encrypted = bytes.fromhex(encrypted_hex)
    decipher = DES.new(key, DES.MODE_ECB)
    message = decipher.decrypt(encrypted)
    return unpad(message, DES.block_size).decode()

def des_cbc_encrypt(key, msg):
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    message = pad(msg.encode(), DES.block_size)
    encrypted = cipher.encrypt(message)
    return encrypted.hex(), iv

def des_cbc_decrypt(key, encrypted_hex, iv):
    encrypted = bytes.fromhex(encrypted_hex)
    decipher = DES.new(key, DES.MODE_CBC, iv)
    message = decipher.decrypt(encrypted)
    return unpad(message, DES.block_size).decode()