from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64

def DES3_encrypt(key, msg):
    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted = cipher.encrypt(pad(msg.encode(), DES3.block_size))
    return encrypted.hex()

def DES3_decrypt(key, encrypted_hex):
    encrypted = bytes.fromhex(encrypted_hex)
    decipher = DES3.new(key, DES3.MODE_ECB)
    message = decipher.decrypt(encrypted)
    return unpad(message, DES3.block_size).decode()