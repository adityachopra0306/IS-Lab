from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(d):
    n = 16 - len(d) % 16
    return d + bytes([n]) * n

def unpad(d):
    return d[:-d[-1]]

def encrypt(key, msg):
    if isinstance(key, str):
        key = key.encode()
    if len(key) not in (16,24,32):
        raise ValueError("Key must be 16/24/32 bytes for AES-128/192/256")
    iv = get_random_bytes(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    ct = c.encrypt(pad(msg.encode()))
    return iv.hex(), base64.b64encode(ct).decode()

def decrypt(key, iv, ct):
    if isinstance(key, str):
        key = key.encode()
    iv = bytes.fromhex(iv)
    c = AES.new(key, AES.MODE_CBC, iv)
    return unpad(c.decrypt(base64.b64decode(ct))).decode()

if __name__ == "__main__":
    key = "0123456789ABCDEF0123456789ABCDEF"
    msg = "Sensitive Information"
    iv, ct = encrypt(key, msg)
    pt = decrypt(key, iv, ct)
    print("Key:", key)
    print("IV:", iv)
    print("CT:", ct)
    print("PT:", pt)