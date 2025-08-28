from Crypto.Cipher import DES3
import base64

def pad(d): return d + bytes([8 - len(d) % 8]) * (8 - len(d) % 8)
def unpad(d): return d[:-d[-1]]

key = bytes.fromhex("123456789BABCDEF1234567800ABCDEFF234577890ABCDEF")
msg = "Classified Text"

cipher = DES3.new(key, DES3.MODE_ECB)
ct = cipher.encrypt(pad(msg.encode()))
print("Ciphertext:", base64.b64encode(ct).decode())

pt = unpad(cipher.decrypt(ct)).decode()
print("Plaintext:", pt)
