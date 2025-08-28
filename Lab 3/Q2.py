from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from binascii import hexlify

sk = ECC.generate(curve="P-256")
pk = sk.public_key()

def enc(pk, m):
    ek = ECC.generate(curve="P-256")
    s = int((ek.d * pk.pointQ).x).to_bytes(32, "big")
    k = HKDF(s, 32, None, SHA256)
    iv = get_random_bytes(16)
    c = AES.new(k, AES.MODE_GCM, nonce=iv)
    ct, t = c.encrypt_and_digest(m)
    return ek.public_key(), iv, ct, t

def dec(sk, ek, iv, ct, t):
    s = int((sk.d * ek.pointQ).x).to_bytes(32, "big")
    k = HKDF(s, 32, None, SHA256)
    c = AES.new(k, AES.MODE_GCM, nonce=iv)
    return c.decrypt_and_verify(ct, t)

msg = b"Secure Transactions"
ek, iv, ct, t = enc(pk, msg)
dm = dec(sk, ek, iv, ct, t)

print("Plain text:", msg.decode())
print("Ciphertext:", hexlify(ct).decode())
print("Decrypted text:", dm.decode())
