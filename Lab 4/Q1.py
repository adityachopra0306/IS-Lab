from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import random

class Subsys:
    def __init__(self, name, p, g=2):
        self.name = name
        self.rsa = RSA.generate(2048)
        self.pub = self.rsa.publickey()
        self.p, self.g = p, g
        self.dh_priv = random.randint(2, p - 2)
        self.dh_pub = pow(g, self.dh_priv, p)

    def rsa_pub(self):
        return self.pub.export_key()

    def dh_pubkey(self):
        return self.dh_pub

    def shared(self, other_pub):
        s = pow(other_pub, self.dh_priv, self.p)
        return SHA256.new(long_to_bytes(s)).digest()

    def rsa_enc(self, data, rpub_bytes):
        rpub = RSA.import_key(rpub_bytes)
        return PKCS1_OAEP.new(rpub).encrypt(data)

    def rsa_dec(self, ct):
        return PKCS1_OAEP.new(self.rsa).decrypt(ct)

    def aes_enc(self, data, k):
        iv = get_random_bytes(16)
        c = AES.new(k, AES.MODE_CBC, iv)
        return iv + c.encrypt(pad(data, AES.block_size))

    def aes_dec(self, ct, k):
        iv, d = ct[:16], ct[16:]
        c = AES.new(k, AES.MODE_CBC, iv)
        return unpad(c.decrypt(d), AES.block_size)

class KMS:
    def __init__(self):
        self.s = {}
        self.p = getPrime(2048)
        self.g = 2

    def add(self, name):
        sub = Subsys(name, self.p, self.g)
        self.s[name] = sub
        print(f"[KMS] Added {name}")
        return sub

    def drop(self, name):
        if name in self.s:
            del self.s[name]
            print(f"[KMS] Revoked {name}")

    def get(self, name):
        return self.s.get(name)

if __name__ == "__main__":
    kms = KMS()
    fin = kms.add("Finance")
    hr = kms.add("HR")

    fk, hk = fin.dh_pubkey(), hr.dh_pubkey()
    fkey, hkey = fin.shared(hk), hr.shared(fk)
    assert fkey == hkey

    msg = b"Confidential Financial Report Q3"
    enc = fin.aes_enc(msg, fkey)
    print(f"[Finance -> HR] Encrypted: {enc.hex()}")
    dec = hr.aes_dec(enc, hkey)
    print(f"[HR] Decrypted: {dec.decode()}")
