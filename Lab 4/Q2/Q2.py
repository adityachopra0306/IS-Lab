import os, json, logging
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from datetime import datetime

logging.basicConfig(filename="kms.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

class RabinKey:
    def __init__(self, p, q, n):
        self.p, self.q, self.n = p, q, n

class KMS:
    def __init__(self, size=1024, store="keys.json", aes_key=None):
        self.size = size
        self.store = store
        self.keys = {}
        self.aes_key = aes_key or get_random_bytes(32)
        self._load()

    def gen_key(self):
        def prime():
            while True:
                x = getPrime(self.size // 2)
                if x % 4 == 3: return x
        p, q = prime(), prime()
        while q == p: q = prime()
        return RabinKey(p, q, p*q)

    def enc_priv(self, p, q):
        data = json.dumps({"p": p, "q": q}).encode()
        iv = get_random_bytes(16)
        c = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return iv + c.encrypt(pad(data, AES.block_size))

    def dec_priv(self, blob):
        iv, ct = blob[:16], blob[16:]
        c = AES.new(self.aes_key, AES.MODE_CBC, iv)
        d = unpad(c.decrypt(ct), AES.block_size)
        k = json.loads(d.decode())
        return k["p"], k["q"]

    def add(self, name):
        if name in self.keys: return None
        kp = self.gen_key()
        enc = self.enc_priv(kp.p, kp.q)
        self.keys[name] = {
            "pub": kp.n,
            "priv": enc.hex(),
            "time": datetime.utcnow().isoformat(),
            "revoked": False
        }
        self._save()
        logging.info(f"Added {name}")
        return kp.n, (kp.p, kp.q)

    def get(self, name):
        r = self.keys.get(name)
        if not r or r["revoked"]: return None
        p, q = self.dec_priv(bytes.fromhex(r["priv"]))
        return r["pub"], (p, q)

    def revoke(self, name):
        if name not in self.keys: return False
        self.keys[name]["revoked"] = True
        self._save()
        logging.info(f"Revoked {name}")
        return True

    def renew(self, name):
        if name not in self.keys: return False
        kp = self.gen_key()
        enc = self.enc_priv(kp.p, kp.q)
        self.keys[name].update({
            "pub": kp.n,
            "priv": enc.hex(),
            "time": datetime.utcnow().isoformat(),
            "revoked": False
        })
        self._save()
        logging.info(f"Renewed {name}")
        return True

    def renew_all(self):
        for n in self.keys:
            if not self.keys[n]["revoked"]:
                self.renew(n)
        logging.info("All active renewed")

    def _save(self):
        with open(self.store, "w") as f: json.dump(self.keys, f)

    def _load(self):
        if os.path.exists(self.store):
            with open(self.store, "r") as f: self.keys = json.load(f)

if __name__ == "__main__":
    kms = KMS(1024)

    print("Adding Hospital_A...")
    pub, priv = kms.add("Hospital_A")
    print("Public n:", pub)

    print("Retrieving keys...")
    print("Keys:", kms.get("Hospital_A"))

    print("Revoking...")
    kms.revoke("Hospital_A")
    print("Try get revoked:", kms.get("Hospital_A"))

    print("Renewing...")
    kms.renew("Hospital_A")
    print("Renewed:", kms.get("Hospital_A"))

    kms.renew_all()
