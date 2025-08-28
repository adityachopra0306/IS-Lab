import os, time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def make_file(name, mb):
    with open(name, "wb") as f:
        f.write(os.urandom(mb * 1024 * 1024))

def aes_enc(d, k):
    c = AES.new(k, AES.MODE_GCM)
    ct, t = c.encrypt_and_digest(d)
    return c.nonce, ct, t

def aes_dec(n, ct, t, k):
    c = AES.new(k, AES.MODE_GCM, nonce=n)
    return c.decrypt_and_verify(ct, t)

def rsa_enc(k, pub):
    return PKCS1_OAEP.new(pub).encrypt(k)

def rsa_dec(ct, priv):
    return PKCS1_OAEP.new(priv).decrypt(ct)

def ecc_enc(k, pub):
    ek = ECC.generate(curve="P-256")
    s = int((ek.d * pub.pointQ).x).to_bytes(32, "big")
    dk = HKDF(s, 32, b"", SHA256)
    n, ct, t = aes_enc(k, dk)
    return ek.public_key(), n, ct, t

def ecc_dec(epub, n, ct, t, priv):
    s = int((priv.d * epub.pointQ).x).to_bytes(32, "big")
    dk = HKDF(s, 32, b"", SHA256)
    return aes_dec(n, ct, t, dk)

def bench(name, m):
    data = open(name, "rb").read()
    k = get_random_bytes(32)

    st = time.time()
    n, ct, t = aes_enc(data, k)
    et = time.time() - st

    if m == "RSA":
        st = time.time()
        r = RSA.generate(2048)
        ek = rsa_enc(k, r.publickey())
        dk = rsa_dec(ek, r)
        dt = time.time() - st
    elif m == "ECC":
        st = time.time()
        e = ECC.generate(curve="P-256")
        ep, n2, ct2, t2 = ecc_enc(k, e.public_key())
        dk = ecc_dec(ep, n2, ct2, t2, e)
        dt = time.time() - st
    else:
        raise ValueError

    assert dk == k
    print(f"\n--- {m} ---")
    print(f"Size: {len(data)/(1024*1024):.2f} MB")
    print(f"AES Enc Time: {et:.4f}s")
    print(f"{m} Key Time: {dt:.4f}s")
    print(f"Key Size: {len(dk)} bytes")
    print("Verified")

make_file("f1.bin", 1)
make_file("f10.bin", 10)

bench("f1.bin", "RSA")
bench("f10.bin", "RSA")
bench("f1.bin", "ECC")
bench("f10.bin", "ECC")
