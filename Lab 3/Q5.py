import os, time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

def bench():
    sizes = [1024, 10*1024]
    t0 = time.time()
    rsk, rpk = RSA.generate(2048), None
    rpk = rsk.publickey()
    print(f"Key gen: {time.time()-t0:.4f}s\n")

    for s in sizes:
        m, k = os.urandom(s), os.urandom(32)
        t0 = time.time()
        iv = os.urandom(12)
        c = AES.new(k, AES.MODE_GCM, nonce=iv)
        ct, tg = c.encrypt_and_digest(m)
        ek = PKCS1_OAEP.new(rpk, SHA256).encrypt(k)
        print(f"RSA Enc {s//1024}KB: {time.time()-t0:.4f}s")
        t0 = time.time()
        dk = PKCS1_OAEP.new(rsk, SHA256).decrypt(ek)
        pt = AES.new(dk, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tg)
        assert pt == m
        print(f"RSA Dec {s//1024}KB: {time.time()-t0:.4f}s")

    t0 = time.time()
    e1, e2 = ECC.generate(curve='P-256'), ECC.generate(curve='P-256')
    ep1, ep2 = e1.public_key(), e2.public_key()
    print(f"Key gen: {time.time()-t0:.4f}s\n")

    for s in sizes:
        m = os.urandom(s)
        t0 = time.time()
        s1 = (ep2.pointQ * e1.d).x.to_bytes()
        k1 = HKDF(s1, 32, b"", SHA256)
        iv = os.urandom(12)
        c = AES.new(k1, AES.MODE_GCM, nonce=iv)
        ct, tg = c.encrypt_and_digest(m)
        print(f"ECC Enc {s//1024}KB: {time.time()-t0:.4f}s")
        t0 = time.time()
        s2 = (ep1.pointQ * e2.d).x.to_bytes()
        k2 = HKDF(s2, 32, b"", SHA256)
        pt = AES.new(k2, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tg)
        assert pt == m
        print(f"ECC Dec {s//1024}KB: {time.time()-t0:.4f}s")

bench()