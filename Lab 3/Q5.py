import os, time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_enc(k, d):
    iv = os.urandom(12)
    e = Cipher(algorithms.AES(k), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = e.update(d) + e.finalize()
    return iv, ct, e.tag

def aes_dec(k, iv, ct, t):
    d = Cipher(algorithms.AES(k), modes.GCM(iv, t), backend=default_backend()).decryptor()
    return d.update(ct) + d.finalize()

def rsa_keys():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return sk, sk.public_key()

def rsa_enc(pub, m):
    return pub.encrypt(m, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_dec(sk, ct):
    return sk.decrypt(ct, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def ecc_keys():
    sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return sk, sk.public_key()

def ecc_key(sk, pub):
    s = sk.exchange(ec.ECDH(), pub)
    return HKDF(hashes.SHA256(), 32, None, b"x", default_backend()).derive(s)

def ecc_enc(sk, pub, m):
    k = ecc_key(sk, pub)
    return aes_enc(k, m)

def ecc_dec(sk, pub, iv, ct, t):
    k = ecc_key(sk, pub)
    return aes_dec(k, iv, ct, t)

def bench():
    sizes = [1024, 10*1024]
    print("RSA 2048...")
    st = time.time()
    rsk, rpk = rsa_keys()
    print(f"Key gen: {time.time()-st:.4f}s\n")

    for s in sizes:
        m = os.urandom(s)
        k = os.urandom(32)
        st = time.time()
        iv, ct, t = aes_enc(k, m)
        ek = rsa_enc(rpk, k)
        print(f"RSA Enc {s//1024}KB: {time.time()-st:.4f}s")
        st = time.time()
        dk = rsa_dec(rsk, ek)
        pt = aes_dec(dk, iv, ct, t)
        print(f"RSA Dec {s//1024}KB: {time.time()-st:.4f}s")
        assert pt == m

    print("\nECC P-256...")
    st = time.time()
    e1, ep1 = ecc_keys()
    e2, ep2 = ecc_keys()
    print(f"Key gen: {time.time()-st:.4f}s\n")

    for s in sizes:
        m = os.urandom(s)
        st = time.time()
        iv, ct, t = ecc_enc(e1, ep2, m)
        print(f"ECC Enc {s//1024}KB: {time.time()-st:.4f}s")
        st = time.time()
        pt = ecc_dec(e2, ep1, iv, ct, t)
        print(f"ECC Dec {s//1024}KB: {time.time()-st:.4f}s")
        assert pt == m

bench()