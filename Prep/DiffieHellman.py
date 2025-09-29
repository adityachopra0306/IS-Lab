from Crypto.Util.number import getPrime
import random
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def dh_keygen(bits=256):
    p = getPrime(bits)
    g = 2                                   # p = random prime of len bits
    return p, g

def dh_generate_private_key(p):
    return random.randint(2, p - 2)                 # priv = random in [2, p-2]

def dh_generate_public_key(g, private_key, p):
    return pow(g, private_key, p)                   # pub = g^priv mod p

def dh_compute_shared_key(other_public, private_key, p):
    return pow(other_public, private_key, p)                    #key = pub2^priv1 = pub1^priv2 = g^(priv1*priv2)  (mod p)   

def derive_key(shared_secret, length=32, info=b"handshake data"):
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),                              # converts int key to 32 byte key
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(secret_bytes)


if __name__ == "__main__":
    p, g = dh_keygen(256)
    print("Public parameters:\n p =", p, "\n g =", g)

    alice_priv = dh_generate_private_key(p)
    alice_pub = dh_generate_public_key(g, alice_priv, p)

    bob_priv = dh_generate_private_key(p)
    bob_pub = dh_generate_public_key(g, bob_priv, p)

    alice_shared = dh_compute_shared_key(bob_pub, alice_priv, p)
    bob_shared = dh_compute_shared_key(alice_pub, bob_priv, p)

    assert alice_shared == bob_shared

    session_key = derive_key(alice_shared, length=32)
    print("\nShared session key (HKDF derived, 256-bit):", session_key.hex())
