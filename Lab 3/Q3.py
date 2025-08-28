from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Random import random

def gen_keys(n=2048):
    p = getPrime(n)
    g = random.randint(2, p-1)
    x = random.randint(2, p-2)
    h = pow(g, x, p)
    return (p, g, h), x

def enc(pk, m):
    p, g, h = pk
    k = random.randint(2, p-2)
    c1 = pow(g, k, p)
    c2 = (bytes_to_long(m) * pow(h, k, p)) % p
    return c1, c2

def dec(sk, p, c1, c2):
    s = pow(c1, sk, p)
    m = (c2 * inverse(s, p)) % p
    return long_to_bytes(m)

pk, sk = gen_keys()
msg = b"Confidential Data"
c1, c2 = enc(pk, msg)
dm = dec(sk, pk[0], c1, c2)

print("Plain text:", msg.decode())
print("Ciphertext:", (c1, c2))
print("Decrypted text:", dm.decode())
print("Successful" if dm == msg else "Unsuccessful")
