from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from sympy import mod_inverse

def rabin_keygen(bits=256):
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits)
        if q % 4 == 3 and q != p:           
            break                           #p, q - 2 random primes, p=q=3 (mod 4)
    return p * q, p, q                      #n = pq

def rabin_encrypt(msg, n):
    m = bytes_to_long(msg.encode())  
    if m >= n:
        raise ValueError("Message too large for the modulus")
    c = pow(m, 2, n)                                                    #c = M^2 (modn)
    return c

def rabin_decrypt(c, p, q):
    r_p = pow(c, (p+1)//4, p)
    r_q = pow(c, (q+1)//4, q)

    y_p = mod_inverse(p, q)
    y_q = mod_inverse(q, p)           

    n = p*q
    m1 = (r_p * q * y_q + r_q * p * y_p) % n
    m2 = (r_p * q * y_q - r_q * p * y_p) % n
    m3 = (-r_p * q * y_q + r_q * p * y_p) % n
    m4 = (-r_p * q * y_q - r_q * p * y_p) % n

    candidates = []
    for m in [m1, m2, m3, m4]:
        try:
            candidates.append(long_to_bytes(m).decode())
        except:
            continue
    return candidates

if __name__ == "__main__":
    msg = "Confidential Data"
    n, p, q = rabin_keygen(256)
    ciphertext = rabin_encrypt(msg, n)
    print("Ciphertext:", ciphertext)

    plaintexts = rabin_decrypt(ciphertext, p, q)
    print("Possible plaintexts:", plaintexts)
