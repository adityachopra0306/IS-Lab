from Crypto.Util.number import getPrime
from Crypto.Random import random


def get_elgamal_keys_manual(g, x, p):
    return g, x, p, pow(g, x, p)                        #p - prime modulus, g - generator (primitive root), x-private key [2,p-2], h - g^x modp

def elgamal_encrypt(msg, p, g, h):
    m = int.from_bytes(msg.encode(), 'big')
    if m >= p:
        raise ValueError("Message too large for modulus. Use a bigger prime.")
    y = random.randint(1, p - 2)
    c1 = pow(g, y, p)
    c2 = (m * pow(h, y, p)) % p                             # y - random (EPHEMERAL KEY)
    return (c1, c2)                                     


def elgamal_decrypt(ciphertext, p, x):
    c1, c2 = ciphertext
    s = pow(c1, x, p)                                       #s = c1^x = g^xy (mod p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p                                       #m = c2 * s^-1 (modp)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


if __name__ == "__main__":
    p = getPrime(256)
    g = 2

    x = random.randint(2, p - 2)

    g, x, p, h = get_elgamal_keys_manual(g, x, p)

    print("Public key (p, g, h):")
    print("p =", p)
    print("g =", g)
    print("h =", h)
    print("Private key x =", x)

    msg = "ElGamal encryption test"
    ciphertext = elgamal_encrypt(msg, p, g, h)
    print("\nCiphertext:", ciphertext)

    plaintext = elgamal_decrypt(ciphertext, p, x)
    print("Decrypted plaintext:", plaintext)
