from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def set_RSA_keys_manual(n, e, d):
    pub = RSA.construct((n, e))
    priv = RSA.construct((n, e, d))
    return pub, priv


def set_RSA_keys():
    rsa_key = RSA.generate(2048)
    pub = rsa_key.publickey()
    priv = rsa_key
    return pub, priv


def encrypt_rsa(msg, pub):
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(msg.encode())


def decrypt_rsa(ciphertext, priv):
    decipher = PKCS1_OAEP.new(priv)
    return decipher.decrypt(ciphertext).decode()


if __name__ == "__main__":
    pub, priv = set_RSA_keys()
    print("Public key (n, e):")
    print("n =", pub.n)
    print("e =", pub.e)
    print("\nPrivate key d =", priv.d)

    msg = "RSA encryption test"
    print("\nOriginal message:", msg)

    ciphertext = encrypt_rsa(msg, pub)
    print("Ciphertext:", ciphertext.hex())

    plaintext = decrypt_rsa(ciphertext, priv)
    print("Decrypted plaintext:", plaintext)
