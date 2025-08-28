from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

rsa_key = RSA.generate(2048)
pub = rsa_key.publickey()
priv = rsa_key

def encrypt_rsa(msg, pk):
    enc_cipher = PKCS1_OAEP.new(pk)
    return enc_cipher.encrypt(msg.encode("utf-8"))

def decrypt_rsa(enc, sk):
    dec_cipher = PKCS1_OAEP.new(sk)
    return dec_cipher.decrypt(enc).decode("utf-8")

text = "Asymmetric Encryption"
print("Original message:", text)

enc_text = encrypt_rsa(text, pub)
print("Encrypted message (hex):", enc_text.hex())

dec_text = decrypt_rsa(enc_text, priv)
print("Decrypted message:", dec_text)
