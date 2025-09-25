from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad


def get_ecc_keys():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    return public_key, private_key


def ecc_encrypt(msg, receiver_pub):
    eph_priv = ECC.generate(curve='P-256')
    eph_pub = eph_priv.public_key()

    shared_point = eph_priv.d * receiver_pub.pointQ
    shared_secret_bytes = int(shared_point.x).to_bytes(32, 'big')

    aes_key = HKDF(master=shared_secret_bytes, key_len=32, salt=None, hashmod=SHA256)

    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(msg.encode(), AES.block_size))

    return ciphertext, cipher.iv, eph_pub.export_key(format='DER')


def ecc_decrypt(ciphertext, iv, eph_pub_bytes, receiver_priv):
    eph_pub = ECC.import_key(eph_pub_bytes)

    shared_point = receiver_priv.d * eph_pub.pointQ
    shared_secret_bytes = int(shared_point.x).to_bytes(32, 'big')

    aes_key = HKDF(master=shared_secret_bytes, key_len=32, salt=None, hashmod=SHA256)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

if __name__ == "__main__":
    receiver_pub, receiver_priv = get_ecc_keys()
    print("Receiver public key (PEM):")
    print(receiver_pub.export_key(format="PEM"))
    print("Receiver private key (PEM):")
    print(receiver_priv.export_key(format="PEM"))

    msg = "ECC ECDH encryption test"
    print("\nOriginal message:", msg)

    ciphertext, iv, eph_pub_bytes = ecc_encrypt(msg, receiver_pub)
    print("\nCiphertext (hex):", ciphertext.hex())
    print("IV (hex):", iv.hex())
    print("Ephemeral public key (DER, hex):", eph_pub_bytes.hex())

    plaintext = ecc_decrypt(ciphertext, iv, eph_pub_bytes, receiver_priv)
    print("\nDecrypted plaintext:", plaintext)

    if plaintext == msg:
        print("\nSuccess: plaintext matches original")
    else:
        print("\nFailure: mismatch detected")
