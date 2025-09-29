import os
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse

USERS_FILE = "users.json"

# ------------------- User Management -------------------

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def register(username, password):
    users = load_users()
    if username in users:
        raise ValueError("User already exists")

    # Hash password with SHA256
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    # Generate RSA keypair for digital signatures
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()

    users[username] = {"password": hashed_pw, "public_key": public_key, "private_key": private_key}
    save_users(users)

def login(username, password):
    users = load_users()
    if username not in users:
        return False
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    return users[username]["password"] == hashed_pw

# ------------------- DH Key Exchange -------------------

def dhke():
    # Prime (p) and generator (g) — small values for demo only
    p = getPrime(256)
    g = 2

    # Alice’s private and public
    a = int.from_bytes(get_random_bytes(16), "big")
    A = pow(g, a, p)

    # Bob’s private and public
    b = int.from_bytes(get_random_bytes(16), "big")
    B = pow(g, b, p)

    # Shared secrets
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    assert s1 == s2
    shared_key = hashlib.sha256(str(s1).encode()).digest()[:16]  # AES-128 key
    return shared_key

# ------------------- AES + Signature -------------------

def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    data = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size).decode()

def sign_message(private_key_pem, message):
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(public_key_pem, message, signature):
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ------------------- Demo -------------------

if __name__ == "__main__":
    # Register users A and B
    register("Alice", "alicepass")
    register("Bob", "bobpass")

    # Login check
    assert login("Alice", "alicepass")
    assert login("Bob", "bobpass")

    users = load_users()

    # Generate shared AES key using DHKE
    shared_key = dhke()

    # Alice sends a message to Bob
    message = "Hello Bob, this is Alice."
    ciphertext = aes_encrypt(shared_key, message)
    signature = sign_message(users["Alice"]["private_key"], message)

    # Bob receives: decrypt + verify signature
    decrypted = aes_decrypt(shared_key, ciphertext)
    is_valid = verify_signature(users["Alice"]["public_key"], decrypted, signature)

    print("Decrypted message:", decrypted)
    print("Signature valid?  ", is_valid)
