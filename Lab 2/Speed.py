import time
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
import base64

msg = b"Performance Testing of Encryption Algorithms"

des_key = get_random_bytes(8)  
des_iv  = get_random_bytes(8)  
des     = DES.new(des_key, DES.MODE_CBC, des_iv)

pad_len = 8 - len(msg) % 8
msg_padded_des = msg + bytes([pad_len]) * pad_len

aes_key = get_random_bytes(32) 
aes_iv  = get_random_bytes(16) 
aes     = AES.new(aes_key, AES.MODE_CBC, aes_iv)

pad_len = 16 - len(msg) % 16
msg_padded_aes = msg + bytes([pad_len]) * pad_len


# --- Benchmark DES ---
t1 = time.time()
ct_des = des.encrypt(msg_padded_des)
t2 = time.time()
pt_des = DES.new(des_key, DES.MODE_CBC, des_iv).decrypt(ct_des)
t3 = time.time()

print("DES Encryption Time: ", (t2 - t1) * 1e6, "µs")
print("DES Decryption Time: ", (t3 - t2) * 1e6, "µs")

# --- Benchmark AES-256 ---
t4 = time.time()
ct_aes = aes.encrypt(msg_padded_aes)
t5 = time.time()
pt_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv).decrypt(ct_aes)
t6 = time.time()

print("AES-256 Encryption Time: ", (t5 - t4) * 1e6, "µs")
print("AES-256 Decryption Time: ", (t6 - t5) * 1e6, "µs")
