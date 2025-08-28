from DES_utils import IP, FP, E, P, PC1, PC2, SHIFT, SBOX

def permute(block, table):
    return [block[i-1] for i in table]

def left_rotate(lst, n):
    return lst[n:] + lst[:n]

def xor(a, b):
    return [i ^ j for i,j in zip(a,b)]

def sbox_sub(block):
    out = []
    for i in range(8):
        chunk = block[i*6:(i+1)*6]
        row = (chunk[0]<<1) + chunk[5]
        col = (chunk[1]<<3) + (chunk[2]<<2) + (chunk[3]<<1) + chunk[4]
        val = SBOX[i][row][col]
        out.extend([int(x) for x in f"{val:04b}"])
    return out

def generate_keys(key64):
    key56 = permute(key64, PC1)
    C, D = key56[:28], key56[28:]
    keys = []
    for shift in SHIFT:
        C, D = left_rotate(C, shift), left_rotate(D, shift)
        keys.append(permute(C+D, PC2))
    return keys

def feistel(R, K):
    ER = permute(R, E)
    xored = xor(ER, K)
    s_out = sbox_sub(xored)
    return permute(s_out, P)

def des_block(block64, keys, decrypt=False):
    block = permute(block64, IP)
    L, R = block[:32], block[32:]
    for i in range(16):
        k = keys[-(i+1)] if decrypt else keys[i]
        f = feistel(R, k)
        L, R = R, xor(L, f)
    return permute(R+L, FP)

def str_to_bits(s):
    return [int(x) for ch in s.encode('utf-8') for x in f"{ch:08b}"]

def bits_to_str(b):
    return bytes(int("".join(map(str,b[i:i+8])),2) for i in range(0,len(b),8))

def hex_to_bits(h):
    return [int(i) for i in bin(int(h, 16))[2:].zfill(64)]

def bits_to_hex(b):
    return "".join(f"{int(''.join(map(str,b[i:i+8])),2):02X}" for i in range(0,len(b),8))

def hex_to_bits_full(h):
    return [int(x) for ch in bytes.fromhex(h) for x in f"{ch:08b}"]

def pad(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_message(msg, keys):
    data = pad(msg.encode('utf-8'))
    ct_bits_total = []
    for i in range(0, len(data), 8):
        blk = data[i:i+8]
        pt_bits = [int(x) for ch in blk for x in f"{ch:08b}"]
        ct_bits = des_block(pt_bits, keys)
        ct_bits_total.extend(ct_bits)
    return bits_to_hex(ct_bits_total)

def decrypt_message(ct_hex, keys):
    ct_bits = hex_to_bits_full(ct_hex)
    blocks = [ct_bits[i:i+64] for i in range(0, len(ct_bits), 64)]
    out = b""
    for blk in blocks:
        pt_bits = des_block(blk, keys, decrypt=True)
        out += bytes(int("".join(map(str,pt_bits[i:i+8])),2) for i in range(0,64,8))
    return unpad(out).decode('utf-8', errors='ignore')

if __name__ == "__main__":
    key = "A1B2C3D4"
    msg = "Mathematica"

    key_bits = str_to_bits(key)
    keys = generate_keys(key_bits)

    ct_hex = encrypt_message(msg, keys)
    dec_msg = decrypt_message(ct_hex, keys)

    print("Plaintext :", msg)
    print("Ciphertext:", ct_hex)
    print("Decrypted :", dec_msg)