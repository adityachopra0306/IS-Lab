import numpy as np

ALPHABET = "abcdefghijklmnopqrstuvwxyz"

def find_inverse(key=1):
    for i in range(1, 26):
        if key * i % 26 == 1:
            return i
    return -1

def check_key(key):
    det = round(np.linalg.det(key)) % 26
    return find_inverse(det) is not None

def process_text(text, n):
    text = ''.join([c.lower() for c in text if c.isalpha()])
    while len(text) % n != 0:
        text += 'x'
    return text

def text_to_numbers(text):
    return [ALPHABET.index(c) for c in text]

def numbers_to_text(nums):
    return ''.join(ALPHABET[n % 26] for n in nums)

def hill(text, key):
    key = np.array(key)
    n = key.shape[0]

    if not check_key(key):
        return "Cannot be encrypted, invalid key"

    text = process_text(text, n)
    nums = text_to_numbers(text)

    ciphertext_nums = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        cblock = key.dot(block) % 26
        ciphertext_nums.extend(cblock)

    return numbers_to_text(ciphertext_nums)

def hill_decrypt(ciphertext, key):
    key = np.array(key)
    n = key.shape[0]

    det = round(np.linalg.det(key)) % 26
    det_inv = find_inverse(det)
    if det_inv is None:
        return "Cannot decrypt, invalid key"

    key_inv = np.round(det_inv * np.linalg.inv(key) * det).astype(int) % 26

    nums = text_to_numbers(ciphertext)
    plaintext_nums = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        pblock = key_inv.dot(block) % 26
        plaintext_nums.extend(pblock)

    return numbers_to_text(plaintext_nums).replace('x', '')

message = 'We live in an insecure world'
key = [
    [3, 3],
    [2, 7]
]

ciphertext = hill(message, key)
print(f'ENCRYPTED - {ciphertext}')
print(f'DECRYPTED - {hill_decrypt(ciphertext, key)}')
