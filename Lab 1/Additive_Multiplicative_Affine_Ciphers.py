def caesar(text, key=0, crack=False):
    text = text.lower()
    modified = ''
    for c in text:
        if c.isalpha():
            char_num = ord(c) - ord('a')
            modified += chr((char_num + key) % 26 + ord('a')) if not crack else chr((char_num - key) % 26 + ord('a'))
        else:
            modified += c
    return modified

def find_inverse(key=1):
    for i in range(1, 26):
        if key * i % 26 == 1:
            return i
    return -1

def multiplicative(text, key=1, crack=False):
    valid_keys = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}

    if key not in valid_keys:
        return "ERROR: Invalid key"

    text = text.lower()
    modified = ''
    inv = 1
    if crack:
        inv = find_inverse(key)
        if inv == -1:
            return "ERROR: No multiplicative inverse exists"

    for c in text:
        if c.isalpha():
            char_num = ord(c) - ord('a')
            multiplier = key if not crack else inv
            modified += chr(char_num * multiplier % 26 + ord('a'))
        else:
            modified += c
    return modified



def affine(text, k1=1, k2=0, crack=False):
    if not crack:
        return caesar(multiplicative(text, k1), k2)
    return multiplicative(caesar(text, k2, True), k1, True)

if __name__ == '__main__':
    message = "I am learning information security"

    print("\n ADDITIVE CIPHER:")
    a = caesar(message, 20)
    print('ENCRYPTED -', a)
    print('DECRYPTED -', caesar(a, 20, True))

    print("\n MULTIPLICATIVE CIPHER:")
    b = multiplicative(message, 15)
    print('ENCRYPTED -', b)
    print('DECRYPTED -', multiplicative(b, 15, True))

    print("\n AFFINE CIPHER:")
    c = affine(message, 15, 20)
    print('ENCRYPTED -', c)
    print('DECRYPTED -', affine(c, 15, 20, True))