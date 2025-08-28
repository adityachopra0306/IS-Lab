def get_key_matrix(key):
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    key = key.lower().replace("j", "i")

    seen = set()
    res = []

    for k in key:
        if k not in seen and k in alphabet:
            res.append(k)
            seen.add(k)

    for c in alphabet:
        if c not in seen:
            res.append(c)
            seen.add(c)

    matrix = [res[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, char):
    for r, row in enumerate(matrix):
        for c, val in enumerate(row):
            if val == char:
                return r, c
    return None

def process_text(text):
    text = text.lower().replace("j", "i")
    text = "".join([c for c in text if c.isalpha()])

    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "x"
        if a == b:
            digraphs.append(a + "x")
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    if len(digraphs[-1]) == 1:
        digraphs[-1] += "x"
    return digraphs

def playfair(text, key):
    dig = process_text(text)
    mat = get_key_matrix(key)

    ciphertext = ''

    for a,b in dig:
        r1, c1 = find_position(mat, a)
        r2, c2 = find_position(mat, b)

        if r1 == r2:
            ciphertext += mat[r1][(c1+1)%5] + mat[r2][(c2+1)%5]
        elif c1 == c2:
            ciphertext += mat[(r1+1)%5][c1] + mat[(r2+1)%5][c2]
        else:
            ciphertext += mat[r1][c2] + mat[r2][c1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    dig = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    mat = get_key_matrix(key)
    text = ''

    for a,b in dig:
        r1, c1 = find_position(mat, a)
        r2, c2 = find_position(mat, b)

        if r1 == r2:
            text += mat[r1][(c1-1)%5] + mat[r2][(c2-1)%5]
        elif c1 == c2:
            text += mat[(r1-1)%5][c1] + mat[(r2-1)%5][c2]
        else:
            text += mat[r1][c2] + mat[r2][c1]

    return text.replace('x', '')

message = 'The key is hidden under the door pad'
key = 'GUIDANCE'

enc = playfair(message, key)
print(f'ENCRYPTED - {enc}')
print(f'DECRYPTED - {playfair_decrypt(enc, key)}')