from Additive_Multiplicative_Affine_Ciphers import affine

def bruteforce(known, locked):
    valid_k2 = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}

    known_plaintext, known_ciphertext = known

    k1_values = [locked['k1']] if locked['k1'] is not None else valid_k2
    k2_values = [locked['k2']] if locked['k2'] is not None else range(26)

    for k1 in k1_values:
        for k2 in k2_values:
            try:
                if affine(known_plaintext, k1, k2) == known_ciphertext:
                    yield k1, k2
            except Exception:
                continue

def crack_affine_bruteforce(ciphertext, known=(), locked={'k1': None, 'k2': None}):
    print(f"\nAttempting brute-force with locked keys: {locked}")
    for k1, k2 in bruteforce(known, locked):
        try:
            decoded = affine(ciphertext, k1, k2, crack=True)
            print(f"K1: {k1}, K2: {k2} -> DECODED TEXT: {decoded}")
        except Exception as e:
            print(f"K1: {k1}, K2: {k2} -> Error: {e}")

crack_affine_bruteforce('XVIEWYWI', ('yes', 'ciw'))
crack_affine_bruteforce('XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS', ('ab', 'gl'))