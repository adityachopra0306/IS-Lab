def vigenere(text, key, crack=False):
    text = text.lower()
    modified = ''
    key = get_vigenere_key(text, key.lower())
    
    k = -1
    for c in text:
        if not c.isalpha():
            modified += c
            continue
        
        k += 1
        text_num = ord(c) - ord('a')
        key_num = ord(key[k]) - ord('a')

        modified += chr((text_num + key_num) % 26 + ord('a')) if not crack else chr((text_num - key_num) % 26 + ord('a'))

    return modified

def get_vigenere_key(text, key):
    key = [c for c in key if c.isalpha()]
    l = len(key)

    return ''.join(key * (len(text)//len(key) + 1))[:len(text)]

def autokey(text, key):
    text = text.lower()
    ciphertext = ''
    key = get_autokey(text, key)
 
    k = -1
    for c in text:
        if not c.isalpha():
            ciphertext += c
            continue
        
        k += 1
        text_num = ord(c) - ord('a')
        key_num = ord(key[k]) - ord('a')
        ciphertext += chr((text_num + key_num) % 26 + ord('a'))

    return ciphertext

def get_autokey(text, key):
    if type(key)==int:
        key = chr(key + ord('a')-1)
    text = ''.join([t for t in text if t.isalpha()])
    return (key + text)[:len(text)]    

def autokey_decrypt(ciphertext, key):
    if type(key)==int:
        key = chr(key + ord('a')-1)
    
    text = ''
    chars = []

    k = -1
    for c in ciphertext:
        if not c.isalpha():
            text += c
            continue
            
        k += 1
        ciphertext_num = ord(c) - ord('a')
        if k < len(key):
            key_num = ord(key[k]) - ord('a')
        else:
            key_num = ord(chars[-1]) - ord('a')
        
        text += chr((ciphertext_num - key_num) % 26 + ord('a'))
        chars += text[-1]
    
    return text

message = "The house is being sold tonight"
key = "dollars"

print("\n VIGENERE:")
a  = vigenere(message, key)
print('ENCRYPTED - ', a)
print('DECRYPTED - ', vigenere(a, key, True))

print("\n AUTOKEY:")
b  = autokey(message, 7)
print('ENCRYPTED - ', b)
print('DECRYPTED - ', autokey_decrypt(b, 7))
