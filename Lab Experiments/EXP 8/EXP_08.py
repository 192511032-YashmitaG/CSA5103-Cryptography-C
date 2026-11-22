# EXP 8: Monoalphabetic Cipher with a memorized permutation
import string
plain_alpha = string.ascii_uppercase
key = input("Enter 26-letter cipher alphabet: ").upper()
text = input("Enter plaintext: ").upper()
if len(key) != 26 or set(key) != set(plain_alpha):
    print("Invalid cipher alphabet.")
else:
    enc = text.translate(str.maketrans(plain_alpha, key))
    dec = enc.translate(str.maketrans(key, plain_alpha))
    print("Cipher alphabet:", key)
    print("Encrypted text:", enc)
    print("Decrypted text:", dec)
