# EXP 2: Monoalphabetic Substitution Cipher
import string
plain_alphabet = string.ascii_uppercase
cipher_alphabet = input("Enter 26-letter substitution alphabet: ").upper()
text = input("Enter plaintext: ").upper()
if len(cipher_alphabet) != 26 or set(cipher_alphabet) != set(plain_alphabet):
    print("Invalid key: enter every alphabet letter exactly once.")
else:
    table = str.maketrans(plain_alphabet, cipher_alphabet)
    print("Encrypted text:", text.translate(table))
