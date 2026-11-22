# EXP 4: Polyalphabetic (Vigenere) Cipher
text = input("Enter plaintext: ").upper()
key = input("Enter key: ").upper()
if not key.isalpha():
    print("Key must contain letters only.")
else:
    result, j = "", 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - 65
            result += chr((ord(ch) - 65 + shift) % 26 + 65)
            j += 1
        else:
            result += ch
    print("Encrypted text:", result)
