# EXP 1: Caesar Cipher
text = input("Enter plaintext: ")
k = int(input("Enter key (1-25): "))
if not 1 <= k <= 25:
    print("Invalid key! Enter a key from 1 to 25.")
else:
    result = ""
    for ch in text:
        if ch.isupper():
            result += chr((ord(ch) - 65 + k) % 26 + 65)
        elif ch.islower():
            result += chr((ord(ch) - 97 + k) % 26 + 97)
        else:
            result += ch
    print("Encrypted text:", result)
