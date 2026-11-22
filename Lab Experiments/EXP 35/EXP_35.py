# EXP 35: One-time-pad version of Vigenere cipher
import secrets, string
text=input("Enter plaintext: ").upper()
letters=[c for c in text if c.isalpha()]
key="".join(secrets.choice(string.ascii_uppercase) for _ in letters)
cipher=[]; j=0
for ch in text:
    if ch.isalpha():
        cipher.append(chr((ord(ch)-65 + ord(key[j])-65)%26+65)); j+=1
    else: cipher.append(ch)
cipher="".join(cipher)
print("Random one-time key:",key)
print("Ciphertext:",cipher)
# Decrypt to demonstrate
plain=[]; j=0
for ch in cipher:
    if ch.isalpha():
        plain.append(chr((ord(ch)-65 - (ord(key[j])-65))%26+65)); j+=1
    else: plain.append(ch)
print("Decrypted text:","".join(plain))
print("Keep the key secret and never reuse it.")
