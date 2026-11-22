# EXP 36: Affine Caesar cipher encryption and decryption
import math
text=input("Enter plaintext: ").upper()
a=int(input("Enter a: ")); b=int(input("Enter b: "))
if math.gcd(a,26)!=1: raise SystemExit("Invalid key: gcd(a,26) must be 1.")
cipher="".join(chr(((a*(ord(c)-65)+b)%26)+65) if c.isalpha() else c for c in text)
inv=pow(a,-1,26)
plain="".join(chr((inv*(ord(c)-65-b)%26)+65) if c.isalpha() else c for c in cipher)
print("Encrypted:",cipher)
print("Decrypted:",plain)
