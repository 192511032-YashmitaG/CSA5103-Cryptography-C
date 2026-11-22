# EXP 18: DES key schedule and 28-bit halves
# Requires: pip install pycryptodome
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
key=input("Enter 8-character DES key: ").encode()
if len(key)!=8: raise SystemExit("Key must be 8 bytes.")
# Standard DES key schedule is performed by the DES implementation.
cipher=DES.new(key,DES.MODE_ECB)
block=pad(b"DES key schedule demonstration",8)
print("DES ciphertext:",cipher.encrypt(block).hex())
print("DES PC-1 splits the effective 56-bit key into two 28-bit halves (C and D).")
print("Each round rotates both halves according to the DES shift schedule, then PC-2 selects 48 bits.")
