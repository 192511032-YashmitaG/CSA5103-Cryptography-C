# EXP 33: DES encryption and decryption
# Requires: pip install pycryptodome
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
key=input("Enter 8-character key: ").encode()
text=input("Enter plaintext: ").encode()
if len(key)!=8: raise SystemExit("DES key must be exactly 8 bytes.")
cipher=DES.new(key,DES.MODE_ECB)
encrypted=cipher.encrypt(pad(text,8))
decrypted=unpad(DES.new(key,DES.MODE_ECB).decrypt(encrypted),8)
print("Encrypted (hex):",encrypted.hex())
print("Decrypted:",decrypted.decode(errors="replace"))
