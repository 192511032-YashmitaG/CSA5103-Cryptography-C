# EXP 17: DES decryption using round keys in reverse order
# Requires: pip install pycryptodome
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
key=input("Enter 8-character DES key: ").encode()
ciphertext_hex=input("Enter ciphertext hex (or press Enter to encrypt a demo): ").strip()
if len(key)!=8: raise SystemExit("DES key must be exactly 8 bytes.")
if ciphertext_hex:
    data=bytes.fromhex(ciphertext_hex)
    cipher=DES.new(key,DES.MODE_ECB)
    print("Decrypted:",unpad(cipher.decrypt(data),8).decode(errors="replace"))
else:
    msg=input("Enter plaintext: ").encode()
    c=DES.new(key,DES.MODE_ECB); encrypted=c.encrypt(pad(msg,8))
    d=DES.new(key,DES.MODE_ECB)
    print("Ciphertext hex:",encrypted.hex())
    print("Decrypted:",unpad(d.decrypt(encrypted),8).decode())
print("DES decryption applies the 16 round subkeys in reverse order internally.")
