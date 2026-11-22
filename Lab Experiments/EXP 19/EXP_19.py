# EXP 19: 3DES CBC encryption demonstration
# Requires: pip install pycryptodome
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
key=DES3.adjust_key_parity(get_random_bytes(24))
iv=get_random_bytes(8)
text=input("Enter plaintext: ").encode()
cipher=DES3.new(key,DES3.MODE_CBC,iv)
ct=cipher.encrypt(pad(text,8))
print("IV:",iv.hex())
print("Ciphertext:",ct.hex())
print("Security: 3DES is stronger than single DES but is legacy and has a 64-bit block size.")
print("Performance: 3DES is slower than modern AES; use AES-GCM for new systems.")
