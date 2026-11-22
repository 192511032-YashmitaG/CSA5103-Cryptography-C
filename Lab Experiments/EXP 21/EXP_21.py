# EXP 21: ECB, CBC and CFB modes with padding
# Requires: pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key=b"0123456789abcdef"; iv=b"abcdef0123456789"
text=input("Enter plaintext: ").encode()
data=pad(text,16)
for name,mode in [("ECB",AES.MODE_ECB),("CBC",AES.MODE_CBC),("CFB",AES.MODE_CFB)]:
    cipher=AES.new(key,mode,**({} if mode==AES.MODE_ECB else {"iv":iv}))
    encrypted=cipher.encrypt(data) if mode!=AES.MODE_CFB else cipher.encrypt(text)
    dec=AES.new(key,mode,**({} if mode==AES.MODE_ECB else {"iv":iv}))
    decrypted=dec.decrypt(encrypted)
    if mode!=AES.MODE_CFB: decrypted=unpad(decrypted,16)
    print(f"{name} ciphertext:",encrypted.hex())
    print(f"{name} decrypted:",decrypted.decode(errors="replace"))
print("Padding is needed for block modes when plaintext length is not a multiple of the block size; CFB is a stream-like mode and does not require padding.")
