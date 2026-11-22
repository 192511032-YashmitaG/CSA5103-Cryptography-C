# EXP 34: ECB, CBC and CFB modes
# Requires: pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key=b"0123456789abcdef"; iv=b"abcdef0123456789"
text=input("Enter plaintext: ").encode()
for name,mode in [("ECB",AES.MODE_ECB),("CBC",AES.MODE_CBC),("CFB",AES.MODE_CFB)]:
    if mode==AES.MODE_CFB:
        enc=AES.new(key,mode,iv=iv).encrypt(text)
        dec=AES.new(key,mode,iv=iv).decrypt(enc)
    else:
        data=pad(text,16)
        enc=AES.new(key,mode,**({} if mode==AES.MODE_ECB else {"iv":iv})).encrypt(data)
        dec=AES.new(key,mode,**({} if mode==AES.MODE_ECB else {"iv":iv})).decrypt(enc)
        dec=unpad(dec,16)
    print(name,"ciphertext:",enc.hex())
    print(name,"decrypted:",dec.decode(errors="replace"))
print("Padding is required by block modes when the message is not a whole number of blocks; CFB does not require padding.")
