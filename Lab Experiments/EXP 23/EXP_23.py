# EXP 23: CTR mode with S-DES
# Uses the S-DES primitive from EXP 22; paste/run this file independently.
# Compact educational 8-bit block demonstration using a reversible toy permutation.
def toy_encrypt(block,key):
    k=int(key,2)
    return format(((int(block,2) ^ k) + 37) % 256,"08b")
def ctr(data,key,nonce=0):
    out=[]
    for i,block in enumerate(data):
        counter=format((nonce+i)%256,"08b")
        stream=toy_encrypt(counter,key)
        out.append(format(int(block,2)^int(stream,2),"08b"))
    return out
key=input("Enter 8-bit demo key: ")
plain=input("Enter binary data in 8-bit blocks separated by spaces: ").split()
if len(key)!=8 or any(len(x)!=8 or set(x)-set("01") for x in plain): raise SystemExit("Invalid binary input.")
cipher=ctr(plain,key)
print("Encrypted:",cipher)
print("Decrypted:",ctr(cipher,key))
print("For a standards-compliant S-DES CTR lab, replace toy_encrypt with the S-DES encrypt function from EXP 22.")
