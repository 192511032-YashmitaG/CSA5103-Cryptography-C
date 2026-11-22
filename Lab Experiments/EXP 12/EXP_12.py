# EXP 12: Hill Cipher encryption (2x2 key)
import numpy as np
def clean(s): return [ord(c)-65 for c in s.upper() if c.isalpha()]
def hill_encrypt(text, key):
    nums=clean(text)
    if len(nums)%2: nums.append(ord("X")-65)
    out=""
    for i in range(0,len(nums),2):
        v=np.array(nums[i:i+2])
        c=np.dot(key,v)%26
        out += "".join(chr(int(x)+65) for x in c)
    return out
print("Enter four key numbers row-wise (example: 3 3 2 5).")
vals=list(map(int,input("Key: ").split()))
if len(vals)!=4: raise SystemExit("Enter exactly four numbers.")
key=np.array(vals).reshape(2,2)
text=input("Enter plaintext: ")
print("Encrypted text:",hill_encrypt(text,key))
