# EXP 22: CBC mode with Simplified DES (S-DES)
# Educational S-DES implementation (8-bit blocks, 10-bit key)
P10=[3,5,2,7,4,10,1,9,8,6]; P8=[6,3,7,4,8,5,10,9]
IP=[2,6,3,1,4,8,5,7]; IP_INV=[4,1,3,5,7,2,8,6]
EP=[4,1,2,3,2,3,4,1]; P4=[2,4,3,1]
S0=[[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
S1=[[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
def perm(x,p): return ''.join(x[i-1] for i in p)
def keys(k):
    x=perm(k,P10); l,r=x[:5],x[5:]
    l=l[1:]+l[:1]; r=r[1:]+r[:1]; k1=perm(l+r,P8)
    l=l[2:]+l[:2]; r=r[2:]+r[:2]; k2=perm(l+r,P8)
    return k1,k2
def xor(a,b): return ''.join('1' if x!=y else '0' for x,y in zip(a,b))
def f(r,k):
    x=xor(perm(r,EP),k)
    def sb(bits,box):
        row=int(bits[0]+bits[3],2); col=int(bits[1:3],2)
        return format(box[row][col],'02b')
    return perm(sb(x[:4],S0)+sb(x[4:],S1),P4)
def enc(block,k,dec=False):
    k1,k2=keys(k); a,b=(k2,k1) if dec else (k1,k2)
    x=perm(block,IP); l,r=x[:4],x[4:]
    l,r=r,xor(l,f(r,a)); l,r=r,xor(l,f(r,b))
    return perm(r+l,IP_INV)
key=input("Enter 10-bit key: ")
iv=input("Enter 8-bit IV: ")
text=input("Enter binary plaintext (multiple of 8 bits): ")
if len(key)!=10 or len(iv)!=8 or len(text)%8 or set(key+iv+text)-set("01"): raise SystemExit("Invalid binary input.")
blocks=[text[i:i+8] for i in range(0,len(text),8)]
prev=iv; cipher=[]
for b in blocks:
    c=enc(xor(b,prev),key); cipher.append(c); prev=c
print("Encrypted blocks:",cipher)
prev=iv; plain=[]
for c in cipher:
    p=xor(enc(c,key,True),prev); plain.append(p); prev=c
print("Decrypted blocks:",plain)
