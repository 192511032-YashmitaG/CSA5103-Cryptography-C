# EXP 9: Decrypt a Playfair-coded historical message
# Enter the ciphertext shown in your lab sheet; the sheet's image contains the message.
def matrix_for(key):
    alphabet="ABCDEFGHIKLMNOPQRSTUVWXYZ"; s=[]
    for c in key.upper().replace("J","I")+alphabet:
        if c.isalpha() and c!="J" and c not in s: s.append(c)
    return [s[i:i+5] for i in range(0,25,5)]
def decrypt(cipher,key):
    m=matrix_for(key); pos={m[r][c]:(r,c) for r in range(5) for c in range(5)}
    text="".join(c for c in cipher.upper().replace("J","I") if c.isalpha())
    if len(text)%2: raise ValueError("Ciphertext must contain an even number of letters.")
    out=""
    for i in range(0,len(text),2):
        (r1,c1),(r2,c2)=pos[text[i]],pos[text[i+1]]
        if r1==r2: out+=m[r1][(c1-1)%5]+m[r2][(c2-1)%5]
        elif c1==c2: out+=m[(r1-1)%5][c1]+m[(r2-1)%5][c2]
        else: out+=m[r1][c2]+m[r2][c1]
    return out
key=input("Enter Playfair keyword: ")
cipher=input("Enter the PT-109 ciphertext from the lab sheet: ")
print("Decrypted text (remove filler X where appropriate):",decrypt(cipher,key))
