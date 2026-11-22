# EXP 13: Known-plaintext attack on a 2x2 Hill cipher
import numpy as np
def inv_mod_matrix(m, mod=26):
    det=int(round(np.linalg.det(m))) % mod
    if det == 0: return None
    try: invdet=pow(det,-1,mod)
    except ValueError: return None
    adj=np.array([[m[1,1],-m[0,1]],[-m[1,0],m[0,0]]],dtype=int)
    return (invdet*adj)%mod
# Provide two plaintext blocks and their matching ciphertext blocks (4 letters each).
p=input("Known plaintext (at least 4 letters): ").upper()
c=input("Matching ciphertext (same length): ").upper()
P=[ord(x)-65 for x in p if x.isalpha()][:4]
C=[ord(x)-65 for x in c if x.isalpha()][:4]
if len(P)!=4 or len(C)!=4: raise SystemExit("Enter at least four alphabetic letters in each.")
Pmat=np.array(P).reshape(2,2); Cmat=np.array(C).reshape(2,2)
Pinv=inv_mod_matrix(Pmat)
if Pinv is None: print("Plaintext matrix is not invertible modulo 26; choose different known pairs.")
else:
    K=(Cmat @ Pinv)%26
    print("Recovered key matrix:")
    print(K)
    print("Verify: (K @ plaintext column) mod 26 gives the ciphertext.")
