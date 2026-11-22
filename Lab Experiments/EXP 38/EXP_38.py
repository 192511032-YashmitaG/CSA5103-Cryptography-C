# EXP 38: Recover 2x2 Hill cipher key from known pairs
import numpy as np
def matrix_inverse_mod26(M):
    a,b,c,d=map(int,M.flatten())
    det=(a*d-b*c)%26
    if math.gcd(det,26)!=1: return None
    invdet=pow(det,-1,26)
    return (invdet*np.array([[d,-b],[-c,a]]))%26
import math
p=input("Enter 4-letter known plaintext: ").upper()
c=input("Enter matching 4-letter ciphertext: ").upper()
P=np.array([ord(x)-65 for x in p if x.isalpha()][:4]).reshape(2,2)
C=np.array([ord(x)-65 for x in c if x.isalpha()][:4]).reshape(2,2)
Pinv=matrix_inverse_mod26(P)
if Pinv is None: print("Cannot recover key: plaintext matrix is not invertible modulo 26.")
else:
    K=(C@Pinv)%26
    print("Recovered key matrix:")
    print(K)
