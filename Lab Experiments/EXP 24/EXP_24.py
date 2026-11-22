# EXP 24: Find RSA private key for e=31, n=3599
import math
n=3599; e=31
p=q=None
for candidate in range(2,math.isqrt(n)+1):
    if n%candidate==0:
        p,q=candidate,n//candidate; break
if p is None: raise SystemExit("n is prime; cannot factor.")
phi=(p-1)*(q-1)
d=pow(e,-1,phi)
print("p =",p,"q =",q)
print("n =",n)
print("phi(n) =",phi)
print("Public key =", (e,n))
print("Private key =", (d,n))
