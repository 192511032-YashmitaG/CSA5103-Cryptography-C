# EXP 26: RSA risk when reusing the same modulus
import math
p=int(input("Enter small prime p: ") or "11")
q=int(input("Enter small prime q: ") or "13")
e1=int(input("Enter first public exponent: ") or "7")
e2=int(input("Enter second public exponent: ") or "11")
n=p*q; phi=(p-1)*(q-1)
d1=pow(e1,-1,phi); d2=pow(e2,-1,phi)
print("Old public key:",(e1,n))
print("Leaked private exponent d1:",d1)
print("New public key with same modulus:",(e2,n))
print("New private exponent d2:",d2)
print("Factors of reused modulus:",p,q)
print("Security: NOT SAFE — anyone who factors/reuses n can derive private keys for that modulus.")
