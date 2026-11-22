# EXP 25: Common factor reveals an RSA modulus factor
import math
n=int(input("Enter RSA modulus n: "))
m=int(input("Enter plaintext block m: "))
g=math.gcd(m,n)
print("gcd(m,n) =",g)
if 1 < g < n:
    print("A non-trivial factor was found:",g,"and",n//g)
else:
    print("No non-trivial factor revealed for this plaintext block.")
