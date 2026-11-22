# EXP 6: Break an Affine Cipher using frequency clues
import math
cipher = input("Enter ciphertext: ").upper()
# Most frequent ciphertext B is assumed to represent E; second U is assumed to represent T.
# Solve a*4+b = 1 (B) and a*19+b = 20 (U), modulo 26.
solutions = []
for a in range(26):
    if math.gcd(a, 26) == 1:
        for b in range(26):
            if (a*4+b) % 26 == 1 and (a*19+b) % 26 == 20:
                inv = pow(a, -1, 26)
                plain = "".join(chr(((inv*(ord(c)-65-b)) % 26)+65) if c.isalpha() else c for c in cipher)
                solutions.append((a,b,plain))
if solutions:
    for a,b,p in solutions:
        print(f"a={a}, b={b} -> {p}")
else:
    print("No key satisfies both frequency assumptions. Try other plaintext-letter assumptions.")
