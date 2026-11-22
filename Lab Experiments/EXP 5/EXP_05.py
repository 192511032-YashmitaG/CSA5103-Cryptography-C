# EXP 5: Generalized Caesar / Affine Cipher
text = input("Enter plaintext: ").upper()
a = int(input("Enter value of a: "))
b = int(input("Enter value of b: "))
if not 0 <= b < 26 or not any((a*x) % 26 == 1 for x in range(26)):
    print("Invalid values: b must be 0..25 and gcd(a,26) must be 1.")
else:
    result = ""
    for ch in text:
        if ch.isalpha():
            p = ord(ch) - 65
            result += chr(((a*p + b) % 26) + 65)
        else:
            result += ch
    print("Encrypted text:", result)
