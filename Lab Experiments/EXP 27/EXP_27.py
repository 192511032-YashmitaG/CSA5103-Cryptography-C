# EXP 27: Dictionary attack on RSA with one character per block
# Small textbook RSA values are intentionally used for demonstration only.
p,q,e=61,53,17
n=p*q; phi=(p-1)*(q-1); d=pow(e,-1,phi)
message=input("Enter message: ").upper()
cipher=[pow(ord(ch),e,n) for ch in message]
lookup={pow(i,e,n):chr(i) for i in range(32,127)}
recovered="".join(lookup.get(c,"?") for c in cipher)
print("RSA public key:",(e,n))
print("Encrypted blocks:",cipher)
print("Attacker recovered:",recovered)
print("Encrypting each character separately leaks patterns and enables dictionary lookup.")
