# EXP 15: Frequency attack on an additive cipher
from collections import Counter
cipher=input("Enter ciphertext: ").upper()
freq=Counter(c for c in cipher if c.isalpha())
most=freq.most_common(1)[0][0] if freq else None
print("Cipher letter frequencies:",freq)
if most:
    # Try all 26 shifts and rank by common English words.
    words=("THE","AND","TO","OF","IN","IS","THAT","HELLO","MEET")
    candidates=[]
    for k in range(26):
        p="".join(chr((ord(c)-65-k)%26+65) if c.isalpha() else c for c in cipher)
        score=sum(p.count(w) for w in words)
        candidates.append((score,k,p))
    for score,k,p in sorted(candidates,reverse=True)[:10]:
        print(f"Key {k:2}: {p}  [score={score}]")
