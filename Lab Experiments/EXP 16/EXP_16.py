# EXP 16: Top 10 frequency-based candidates for monoalphabetic substitution
from collections import Counter
cipher=input("Enter ciphertext: ").upper()
top_n=int(input("How many candidates? (default 10): ") or "10")
english="ETAOINSHRDLCUMWFGYPBVKJXQZ"
freq=Counter(c for c in cipher if c.isalpha())
order=[c for c,_ in freq.most_common()]
candidates=[]
for shift in range(min(26,max(1,len(order)))):
    mapping={c:english[(i+shift)%26] for i,c in enumerate(order)}
    plain="".join(mapping.get(c,c) for c in cipher)
    candidates.append(plain)
for i,p in enumerate(candidates[:top_n],1):
    print(f"{i}. {p}")
print("These are heuristic frequency candidates, not guaranteed solutions.")
