# EXP 37: Frequency attack on monoalphabetic substitution - top 10 candidates
from collections import Counter
cipher=input("Enter ciphertext: ").upper()
top_n=10
english="ETAOINSHRDLCUMWFGYPBVKJXQZ"
freq=Counter(c for c in cipher if c.isalpha())
order=[c for c,_ in freq.most_common()]
results=[]
for offset in range(10):
    mapping={c:english[(i+offset)%26] for i,c in enumerate(order)}
    candidate="".join(mapping.get(c,c) for c in cipher)
    results.append(candidate)
print("Top possible plaintexts:")
for i,text in enumerate(results,1): print(f"{i}. {text}")
