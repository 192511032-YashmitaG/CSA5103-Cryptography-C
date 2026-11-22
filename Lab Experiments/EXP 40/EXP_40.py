# EXP 40: Frequency analysis on monoalphabetic substitution
from collections import Counter
cipher=input("Enter ciphertext: ").upper()
english="ETAOINSHRDLCUMWFGYPBVKJXQZ"
freq=Counter(c for c in cipher if c.isalpha())
ordered=[c for c,_ in freq.most_common()]
mapping={c:english[i] for i,c in enumerate(ordered)}
plaintext="".join(mapping.get(c,c) for c in cipher)
print("Letter frequencies:",freq)
print("Possible plaintext:",plaintext)
print("Mapping:",mapping)
