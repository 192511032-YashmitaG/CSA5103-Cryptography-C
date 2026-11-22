# EXP 7: Frequency analysis for a simple substitution ciphertext
from collections import Counter
import string
cipher = input("Enter ciphertext: ").upper()
letters = [c for c in cipher if c.isalpha()]
freq = Counter(letters)
english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
cipher_order = [c for c,_ in freq.most_common()]
mapping = {c: english_order[i] for i,c in enumerate(cipher_order)}
plain = "".join(mapping.get(c, c) for c in cipher)
print("Cipher letter frequencies:", freq)
print("Frequency-based candidate:", plain)
print("Note: frequency mapping is a starting guess; substitution puzzles may need manual refinement.")
