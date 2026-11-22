# EXP 39: Frequency attack on additive cipher - top 10 shifts
cipher=input("Enter ciphertext: ").upper()
common_words=["THE","AND","TO","OF","IN","IS","THAT","HELLO","MEET","YOU"]
results=[]
for key in range(26):
    plain="".join(chr((ord(ch)-65-key)%26+65) if ch.isalpha() else ch for ch in cipher)
    score=sum(plain.count(word) for word in common_words)
    results.append((score,key,plain))
for score,key,plain in sorted(results,reverse=True)[:10]:
    print(f"Key {key:2}: {plain} (score={score})")
