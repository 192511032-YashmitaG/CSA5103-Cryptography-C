# EXP 10: Display a Playfair 5x5 matrix
key = input("Enter keyword: ").upper()
alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
letters = []
for ch in key.replace("J","I") + alphabet:
    if ch.isalpha() and ch != "J" and ch not in letters:
        letters.append(ch)
matrix = [letters[i:i+5] for i in range(0,25,5)]
print("Playfair Matrix:")
for row in matrix:
    print(" ".join(row))
