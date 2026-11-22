# EXP 3: Playfair Cipher Encryption
def make_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    chars = []
    for ch in (key.upper().replace("J", "I") + alphabet):
        if ch.isalpha() and ch != "J" and ch not in chars:
            chars.append(ch)
    return [chars[i:i+5] for i in range(0, 25, 5)]

def prepare(text):
    text = "".join(c for c in text.upper().replace("J", "I") if c.isalpha())
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        if i + 1 == len(text):
            b, i = "X", i + 1
        elif text[i+1] == a:
            b, i = "X", i + 1
        else:
            b, i = text[i+1], i + 2
        pairs.append(a+b)
    return pairs

def encrypt(text, key):
    m = make_matrix(key)
    pos = {m[r][c]: (r, c) for r in range(5) for c in range(5)}
    out = ""
    for pair in prepare(text):
        (r1,c1),(r2,c2) = pos[pair[0]],pos[pair[1]]
        if r1 == r2:
            out += m[r1][(c1+1)%5] + m[r2][(c2+1)%5]
        elif c1 == c2:
            out += m[(r1+1)%5][c1] + m[(r2+1)%5][c2]
        else:
            out += m[r1][c2] + m[r2][c1]
    return out

key = input("Enter keyword: ")
text = input("Enter plaintext: ")
print("Encrypted text:", encrypt(text, key))
