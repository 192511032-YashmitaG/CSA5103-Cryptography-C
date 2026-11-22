# EXP 20: ECB vs CBC error propagation demonstration
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key=b"0123456789abcdef"; iv=b"abcdef0123456789"
plain=b"BLOCK-ONE-123456BLOCK-TWO-12345"
plain=pad(plain,16)
ecb=AES.new(key,AES.MODE_ECB); cbc=AES.new(key,AES.MODE_CBC,iv)
ec=bytearray(ecb.encrypt(plain)); cc=bytearray(cbc.encrypt(plain))
# Flip one bit in first ciphertext block
ec[0]^=1; cc[0]^=1
dec_ecb=AES.new(key,AES.MODE_ECB).decrypt(bytes(ec))
dec_cbc=AES.new(key,AES.MODE_CBC,iv).decrypt(bytes(cc))
print("ECB: corruption is confined to the corresponding plaintext block (though that block is garbled).")
print("CBC: P1 is garbled and the same bit position in P2 is flipped; later blocks are not affected.")
print("A bit error in source P1 changes C1 and, due to chaining, affects all subsequent CBC ciphertext blocks.")
print("Original plaintext:",plain)
print("ECB after bit flip:",dec_ecb)
print("CBC after bit flip:",dec_cbc)
