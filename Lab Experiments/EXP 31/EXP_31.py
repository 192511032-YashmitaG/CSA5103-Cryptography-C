# EXP 31: Generate CMAC subkeys for 64-bit and 128-bit blocks
def left_shift(block):
    n=int.from_bytes(block,"big")
    bits=len(block)*8
    carry=(n>>(bits-1))&1
    n=(n<<1)&((1<<bits)-1)
    if carry:
        n ^= 0x1B if bits==64 else 0x87
    return n.to_bytes(len(block),"big")
def subkeys(block_bits):
    L=bytes(block_bits//8)  # illustrative placeholder for E_K(0); replace with block-cipher output
    k1=left_shift(L); k2=left_shift(k1)
    return k1,k2
for bits in (64,128):
    k1,k2=subkeys(bits)
    print(f"{bits}-bit block: K1={k1.hex()} K2={k2.hex()}")
print("For real CMAC, L must be the encryption of the all-zero block under the chosen key.")
