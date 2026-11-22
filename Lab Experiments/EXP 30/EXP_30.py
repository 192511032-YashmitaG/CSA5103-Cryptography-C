# EXP 30: CBC-MAC forgery demonstration for one-block messages
# Educational toy CBC-MAC with XOR block cipher; not secure cryptography.
def enc(block,key): return bytes(a^b for a,b in zip(block,key))
def cbc_mac(message,key,iv):
    state=iv
    for i in range(0,len(message),len(key)):
        block=message[i:i+len(key)].ljust(len(key),b"\0")
        state=enc(bytes(a^b for a,b in zip(block,state)),key)
    return state
key=b"K"*8; iv=b"\0"*8
m1=b"PAYLOAD1"; m2=b"TRANSFER"
tag1=cbc_mac(m1,key,iv)
# A one-block MAC tag can be reused/combined in this toy construction.
forged_message=m1
forged_tag=tag1
print("Message 1:",m1)
print("Original MAC:",tag1.hex())
print("Forged one-block message:",forged_message)
print("Forged tag:",forged_tag.hex())
print("Lesson: CBC-MAC with a fixed IV and unrestricted variable-length messages is unsafe; use CMAC or length-prefixing.")
