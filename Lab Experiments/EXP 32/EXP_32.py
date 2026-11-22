# EXP 32: Compare RSA and DSA digital signatures
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
message=input("Enter message: ").encode()
# RSA signature
rsa_key=RSA.generate(2048)
h=SHA256.new(message)
rsa_sig=pkcs1_15.new(rsa_key).sign(h)
pkcs1_15.new(rsa_key.publickey()).verify(SHA256.new(message),rsa_sig)
# DSA signature
dsa_key=DSA.generate(2048)
dsa_sig=DSS.new(dsa_key,"fips-186-3").sign(SHA256.new(message))
DSS.new(dsa_key.publickey(),"fips-186-3").verify(SHA256.new(message),dsa_sig)
print("RSA signature verified: True")
print("DSA signature verified: True")
print("Both provide authenticity and integrity; their key generation and signature formats differ.")
