"""
Educational Cryptography Assignment 2 — CO2
Run: python3 healthcare_crypto_lab.py

WARNING:
This file uses small toy parameters and educational constructions. It is NOT suitable
for real patient data or production security. The hybrid demo uses a SHA-256-derived
XOR keystream plus HMAC only to illustrate encrypt-then-authenticate; use a vetted
AEAD such as AES-256-GCM or ChaCha20-Poly1305 in real systems.
"""

import hashlib
import hmac
import secrets
import time
from math import gcd

# ---------------- Q1: small educational block-cipher simulations ----------------
# These are deliberately labelled simulations, not standards-compliant DES/Blowfish.
# They let students observe block processing, rounds and mode behaviour safely.

def rotl(x, n, bits=16):
    mask = (1 << bits) - 1
    n %= bits
    return ((x << n) | (x >> (bits - n))) & mask

def toy_feistel_encrypt(block, key, rounds=8):
    """Encrypt one 32-bit block with a toy 16+16 Feistel network."""
    L, R = (block >> 16) & 0xffff, block & 0xffff
    for r in range(rounds):
        rk = (key >> ((r % 4) * 8)) & 0xffff
        F = (rotl((R ^ rk) * 0x45d9, r + 3) ^ (R >> 3)) & 0xffff
        L, R = R, (L ^ F) & 0xffff
    return (L << 16) | R

def toy_feistel_decrypt(block, key, rounds=8):
    L, R = (block >> 16) & 0xffff, block & 0xffff
    for r in reversed(range(rounds)):
        rk = (key >> ((r % 4) * 8)) & 0xffff
        oldR = L
        F = (rotl((oldR ^ rk) * 0x45d9, r + 3) ^ (oldR >> 3)) & 0xffff
        oldL = R ^ F
        L, R = oldL & 0xffff, oldR
    return (L << 16) | R

def toy_3des_encrypt(block, k1, k2, k3):
    return toy_feistel_encrypt(toy_feistel_decrypt(toy_feistel_encrypt(block, k1), k2), k3)

def toy_3des_decrypt(block, k1, k2, k3):
    return toy_feistel_decrypt(toy_feistel_encrypt(toy_feistel_decrypt(block, k3), k2), k1)

def pad_blocks(data, block_bytes=4):
    n = block_bytes - (len(data) % block_bytes)
    return data + bytes([n]) * n

def unpad_blocks(data):
    n = data[-1]
    if n < 1 or n > len(data) or data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid padding")
    return data[:-n]

def toy_block(data4, key):
    return toy_feistel_encrypt(int.from_bytes(data4, "big"), key).to_bytes(4, "big")

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def ecb_encrypt(data, key):
    data = pad_blocks(data)
    return b"".join(toy_block(data[i:i+4], key) for i in range(0, len(data), 4))

def ecb_decrypt(data, key):
    raw = b"".join(toy_feistel_decrypt(int.from_bytes(data[i:i+4], "big"), key).to_bytes(4, "big")
                   for i in range(0, len(data), 4))
    return unpad_blocks(raw)

def cbc_encrypt(data, key, iv):
    data = pad_blocks(data)
    out, prev = [], iv
    for i in range(0, len(data), 4):
        prev = toy_block(xor_bytes(data[i:i+4], prev), key)
        out.append(prev)
    return b"".join(out)

def cbc_decrypt(data, key, iv):
    out, prev = [], iv
    for i in range(0, len(data), 4):
        c = data[i:i+4]
        p = xor_bytes(toy_feistel_decrypt(int.from_bytes(c, "big"), key).to_bytes(4, "big"), prev)
        out.append(p); prev = c
    return unpad_blocks(b"".join(out))

def ctr_crypt(data, key, nonce):
    out = bytearray()
    for counter, i in enumerate(range(0, len(data), 4)):
        stream = toy_block((nonce ^ counter).to_bytes(4, "big"), key)
        chunk = data[i:i+4]
        out.extend(xor_bytes(chunk, stream[:len(chunk)]))
    return bytes(out)


def toy_blowfish_encrypt(block, key, rounds=16):
    """Blowfish-structure simulator: 16-round Feistel, toy keyed F function.
    It does NOT use the standard Blowfish P-array/S-box constants."""
    L, R = (block >> 16) & 0xffff, block & 0xffff
    for r in range(rounds):
        # A deterministic educational substitute for Blowfish's S-box F function.
        k = (key >> ((r % 4) * 8)) & 0xffff
        s0 = ((R * 0x9e37) ^ (R >> 5) ^ k) & 0xffff
        L, R = R, (L ^ rotl(s0, r+1)) & 0xffff
    return (L << 16) | R

def toy_blowfish_decrypt(block, key, rounds=16):
    L, R = (block >> 16) & 0xffff, block & 0xffff
    for r in reversed(range(rounds)):
        oldR = L
        k = (key >> ((r % 4) * 8)) & 0xffff
        s0 = ((oldR * 0x9e37) ^ (oldR >> 5) ^ k) & 0xffff
        oldL = R ^ rotl(s0, r+1)
        L, R = oldL & 0xffff, oldR
    return (L << 16) | R

# RC5-32/12/16: standard RC5 key expansion and block operations.
# Educational implementation of RC5 with 32-bit words, 12 rounds, 16-byte key.
def _u32(x): return x & 0xffffffff
def rc5_expand_key(key, rounds=12, word_bytes=4):
    w = word_bytes * 8
    mod = 1 << w
    c = max(1, (len(key) + word_bytes - 1)//word_bytes)
    L = [0]*c
    for i in reversed(range(len(key))):
        L[i//word_bytes] = _u32((L[i//word_bytes] << 8) + key[i])
    P, Q = (0xB7E15163, 0x9E3779B9) if w == 32 else (0,0)
    t = 2*(rounds+1)
    S=[0]*t; S[0]=P
    for i in range(1,t): S[i]=_u32(S[i-1]+Q)
    A=B=i=j=0
    for _ in range(3*max(t,c)):
        A=S[i]=rotl(_u32(S[i]+A+B),3,32)
        B=L[j]=rotl(_u32(L[j]+A+B),(A+B)%32,32)
        i=(i+1)%t; j=(j+1)%c
    return S

def rc5_encrypt_block(block8, key, rounds=12):
    S=rc5_expand_key(key,rounds)
    A=int.from_bytes(block8[:4],"little"); B=int.from_bytes(block8[4:],"little")
    A=_u32(A+S[0]); B=_u32(B+S[1])
    for i in range(1,rounds+1):
        A=_u32(rotl(A^B,B%32,32)+S[2*i])
        B=_u32(rotl(B^A,A%32,32)+S[2*i+1])
    return A.to_bytes(4,"little")+B.to_bytes(4,"little")

def rc5_decrypt_block(block8, key, rounds=12):
    S=rc5_expand_key(key,rounds)
    A=int.from_bytes(block8[:4],"little"); B=int.from_bytes(block8[4:],"little")
    for i in reversed(range(1,rounds+1)):
        B=rotl(_u32(B-S[2*i+1]),32-(A%32),32)^A
        A=rotl(_u32(A-S[2*i]),32-(B%32),32)^B
    B=_u32(B-S[1]); A=_u32(A-S[0])
    return A.to_bytes(4,"little")+B.to_bytes(4,"little")

# ---------------- Q2: number theory and primality ----------------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

def square_multiply(base, exponent, modulus):
    result, base = 1, base % modulus
    multiplications = 0
    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
            multiplications += 1
        exponent >>= 1
        if exponent:
            base = (base * base) % modulus
            multiplications += 1
    return result, multiplications

def trial_prime(n):
    if n < 2: return False, 0
    steps = 0
    for d in range(2, int(n**0.5) + 1):
        steps += 1
        if n % d == 0: return False, steps
    return True, steps

def fermat_probable_prime(n):
    """Fermat test: vulnerable to Carmichael numbers; returns pass/fail."""
    if n < 4: return n in (2, 3)
    for a in (2,):
        if gcd(a, n) != 1 or pow(a, n-1, n) != 1:
            return False
    return True

def miller_rabin(n, bases=(2, 3, 5, 7, 11)):
    if n in (2, 3): return True
    if n < 2 or n % 2 == 0: return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in bases:
        if a >= n: continue
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = (x*x) % n
            if x == n-1: break
        else:
            return False
    return True

# ---------------- Q3: toy RSA and factorisation ----------------
def rsa_keygen(p, q, e=65537):
    if not trial_prime(p)[0] or not trial_prime(q)[0] or p == q:
        raise ValueError("p and q must be distinct primes")
    n = p*q
    phi = (p-1)*(q-1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    return (e, n), (mod_inverse(e, phi), n), phi

def rsa_encrypt(m, pub):
    e, n = pub
    if not isinstance(m, int) or not (0 <= m < n):
        raise ValueError("Message integer must satisfy 0 <= m < n")
    return pow(m, e, n)

def rsa_decrypt(c, priv):
    d, n = priv
    if not isinstance(c, int) or not (0 <= c < n):
        raise ValueError("Ciphertext must satisfy 0 <= c < n")
    return pow(c, d, n)

def factor_trial(n):
    for d in range(2, int(n**0.5)+1):
        if n % d == 0: return d, n//d
    return None

def factor_fermat(n):
    if n % 2 == 0: return 2, n//2
    a = int(n**0.5)
    if a*a < n: a += 1
    while a < n:
        b2 = a*a - n
        b = int(b2**0.5)
        if b*b == b2: return a-b, a+b
        a += 1
    return None

# ---------------- Q4: Diffie-Hellman and MITM demonstration ----------------
def dh_public(g, private, p):
    return pow(g, private, p)

def dh_shared(peer_public, private, p):
    return pow(peer_public, private, p)

def dh_bruteforce_log(g, target, p):
    value = 1
    for x in range(p):
        if value == target: return x, x+1
        value = (value*g) % p
    return None, p

# ---------------- Q5: toy ECC over a small prime field ----------------
# Curve: y^2 = x^3 + ax + b (mod p); point at infinity is None.
def ecc_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1 == x2 and (y1+y2) % p == 0: return None
    if P != Q:
        slope = ((y2-y1) * mod_inverse((x2-x1) % p, p)) % p
    else:
        if y1 % p == 0: return None
        slope = ((3*x1*x1+a) * mod_inverse((2*y1) % p, p)) % p
    x3 = (slope*slope-x1-x2) % p
    y3 = (slope*(x1-x3)-y1) % p
    return x3,y3

def ecc_mul(k, P, a, p):
    result, addend = None, P
    while k:
        if k & 1: result = ecc_add(result, addend, a, p)
        addend = ecc_add(addend, addend, a, p)
        k >>= 1
    return result

# ---------------- Q6: toy signatures and authenticated hybrid demo ----------------
def rsa_sign_hash(message, private, public):
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    # Reduce only for toy arithmetic; this is NOT RSA-PSS.
    return pow(digest % public[1], private[0], public[1])

def rsa_verify_hash(message, signature, public, private_n=None):
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big") % public[1]
    return pow(signature, public[0], public[1]) == digest

def _keystream(key, nonce, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return out[:length]

def hybrid_demo_encrypt(plaintext, session_key, nonce):
    ciphertext = xor_bytes(plaintext, _keystream(session_key, nonce, len(plaintext)))
    tag = hmac.new(session_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce, ciphertext, tag

def hybrid_demo_decrypt(package, session_key):
    nonce, ciphertext, tag = package
    expected = hmac.new(session_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Authentication failed: data/key/tag tampered")
    return xor_bytes(ciphertext, _keystream(session_key, nonce, len(ciphertext)))

# ---------------- Q7: comparable operation-count experiment ----------------
def benchmark_modexp():
    rows=[]
    for bits in (8, 16, 32, 64, 128):
        exponent=(1 << bits)-159
        start=time.perf_counter()
        _, mults=square_multiply(7, exponent, 1000003)
        elapsed=(time.perf_counter()-start)*1e6
        rows.append((bits, mults, round(elapsed,2)))
    return rows

def run_all():
    print("SYMMETRIC CIPHER AND MODE EXPERIMENTS (educational simulations)")
    key=0x12345678
    block=0x41424344
    c=toy_feistel_encrypt(block,key)
    print("Toy Feistel round-trip:", hex(toy_feistel_decrypt(c,key)) == hex(block))
    msg=b"CLINIC-A|REPORT|CLINIC-A|REPORT"
    ecb=ecb_encrypt(msg,key)
    iv1=b"ABCD"; iv2=b"WXYZ"
    cbc1=cbc_encrypt(msg,key,iv1); cbc2=cbc_encrypt(msg,key,iv2)
    print("ECB repeated-block equality:", ecb[:4] == ecb[16:20])
    print("CBC different-IV ciphertexts differ:", cbc1 != cbc2)
    ctr=ctr_crypt(msg,key,0x10203040)
    print("CTR round-trip:", ctr_crypt(ctr,key,0x10203040)==msg)
    c3=toy_3des_encrypt(block,0x11111111,0x22222222,0x33333333)
    print("Toy 3-stage EDE round-trip:", toy_3des_decrypt(c3,0x11111111,0x22222222,0x33333333)==block)
    cb=toy_blowfish_encrypt(block,key)
    print("Toy Blowfish-structure round-trip:", toy_blowfish_decrypt(cb,key)==block)
    rkey=b"0123456789abcdef"; rb=b"12345678"
    rc=rc5_encrypt_block(rb,rkey)
    print("RC5-32/12/16 round-trip:", rc5_decrypt_block(rc,rkey)==rb)

    print("\\nNUMBER THEORY AND MODULAR ARITHMETIC")
    print("egcd(240,46):", egcd(240,46))
    print("inverse(17 mod 3120):", mod_inverse(17,3120))
    print("7^560 mod 561, square-multiply:", square_multiply(7,560,561))
    for n in (97, 561, 1105, 1729):
        print("candidate",n,"trial",trial_prime(n)[0],"Fermat-pass",fermat_probable_prime(n),"MR",miller_rabin(n))

    print("\\nRSA ENCRYPTION, DECRYPTION AND WEAKNESS TESTS")
    pub,priv,phi=rsa_keygen(61,53,17)
    m=65; ciphertext=rsa_encrypt(m,pub)
    print("p=61 q=53 n=3233 phi=3120 e=17 d=",priv[0])
    print("M=65 C=",ciphertext,"decrypted=",rsa_decrypt(ciphertext,priv))
    print("trial factor n:",factor_trial(pub[1]),"Fermat factor n:",factor_fermat(pub[1]))
    print("deterministic textbook RSA:",rsa_encrypt(m,pub)==rsa_encrypt(m,pub))

    print("\\nDIFFIE–HELLMAN KEY EXCHANGE AND MITM DEMONSTRATION")
    p,g=23,5; a,b=6,15
    A=dh_public(g,a,p); B=dh_public(g,b,p)
    print("A public",A,"B public",B,"shared A/B",dh_shared(B,a,p),dh_shared(A,b,p))
    print("brute-force log for A:",dh_bruteforce_log(g,A,p))
    # MITM: attacker chooses x for A and y for B, producing two different keys.
    x,y=7,9
    attacker_to_A=dh_public(g,x,p); attacker_to_B=dh_public(g,y,p)
    print("MITM public values attacker->A / attacker->B:",attacker_to_A,attacker_to_B)
    print("MITM keys:",dh_shared(A,x,p),dh_shared(B,y,p),"honest key:",dh_shared(B,a,p))

    print("\\nELLIPTIC-CURVE CRYPTOGRAPHY DEMONSTRATION")
    p,a_curve,b_curve=17,2,2
    G=(5,1)  # on y^2=x^3+2x+2 mod 17
    da,db=5,7
    Qa=ecc_mul(da,G,a_curve,p); Qb=ecc_mul(db,G,a_curve,p)
    print("G",G,"QA",Qa,"QB",Qb,"shared",ecc_mul(da,Qb,a_curve,p),ecc_mul(db,Qa,a_curve,p))

    print("\\nDIGITAL SIGNATURES AND HYBRID ENCRYPTION TESTS")
    sig=rsa_sign_hash(b"clinic record",priv,pub)
    print("toy RSA hash-sign verify:",rsa_verify_hash(b"clinic record",sig,pub))
    print("modified message verifies:",rsa_verify_hash(b"modified record",sig,pub))
    package=hybrid_demo_encrypt(b"patient report sample",b"student-demo-key-32-bytes-long!!",b"unique-nonce-01")
    print("hybrid decrypt:",hybrid_demo_decrypt(package,b"student-demo-key-32-bytes-long!!"))
    tampered=(package[0],package[1][:-1]+bytes([package[1][-1]^1]),package[2])
    try: hybrid_demo_decrypt(tampered,b"student-demo-key-32-bytes-long!!")
    except ValueError as ex: print("tamper detected:",ex)

    print("\\nMODULAR EXPONENTIATION PERFORMANCE MEASUREMENTS")
    print("exponent_bits | modular_multiplications | elapsed_microseconds")
    for row in benchmark_modexp(): print(*row,sep=" | ")



# ---------------- Expanded rubric evidence ----------------
def trial_inverse(a, m):
    """Slow reference method: search x until a*x == 1 (mod m)."""
    checks = 0
    for x in range(1, m):
        checks += 1
        if (a*x) % m == 1:
            return x, checks
    raise ValueError("Inverse does not exist")

def naive_modexp(base, exponent, modulus):
    """Reference repeated-multiplication method."""
    result, mults = 1, 0
    for _ in range(exponent):
        result = (result * base) % modulus
        mults += 1
    return result, mults

def cfb_crypt(data, key, iv):
    """Toy 4-byte-segment CFB using the educational block primitive."""
    out, feedback = bytearray(), iv
    for i in range(0, len(data), 4):
        stream = toy_block(feedback, key)
        chunk = data[i:i+4]
        transformed = xor_bytes(chunk, stream[:len(chunk)])
        out.extend(transformed)
        # CFB decryption feeds ciphertext; encryption also feeds output ciphertext.
        feedback = (transformed if len(chunk)==4 else transformed + b"\\x00"*(4-len(chunk))) if False else (
            (transformed if len(chunk)==4 else (transformed + b"\\x00"*(4-len(chunk)))) if False else
            (transformed if len(chunk)==4 else (transformed + b"\\x00"*(4-len(chunk))))
        )
    return bytes(out)

def cfb_encrypt(data, key, iv):
    out, feedback = bytearray(), iv
    for i in range(0, len(data), 4):
        stream = toy_block(feedback, key)
        chunk = data[i:i+4]
        c = xor_bytes(chunk, stream[:len(chunk)])
        out.extend(c)
        feedback = c if len(c)==4 else c + b"\\x00"*(4-len(c))
    return bytes(out)

def cfb_decrypt(data, key, iv):
    out, feedback = bytearray(), iv
    for i in range(0, len(data), 4):
        stream = toy_block(feedback, key)
        chunk = data[i:i+4]
        plain = xor_bytes(chunk, stream[:len(chunk)])
        out.extend(plain)
        feedback = chunk if len(chunk)==4 else chunk + b"\\x00"*(4-len(chunk))
    return bytes(out)

def ofb_crypt(data, key, iv):
    out, state = bytearray(), iv
    for i in range(0, len(data), 4):
        state = toy_block(state, key)
        chunk = data[i:i+4]
        out.extend(xor_bytes(chunk, state[:len(chunk)]))
    return bytes(out)

def benchmark_symmetric_sizes():
    key=0x12345678
    rows=[]
    for size in (64, 256, 1024, 4096):
        msg=(b"CLINIC-RECORD-" * ((size//14)+1))[:size]
        start=time.perf_counter(); enc=ctr_crypt(msg,key,0x10203040)
        elapsed=(time.perf_counter()-start)*1e6
        rows.append((size, (size+3)//4, round(elapsed,2), len(enc)))
    return rows

def run_expanded_rubric_evidence():
    print("\\n=== ADDITIONAL EXPERIMENTAL EVIDENCE ===")
    print("ADDITIONAL MODE TESTS: CFB, OFB AND NONCE REUSE")
    msg=b"REMOTE-CLINIC-REPORT-2026"
    key=0x12345678; iv=b"IV01"
    cfb=cfb_encrypt(msg,key,iv)
    ofb=ofb_crypt(msg,key,iv)
    print("CFB round-trip:", cfb_decrypt(cfb,key,iv)==msg)
    print("OFB round-trip:", ofb_crypt(ofb,key,iv)==msg)
    p1=b"PATIENT-RECORD-ALPHA"; p2=b"PATIENT-RECORD-BETA!"
    nonce=0x01020304
    c1=ctr_crypt(p1,key,nonce); c2=ctr_crypt(p2,key,nonce)
    xor_c=xor_bytes(c1[:min(len(c1),len(c2))],c2[:min(len(c1),len(c2))])
    xor_p=xor_bytes(p1[:len(xor_c)],p2[:len(xor_c)])
    print("CTR nonce reuse: C1 XOR C2 equals P1 XOR P2:",xor_c==xor_p)
    print("Symmetric size table: bytes | toy-block calls | microseconds | ciphertext bytes")
    for row in benchmark_symmetric_sizes(): print(*row,sep=" | ")

    print("\\nMODULAR INVERSE AND EXPONENTIATION COMPARISON")
    inv1,checks=trial_inverse(17,3120)
    inv2=mod_inverse(17,3120)
    naive,naive_count=naive_modexp(7,560,561)
    fast,fast_count=square_multiply(7,560,561)
    print("Trial inverse:",inv1,"candidate checks:",checks)
    print("Extended-Euclid inverse:",inv2)
    print("Naive exponent result/count:",naive,naive_count)
    print("Square-multiply result/count:",fast,fast_count)

    print("\\nRSA BOUNDARY, SMALL-EXPONENT AND FACTORISATION TESTS")
    pub,priv,phi=rsa_keygen(61,53,17)
    for m in (0,1,pub[1]-1):
        c=rsa_encrypt(m,pub); print("boundary",m,"->",c,"->",rsa_decrypt(c,priv))
    for m in (pub[1],-1):
        try: rsa_encrypt(m,pub)
        except ValueError: print("invalid message rejected:",m)
    # textbook RSA with e=3: if m^3 < n, ciphertext equals the ordinary cube.
    small_pub=(3,1000003*1000033)
    small_m=42
    small_c=rsa_encrypt(small_m,small_pub)
    print("small exponent example e=3, M=42, C=M^3 (no modular wrap):",small_c==small_m**3)
    print("small-factor modulus 13*101=1313 factored:",factor_trial(13*101))
    print("close-prime Fermat example 101*107=10807:",factor_fermat(101*107))

    print("\\nLARGER TOY DIFFIE–HELLMAN AND DISCRETE-LOG EXPERIMENT")
    p,g=10007,5
    secret=1234
    pubval=pow(g,secret,p)
    recovered,steps=dh_bruteforce_log(g,pubval,p)
    print("p=10007, g=5, chosen exponent=1234, recovered=",recovered,"trial steps=",steps)
    print("This is a toy group; it is not a secure DH parameter set.")

    print("\\nSIGNATURE AND SESSION-KEY TAMPERING; DIRECT RSA VS HYBRID ESTIMATE")
    pub,priv,_=rsa_keygen(61,53,17)
    msg=b"clinic record manifest"
    sig=rsa_sign_hash(msg,priv,pub)
    print("original signature verifies:",rsa_verify_hash(msg,sig,pub))
    print("modified signature verifies:",rsa_verify_hash(msg,sig^1,pub))
    sk=b"student-demo-key-32-bytes-long!!"
    package=hybrid_demo_encrypt(b"1 KiB sample file".ljust(1024,b"."),sk,b"nonce-for-demo!!")
    wrong_key=b"wrong-session-key-32-bytes-long!"
    try: hybrid_demo_decrypt(package,wrong_key)
    except ValueError: print("wrong session key rejected: True")
    # Toy RSA n=3233 can encode only integer representatives 0..3232.
    # A conservative byte-at-a-time illustration for 1 KiB requires 1024 RSA operations.
    print("toy direct RSA estimate for 1024-byte file at 1 byte/block: 1024 RSA operations")
    print("hybrid key wrapping estimate: 1 public-key key-protection operation + symmetric payload encryption")
    print("Direct RSA ciphertext blocks are modulus-sized; hybrid overhead is one wrapped key plus AEAD nonce/tag.")


def export_tables_and_graphs():
    """Export raw experimental tables as CSV and measured-data graphs as PNG."""
    import csv
    import os
    from pathlib import Path
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nGRAPH EXPORT NOT AVAILABLE: install matplotlib with: python -m pip install matplotlib")
        return

    out_dir = Path("assignment_evidence")
    out_dir.mkdir(exist_ok=True)

    symmetric_rows = benchmark_symmetric_sizes()
    with (out_dir / "symmetric_performance.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["message_size_bytes", "toy_block_calls", "execution_time_microseconds", "ciphertext_bytes"])
        w.writerows(symmetric_rows)

    modexp_rows = benchmark_modexp()
    with (out_dir / "modular_exponentiation.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["exponent_bits", "modular_multiplications", "execution_time_microseconds"])
        w.writerows(modexp_rows)

    prime_candidates = (97, 561, 1105, 1729)
    prime_rows = [(n, trial_prime(n)[0], fermat_probable_prime(n), miller_rabin(n), trial_prime(n)[1]) for n in prime_candidates]
    with (out_dir / "primality_test_results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["candidate", "trial_division_prime", "fermat_pass", "miller_rabin_pass", "trial_division_steps"])
        w.writerows(prime_rows)

    sizes = [r[0] for r in symmetric_rows]
    calls = [r[1] for r in symmetric_rows]
    times = [r[2] for r in symmetric_rows]
    plt.figure(figsize=(8, 5))
    plt.plot(sizes, times, marker="o")
    plt.xlabel("Message size (bytes)")
    plt.ylabel("Execution time (microseconds)")
    plt.title("Message Size vs Symmetric Processing Time")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "graph_message_size_vs_time.png", dpi=180)
    plt.close()

    plt.figure(figsize=(8, 5))
    plt.plot(sizes, calls, marker="o")
    plt.xlabel("Message size (bytes)")
    plt.ylabel("Toy block-cipher calls")
    plt.title("Message Size vs Block-Cipher Operations")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "graph_message_size_vs_operations.png", dpi=180)
    plt.close()

    bits = [r[0] for r in modexp_rows]
    mults = [r[1] for r in modexp_rows]
    plt.figure(figsize=(8, 5))
    plt.plot(bits, mults, marker="o")
    plt.xlabel("Exponent size (bits)")
    plt.ylabel("Modular multiplications")
    plt.title("Exponent Size vs Square-and-Multiply Operations")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "graph_exponent_bits_vs_multiplications.png", dpi=180)
    plt.close()

    print("\nTABLES AND GRAPHS EXPORTED")
    print("Evidence folder:", out_dir.resolve())
    for name in sorted(os.listdir(out_dir)):
        print(" -", name)


if __name__ == "__main__":
    run_all()
    run_expanded_rubric_evidence()
    export_tables_and_graphs()
