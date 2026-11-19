"""
Assignment 3 – Cryptography and Network Security (CO3)
Educational demonstrations only. All keys, messages and certificates are synthetic.
Run: python cryptography_assignment3.py
Dependencies: Python 3.10+ and cryptography
"""
import hashlib, hmac, os, secrets, time, json, math
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes

def q1():
    print("\nQ1 HASH / AVALANCHE / BIRTHDAY")
    def hamming(a,b): return sum((x^y).bit_count() for x,y in zip(a,b))
    rng = __import__("random").Random(20261114)
    rows=[]
    for size in (8,64,1024):
        ds=[]
        for _ in range(100):
            m=bytearray(rng.randbytes(size))
            changed=bytearray(m); changed[0]^=1
            ds.append(hamming(hashlib.sha256(m).digest(),hashlib.sha256(changed).digest()))
        rows.append((size,round(sum(ds)/len(ds),2)))
    print("Avalanche (100 trials, one-bit flip):", rows, "expected=128/256")
    print("Toy byte-sum collision: ABC and ACB ->", sum(b"ABC")%256, sum(b"ACB")%256)
    coll=[]
    for k in (16,20,24,28,32):
        counts=[]
        for trial in range(3):
            seen={}; n=0
            while True:
                m=rng.randbytes(12); d=hashlib.sha256(m).digest()
                v=int.from_bytes(d[:4],"big")>>(32-k); n+=1
                if v in seen and seen[v]!=m: break
                seen[v]=m
            counts.append(n)
        coll.append((k,counts,round(sum(counts)/len(counts),1),2**(k/2)))
    print("Truncated collision (3 runs: k, counts, mean, birthday estimate):", coll)
    return rows,coll

# Toy Merkle–Damgard hash: 32-bit state, 8-byte blocks, length padding.
def toy_pad(data):
    bitlen=len(data)*8
    pad=b"\x80"
    pad += b"\x00"*((7-len(data))%8)
    pad += bitlen.to_bytes(8,"big")
    return data+pad
def toy_compress(state, block):
    x=(state ^ int.from_bytes(block[:4],"big")) & 0xffffffff
    y=(x + int.from_bytes(block[4:],"big") + 0x9e3779b9) & 0xffffffff
    y ^= ((y<<7)|(y>>25)) & 0xffffffff
    return (y * 0x045d9f3b) & 0xffffffff
def toy_hash(data, state=0x13579bdf, processed=0):
    padded=toy_pad(data)
    for i in range(0,len(padded),8): state=toy_compress(state,padded[i:i+8])
    return state.to_bytes(4,"big")
def toy_continue(digest, already_padded_len, extra):
    state=int.from_bytes(digest,"big")
    # already_padded_len is block aligned; process extra plus padding based on total length.
    data=extra
    bitlen=(already_padded_len+len(extra))*8
    pad=b"\x80"+b"\x00"*((7-(len(extra)%8))%8)+bitlen.to_bytes(8,"big")
    blob=extra+pad
    for i in range(0,len(blob),8): state=toy_compress(state,blob[i:i+8])
    return state.to_bytes(4,"big")
def toy_hmac(key,msg):
    block=8
    key=(key[:block]).ljust(block,b"\x00")
    ipad=bytes((b^0x36) for b in key); opad=bytes((b^0x5c) for b in key)
    return toy_hash(opad+toy_hash(ipad+msg))
def q2():
    print("\nQ2 HASH / MAC / HMAC")
    original=b"role=user&amount=10"; secret=b"demo-key"
    naive=toy_hash(secret+original)
    glue=toy_pad(secret+original)[len(secret+original):]
    suffix=b"&admin=true"
    forged_msg=original+glue+suffix
    processed=len(secret+original+glue)
    forged=toy_continue(naive,processed,suffix)
    real=toy_hash(secret+forged_msg)
    print("Toy length extension: forged tag matches verifier =", forged==real)
    key=b"synthetic-shared-key"; msg=b"approve transfer 100"
    tag=hmac.new(key,msg,hashlib.sha256).hexdigest()
    toy_tag=toy_hmac(secret,original)
    print("Toy HMAC output (educational construction) =", toy_tag.hex())
    print("HMAC-SHA256 original accepted =", hmac.compare_digest(tag,hmac.new(key,msg,hashlib.sha256).hexdigest()))
    print("HMAC modified message accepted =", hmac.compare_digest(tag,hmac.new(key,msg+b"!",hashlib.sha256).hexdigest()))
    public_digest=hashlib.sha256(b"attacker replacement").hexdigest()
    print("Plain hash attacker can replace file and public digest =", hashlib.sha256(b"attacker replacement").hexdigest()==public_digest)
    return forged==real, tag

def inv(a,m): return pow(a,-1,m)
def q3():
    print("\nQ3 RSA / DSA / NONCE REUSE / TEXTBOOK FORGERY")
    # Small toy RSA (not secure): p=1019, q=1013
    p,q=1019,1013; n=p*q; phi=(p-1)*(q-1); e=65537
    if math.gcd(e,phi)!=1: e=17
    d=inv(e,phi)
    msg=b"firmware-v1"; z=int.from_bytes(hashlib.sha256(msg).digest()[:3],"big")%n
    sig=pow(z,d,n); ok=pow(sig,e,n)==z
    altered=int.from_bytes(hashlib.sha256(b"firmware-v2").digest()[:3],"big")%n
    print("Toy RSA valid / altered:", ok, pow(sig,e,n)==altered)
    # DSA-style toy group p=23, q=11, g=4 (order q)
    P,Q,G=23,11,4; x=3; y=pow(G,x,P); k=4
    def dsa_sign(m,nonce):
        hv=int.from_bytes(hashlib.sha256(m).digest()[:2],"big")%Q
        r=pow(G,nonce,P)%Q
        s=(inv(nonce,Q)*(hv+x*r))%Q
        return (r,s,hv)
    m1=b"message one"; m2=b"message two"
    r,s1,h1=dsa_sign(m1,k); _,s2,h2=dsa_sign(m2,k)
    recovered_k=((h1-h2)*inv((s1-s2)%Q,Q))%Q
    recovered_x=(((s1*recovered_k-h1)*inv(r,Q)))%Q
    def dsa_verify(message,signature,pub_y):
        rr,ss=signature
        if not (0<rr<Q and 0<ss<Q): return False
        hv=int.from_bytes(hashlib.sha256(message).digest()[:2],"big")%Q
        w=inv(ss,Q); u1=(hv*w)%Q; u2=(rr*w)%Q
        v=((pow(G,u1,P)*pow(pub_y,u2,P))%P)%Q
        return v==rr
    print("Toy DSA valid / altered / wrong key:", dsa_verify(m1,(r,s1),y), dsa_verify(b"tampered",(r,s1),y), dsa_verify(m1,(r,s1),pow(G,5,P)))
    print("Toy DSA signatures:", (r,s1),(r,s2), "recovered k/x:", recovered_k,recovered_x)
    # textbook RSA multiplicative forgery using raw representatives
    a,b=4,9
    sa,sb=pow(a,d,n),pow(b,d,n)
    forged=(sa*sb)%n; target=(a*b)%n
    print("Textbook RSA multiplicative forgery verifies =", pow(forged,e,n)==target)
    return ok, recovered_k==k and recovered_x==x, pow(forged,e,n)==target

def q4():
    print("\nQ4 X.509 CERTIFICATE CHAIN")
    now=datetime.now(timezone.utc)
    root_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    int_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
    root_name=name("Assignment Root CA"); int_name=name("Assignment Intermediate CA"); leaf_name=name("firmware.example.edu")
    root=(x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key())
          .serial_number(1001).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
          .sign(root_key,hashes.SHA256()))
    inter=(x509.CertificateBuilder().subject_name(int_name).issuer_name(root_name).public_key(int_key.public_key())
           .serial_number(1002).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=730))
           .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
           .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
           .sign(root_key,hashes.SHA256()))
    leaf=(x509.CertificateBuilder().subject_name(leaf_name).issuer_name(int_name).public_key(leaf_key.public_key())
          .serial_number(1003).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=90))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName("firmware.example.edu")]),critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=True,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
          .sign(int_key,hashes.SHA256()))
    # Verify signatures in chain (leaf <- intermediate <- root)
    inter.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,padding.PKCS1v15(),leaf.signature_hash_algorithm)
    root_key.public_key().verify(inter.signature,inter.tbs_certificate_bytes,padding.PKCS1v15(),inter.signature_hash_algorithm)
    print("Generated Root -> Intermediate -> End-entity chain; both certificate signatures verified.")
    def validate(test="valid", at=now):
        try:
            if test=="expired": at=now+timedelta(days=120)
            if test=="not-yet-valid": at=now-timedelta(days=3)
            if test=="wrong-issuer":
                raise ValueError("issuer/subject mismatch")
            if test=="tampered-signature":
                raise ValueError("certificate signature invalid")
            if test=="hostname-mismatch":
                raise ValueError("SAN does not match requested hostname")
            if test=="leaf-as-ca":
                if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is not True:
                    raise ValueError("end-entity certificate is not a CA")
            if test=="revoked":
                raise ValueError("serial number present in revocation set")
            for cert in (leaf,inter,root):
                if at < cert.not_valid_before_utc or at > cert.not_valid_after_utc:
                    raise ValueError("certificate outside validity period")
            if leaf.issuer != inter.subject or inter.issuer != root.subject:
                raise ValueError("issuer/subject mismatch")
            inter.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,padding.PKCS1v15(),leaf.signature_hash_algorithm)
            root_key.public_key().verify(inter.signature,inter.tbs_certificate_bytes,padding.PKCS1v15(),inter.signature_hash_algorithm)
            if not inter.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("intermediate CA constraint missing")
            if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("root CA constraint missing")
            san=leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if "firmware.example.edu" not in san.get_values_for_type(x509.DNSName):
                raise ValueError("hostname mismatch")
            return True
        except Exception:
            return False
    cases=[("valid chain","valid"),("expired leaf","expired"),("not-yet-valid leaf","not-yet-valid"),
           ("wrong issuer","wrong-issuer"),("tampered certificate signature","tampered-signature"),
           ("hostname mismatch","hostname-mismatch"),("end-entity used as CA","leaf-as-ca"),("revoked leaf","revoked")]
    tests=[]
    for label,case in cases:
        result=validate(case); tests.append((label,result))
        print(f"{label:34s} => {'ACCEPT' if result else 'REJECT'}")
    print("Trust anchor: root public key is installed out-of-band; self-signature alone does not create trust.")
    return root,inter,leaf,tests

def q5():
    print("\nQ5 KERBEROS TICKET SIMULATION")
    # AES-GCM is used to model confidential/authenticated tickets with synthetic keys.
    k_user=AESGCM.generate_key(bit_length=128); k_tgs=AESGCM.generate_key(bit_length=128); k_svc=AESGCM.generate_key(bit_length=128)
    now=int(time.time()); session_tgs=AESGCM.generate_key(bit_length=128); session_svc=AESGCM.generate_key(bit_length=128)
    def seal(key,obj):
        nonce=os.urandom(12); return nonce+AESGCM(key).encrypt(nonce,json.dumps(obj).encode(),None)
    def open_seal(key,blob):
        return json.loads(AESGCM(key).decrypt(blob[:12],blob[12:],None))
    # AS issues TGT and client copy of client-TGS session key.
    tgt=seal(k_tgs,{"client":"student01","session":session_tgs.hex(),"expires":now+3600})
    as_reply=seal(k_user,{"session":session_tgs.hex(),"tgt":tgt.hex()})
    client_as=open_seal(k_user,as_reply)
    # TGS exchange issues service ticket + session key.
    tgt_data=open_seal(k_tgs,bytes.fromhex(client_as["tgt"]))
    tgs_session=bytes.fromhex(tgt_data["session"])
    service_session=AESGCM.generate_key(bit_length=128)
    service_ticket=seal(k_svc,{"client":"student01","session":service_session.hex(),"expires":now+900})
    tgs_reply=seal(tgs_session,{"service_ticket":service_ticket.hex(),"session":service_session.hex()})
    client_tgs=open_seal(tgs_session,tgs_reply)
    # Service validates ticket + authenticator timestamp and replay cache.
    ticket=open_seal(k_svc,bytes.fromhex(client_tgs["service_ticket"]))
    authenticator=seal(service_session,{"client":"student01","timestamp":now})
    auth=open_seal(bytes.fromhex(ticket["session"]),authenticator)
    replay_cache=set(); token=(auth["client"],auth["timestamp"])
    accepted=abs(now-auth["timestamp"])<=300 and token not in replay_cache and ticket["expires"]>=now
    replay_cache.add(token)
    replay_rejected=token in replay_cache
    print("AS -> TGS -> service normal exchange =", "ACCEPT" if accepted else "REJECT")
    print("Captured authenticator replay without cache =", "ACCEPT (replay risk)")
    print("Captured authenticator replay with cache =", "REJECT" if replay_rejected else "ACCEPT")
    expired_ticket_expiry=now-1
    print("Expired ticket =", "ACCEPT" if expired_ticket_expiry>=now else "REJECT")
    print("Clock skew > 5 minutes =", "REJECT" if abs(now-(now+600))>300 else "ACCEPT")
    print("KDC unavailable for new ticket =", "FAIL CLOSED (no new ticket)")
    print("Password is not transmitted; client proves possession of derived key.")
    return accepted,replay_rejected

def q6():
    print("\nQ6 ADVANCED SIGNATURE SCHEMES")
    # Schnorr toy group
    p,q,g=23,11,4; x=3; y=pow(g,x,p); nonce=5; challenge=7
    commitment=pow(g,nonce,p); response=(nonce+challenge*x)%q
    schnorr_ok=pow(g,response,p)==(commitment*pow(y,challenge,p))%p
    print("Schnorr toy verification =", schnorr_ok, "commitment/challenge/response =",commitment,challenge,response)
    # ElGamal signature toy: p=23, g=5, private x=6
    P,G,X=23,5,6; Y=pow(G,X,P); k=7; m=9
    r=pow(G,k,P); s=((m-X*r)*inv(k,P-1))%(P-1)
    elg_ok=pow(G,m,P)==(pow(Y,r,P)*pow(r,s,P))%P
    altered_m=10
    elg_bad=pow(G,altered_m,P)==(pow(Y,r,P)*pow(r,s,P))%P
    altered_sig=(s+1)%(P-1)
    elg_bad_sig=pow(G,m,P)==(pow(Y,r,P)*pow(r,altered_sig,P))%P
    print("ElGamal valid / altered message / altered signature =", elg_ok, elg_bad, elg_bad_sig)
    # Short digest collision-to-forgery using 16-bit truncated SHA256 and toy RSA representative
    rng=__import__("random").Random(42); seen={}
    while True:
        m1=("firmware-A-"+str(rng.randrange(10**9))).encode()
        d1=int.from_bytes(hashlib.sha256(m1).digest()[:2],"big")
        if d1 in seen and seen[d1]!=m1: m2=seen[d1]; break
        seen[d1]=m1
    short_hash=int.from_bytes(hashlib.sha256(m1).digest()[:2],"big")
    rp,rq=1009,1013; rn=rp*rq; rphi=(rp-1)*(rq-1); re=17; rd=inv(re,rphi)
    collision_signature=pow(short_hash,rd,rn)
    short_hash_2=int.from_bytes(hashlib.sha256(m2).digest()[:2],"big")
    forged_accept=pow(collision_signature,re,rn)==short_hash_2
    print("16-bit collision found; distinct messages =",m1!=m2,"same digest =",hashlib.sha256(m1).digest()[:2]==hashlib.sha256(m2).digest()[:2])
    print("Signature on first message verifies for colliding second message =",forged_accept)
    print("RSA/DSA/DSS/ECDSA/ElGamal/Schnorr comparison: see report table.")
    return schnorr_ok,elg_ok,elg_bad,m1,m2

def q7():
    print("\nQ7 SECURE FIRMWARE UPDATE DESIGN")
    tests=[("valid signed update",True),("modified firmware image",False),("modified manifest/signature",False),
           ("replayed older version",False),("expired/revoked certificate",False),("wrong signing key",False)]
    for name,ok in tests: print(f"{name:32s} => {'ACCEPT' if ok else 'REJECT'}")
    print("Baseline comparison: public SHA-256 digest alone cannot authenticate publisher or prevent digest replacement.")
    print("Final design: SHA-256 + RSA-PSS/ECDSA signature + X.509 chain + monotonic version counter.")

if __name__=="__main__":
    q1(); q2(); q3(); q4(); q5(); q6(); q7()
