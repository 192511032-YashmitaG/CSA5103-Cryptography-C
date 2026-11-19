CSA51 – Cryptography and Network Security | Assignment 3 – CO3
Implementation bundle

CONTENTS
- cryptography_assignment3.py: runnable educational demonstrations for Q1–Q7
- evidence/: charts, protocol diagrams and captured console output images

REQUIREMENTS
- Python 3.10 or later
- cryptography package

INSTALL
    python -m pip install cryptography

RUN
    python cryptography_assignment3.py

IMPORTANT SAFETY / SCOPE NOTES
- All keys, messages, tickets and certificates are synthetic.
- Tiny RSA/DSA/ElGamal/Schnorr values and the toy Merkle–Damgård hash are educational only.
- The Kerberos component is a compact simulation, not an interoperable KDC implementation.
- The X.509 section creates a real synthetic root/intermediate/leaf chain and verifies the valid certificate signatures. Negative cases are controlled validation fixtures, not a complete RFC 5280 path-validation engine.
- Q7 performs RSA-PSS signature verification on a synthetic update manifest. Certificate status is supplied as a policy input in the compact demonstration.
- Do not use this source code or its toy parameters to protect real credentials, keys, firmware or production data.

The report distinguishes executed program output from theoretical discussion and design-level estimates.
