# CSA51 Cryptography & Network Security – Assignment 4 (CO4)

## Contents
- `src/assignment4_co4.py`: six-task educational implementation and security tests.
- `data/sample_message.txt`: synthetic input.
- `results/`: generated traces after execution.
- `evidence/`: diagrams included in the reports.

## Run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python src/assignment4_co4.py
```

The project uses the `cryptography` package for AES-GCM, RSA-OAEP and RSA-PSS in the PGP-style demonstration. No secret keys are printed. All test data and identities use the reserved `.test` domain and documentation IP ranges.

## Important scope notes
This is an educational reference implementation, not a production mail client, VPN, certificate authority, or internet-facing HTTPS service. The S/MIME, TLS, SPF, DKIM and DMARC tasks include explicit local policy/validation demonstrations and implementation guidance. For interoperable S/MIME CMS, use OpenSSL CMS with a locally generated CA; for actual TLS packet capture, run the commands in the report on localhost only. Do not deploy the examples with real patient information or real private keys.

## Evidence
The script prints intermediate sizes, operation counts, recipient checks, ESP replay-window state, trust-failure outcomes, and authentication-policy outcomes. Timing is intentionally not presented as a security benchmark.
