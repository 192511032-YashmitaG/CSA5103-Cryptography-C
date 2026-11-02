CSA51 - Cryptography and Network Security - Assignment 1

SETUP
1. Install Python 3.10 or later.
2. Open a terminal in this folder.
3. Install packages:
       pip install -r requirements.txt
4. Run:
       python main.py

IMPLEMENTED
- Caesar, monoalphabetic substitution, Vigenere, 2x2 Hill modulo 26,
  columnar transposition, and a 3x3 extended Hill demonstration modulo 36.
- Correctness tests, punctuation/space handling, odd-length Hill padding,
  invalid-key rejection, patient ID and dosage examples.
- Frequency analysis, index of coincidence, Kasiski distance collection,
  Vigenere key-length experiment, Caesar brute-force helper, Hill known-
  plaintext key recovery demonstration.
- 20-row lab-table checksum and tampering tests.
- Grayscale image intensity shift modulo 256 and pixel permutation,
  decryption verification, histogram/entropy data.
- LSB image steganography with extraction, PSNR, simple chi-square indicator,
  and JPEG survival test; text whitespace steganography demonstration.
- Benchmarks for 100, 1,000, 10,000 and 100,000 characters.
- CSV results and frequency, IC and performance graphs.

OUTPUTS
Generated results are written to outputs/ when main.py is run.
If images/medical_scan.png is absent, a synthetic 256x256 carrier is used.
Do not use diagnostic originals; steganography and image-cipher tests should
use a separate copy or synthetic image.

IMPORTANT
All classical ciphers in this project are educational examples only.
Never use this program to protect actual patient information.
