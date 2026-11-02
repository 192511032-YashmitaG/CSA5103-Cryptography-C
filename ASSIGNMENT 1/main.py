"""
CSA51 Assignment 1 - Classical Cryptography Demonstration
Python 3.10+
Run: python main.py
Optional packages for graphs/image steganography:
    pip install matplotlib pillow numpy pandas

Educational use only. These classical ciphers are NOT suitable for real patient data.
"""
from __future__ import annotations
import csv
import math
import os
import random
import statistics
import string
import time
from collections import Counter
from pathlib import Path

OUT = Path("outputs")
OUT.mkdir(exist_ok=True)
ALPHABET = string.ascii_uppercase
EXT36 = string.ascii_uppercase + string.digits


def letters_only(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def caesar_encrypt(text: str, key: int) -> str:
    if not isinstance(key, int):
        raise ValueError("Caesar key must be an integer.")
    return "".join(
        chr((ord(ch) - 65 + key) % 26 + 65) if ch.isalpha() and ch.upper() in ALPHABET else ch
        for ch in text.upper()
    )


def caesar_decrypt(text: str, key: int) -> str:
    return caesar_encrypt(text, -key)


def validate_substitution_key(key: str) -> str:
    key = key.upper()
    if len(key) != 26 or set(key) != set(ALPHABET):
        raise ValueError("Monoalphabetic key must contain each A-Z letter exactly once.")
    return key


def mono_encrypt(text: str, key: str) -> str:
    key = validate_substitution_key(key)
    table = str.maketrans(ALPHABET, key)
    return text.upper().translate(table)


def mono_decrypt(text: str, key: str) -> str:
    key = validate_substitution_key(key)
    table = str.maketrans(key, ALPHABET)
    return text.upper().translate(table)


def vigenere_encrypt(text: str, key: str) -> str:
    key = letters_only(key)
    if not key:
        raise ValueError("Vigenere key must contain at least one A-Z letter.")
    out, j = [], 0
    for ch in text.upper():
        if ch in ALPHABET:
            shift = ord(key[j % len(key)]) - 65
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    key = letters_only(key)
    if not key:
        raise ValueError("Vigenere key must contain at least one A-Z letter.")
    out, j = [], 0
    for ch in text.upper():
        if ch in ALPHABET:
            shift = ord(key[j % len(key)]) - 65
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def hill_inverse_2x2(matrix, modulus=26):
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a * d - b * c) % modulus
    if math.gcd(det, modulus) != 1:
        raise ValueError(f"Matrix is not invertible: gcd(det, modulus)={math.gcd(det, modulus)}")
    det_inv = pow(det, -1, modulus)
    return [
        [(det_inv * d) % modulus, (-det_inv * b) % modulus],
        [(-det_inv * c) % modulus, (det_inv * a) % modulus],
    ]


def hill_transform(text: str, matrix, decrypt=False, modulus=26, alphabet=ALPHABET):
    if len(matrix) != 2 or any(len(row) != 2 for row in matrix):
        raise ValueError("This demonstration expects a 2x2 Hill matrix.")
    inverse = hill_inverse_2x2(matrix, modulus)
    use_matrix = inverse if decrypt else matrix
    padded_marker = decrypt and text.endswith("~")
    if padded_marker:
        text = text[:-1]
    chars = list(text.upper())
    positions = [i for i, ch in enumerate(chars) if ch in alphabet]
    values = [alphabet.index(chars[i]) for i in positions]
    if not decrypt and len(values) % 2:
        values.append(alphabet.index("X"))
    if decrypt and len(values) % 2:
        raise ValueError("Hill ciphertext must contain an even number of letters.")
    transformed = []
    for i in range(0, len(values), 2):
        x, y = values[i], values[i + 1]
        transformed.extend([
            (use_matrix[0][0] * x + use_matrix[0][1] * y) % modulus,
            (use_matrix[1][0] * x + use_matrix[1][1] * y) % modulus,
        ])
    if decrypt and padded_marker and positions:
        # Remove the final decoded X padding character added by encryption.
        transformed = transformed[:-1]
        positions = positions[:-1]
    for pos, value in zip(positions, transformed):
        chars[pos] = alphabet[value]
    if decrypt and padded_marker:
        chars.pop()  # remove the appended encrypted padding character
    if not decrypt and len(transformed) > len(positions):
        chars.append(alphabet[transformed[-1]])
        chars.append("~")
    return "".join(chars)

def hill_encrypt(text: str, matrix):
    return hill_transform(text, matrix, decrypt=False, modulus=26, alphabet=ALPHABET)


def hill_decrypt(text: str, matrix):
    return hill_transform(text, matrix, decrypt=True, modulus=26, alphabet=ALPHABET)


def hill36_encrypt(text: str):
    # Valid 3x3 upper-triangular matrix with determinant 1 modulo 36.
    # K = [[1,1,0],[0,1,1],[0,0,1]]
    # K^-1 = [[1,35,1],[0,1,35],[0,0,1]] mod 36
    key = [[1, 1, 0], [0, 1, 1], [0, 0, 1]]
    chars = list(text.upper())
    positions = [i for i, ch in enumerate(chars) if ch in EXT36]
    vals = [EXT36.index(chars[i]) for i in positions]
    count = len(vals)
    vals += [EXT36.index("X")] * ((3 - count % 3) % 3)
    out = []
    for i in range(0, len(vals), 3):
        x, y, z = vals[i:i+3]
        out.extend([(x+y) % 36, (y+z) % 36, z % 36])
    for pos, v in zip(positions, out[:count]):
        chars[pos] = EXT36[v]
    if len(out) > count:
        chars.extend(EXT36[v] for v in out[count:])
    return "".join(chars), count


def hill36_decrypt(ciphertext: str, original_count: int):
    chars = list(ciphertext.upper())
    positions = [i for i, ch in enumerate(chars) if ch in EXT36]
    vals = [EXT36.index(chars[i]) for i in positions]
    inv = [[1, 35, 1], [0, 1, 35], [0, 0, 1]]
    out = []
    for i in range(0, len(vals), 3):
        x, y, z = vals[i:i+3]
        out.extend([
            (inv[0][0]*x + inv[0][1]*y + inv[0][2]*z) % 36,
            (inv[1][0]*x + inv[1][1]*y + inv[1][2]*z) % 36,
            z % 36,
        ])
    for pos, v in zip(positions[:original_count], out[:original_count]):
        chars[pos] = EXT36[v]
    padding_count = len(positions) - original_count
    if padding_count:
        chars = chars[:-padding_count]
    return "".join(chars)


def columnar_encrypt(text: str, key: str) -> str:
    key = key.upper()
    if not key or not key.isalpha():
        raise ValueError("Columnar key must contain letters.")
    n = len(key)
    rows = math.ceil(len(text) / n)
    padded = text + ("X" * (rows * n - len(text)))
    grid = [padded[r*n:(r+1)*n] for r in range(rows)]
    order = sorted(range(n), key=lambda i: (key[i], i))
    return "".join(grid[r][c] for c in order for r in range(rows))


def columnar_decrypt(ciphertext: str, key: str, original_length: int) -> str:
    key = key.upper()
    if not key or not key.isalpha():
        raise ValueError("Columnar key must contain letters.")
    n = len(key)
    rows = math.ceil(len(ciphertext) / n)
    if len(ciphertext) != rows * n:
        raise ValueError("Ciphertext length is inconsistent with padded rectangle.")
    order = sorted(range(n), key=lambda i: (key[i], i))
    cols = [""] * n
    cursor = 0
    for c in order:
        cols[c] = ciphertext[cursor:cursor+rows]
        cursor += rows
    plain = "".join("".join(cols[c][r] for c in range(n)) for r in range(rows))
    return plain[:original_length]


def frequency(text: str):
    clean = letters_only(text)
    total = len(clean)
    counts = Counter(clean)
    return {ch: counts.get(ch, 0) for ch in ALPHABET}, total


def index_of_coincidence(text: str) -> float:
    counts, n = frequency(text)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def kasiski_distances(ciphertext: str, min_size=3, max_size=5):
    clean = letters_only(ciphertext)
    distances = []
    for size in range(min_size, max_size + 1):
        seen = {}
        for i in range(len(clean) - size + 1):
            chunk = clean[i:i+size]
            if chunk in seen:
                distances.append(i - seen[chunk])
            else:
                seen[chunk] = i
    return distances


def likely_key_lengths(ciphertext: str, max_len=12):
    clean = letters_only(ciphertext)
    scores = []
    for key_len in range(1, min(max_len, len(clean)) + 1):
        group_ics = []
        for offset in range(key_len):
            group = clean[offset::key_len]
            if len(group) > 1:
                group_ics.append(index_of_coincidence(group))
        scores.append((key_len, sum(group_ics)/len(group_ics) if group_ics else 0))
    return sorted(scores, key=lambda item: item[1], reverse=True)


def caesar_bruteforce(ciphertext: str):
    return [(k, caesar_decrypt(ciphertext, k)) for k in range(26)]


def mod_matrix_multiply(a, b, modulus=26):
    return [[sum(a[i][k] * b[k][j] for k in range(len(b))) % modulus
             for j in range(len(b[0]))] for i in range(len(a))]


def hill_known_plaintext_demo():
    # The selected Hill key is recovered from two independent known plaintext blocks.
    key = [[3, 3], [2, 5]]
    p = [[7, 11], [4, 15]]  # columns are two plaintext vectors
    c = mod_matrix_multiply(key, p, 26)
    # P inverse for this chosen P: determinant = 7*15 - 11*4 = 61 = 9 mod 26
    p_inverse = hill_inverse_2x2(p, 26)
    recovered = mod_matrix_multiply(c, p_inverse, 26)
    return key, p, c, recovered


def benchmark():
    rows = []
    base = ("PATIENT RECORD TRANSFER DIAGNOSIS PRESCRIPTION LABORATORY " * 2000)
    sizes = [100, 1000, 10000, 100000]
    mono_key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    hill_key = [[3, 3], [2, 5]]
    for size in sizes:
        message = (base * (size // len(base) + 1))[:size]
        funcs = [
            ("Caesar", lambda: caesar_encrypt(message, 3), lambda c: caesar_decrypt(c, 3)),
            ("Monoalphabetic", lambda: mono_encrypt(message, mono_key), lambda c: mono_decrypt(c, mono_key)),
            ("Vigenere", lambda: vigenere_encrypt(message, "MEDICAL"), lambda c: vigenere_decrypt(c, "MEDICAL")),
            ("Hill", lambda: hill_encrypt(message, hill_key), lambda c: hill_decrypt(c, hill_key)),
            ("Columnar", lambda: columnar_encrypt(message, "ZEBRA"), lambda c: columnar_decrypt(c, "ZEBRA", len(message))),
        ]
        for name, enc, dec in funcs:
            start = time.perf_counter()
            cipher = enc()
            enc_time = time.perf_counter() - start
            start = time.perf_counter()
            recovered = dec(cipher)
            dec_time = time.perf_counter() - start
            rows.append({
                "message_length": size, "cipher": name,
                "encryption_seconds": enc_time, "decryption_seconds": dec_time,
                "correct": recovered == message,
            })
    with (OUT / "experiment_results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return rows


def save_frequency_csv(sample):
    items = []
    for label, text in [
        ("Plaintext", sample),
        ("Caesar", caesar_encrypt(sample, 3)),
        ("Monoalphabetic", mono_encrypt(sample, "QWERTYUIOPASDFGHJKLZXCVBNM")),
        ("Vigenere", vigenere_encrypt(sample, "MEDICAL")),
        ("Hill", hill_encrypt(sample, [[3,3],[2,5]])),
        ("Columnar", columnar_encrypt(sample, "ZEBRA")),
    ]:
        counts, total = frequency(text)
        for letter in ALPHABET:
            items.append({"text_type": label, "letter": letter,
                          "count": counts[letter],
                          "percentage": (counts[letter] / total * 100) if total else 0})
    with (OUT / "frequency_results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=items[0].keys())
        writer.writeheader()
        writer.writerows(items)



def text_whitespace_stego_demo():
    """Hide bits using one versus two spaces between words; fragile by design."""
    import re
    carrier = ("Regional healthcare clinics exchange records securely with the central hospital " * 8).strip()
    secret = "OK"
    bits = "".join(f"{b:08b}" for b in secret.encode("utf-8"))
    words = carrier.split()
    if len(words) - 1 < len(bits):
        raise ValueError("Carrier text does not have enough word gaps.")
    pieces = [words[0]]
    for i, word in enumerate(words[1:]):
        spaces = "  " if i < len(bits) and bits[i] == "1" else " "
        pieces.extend([spaces, word])
    hidden = "".join(pieces)
    gaps = re.findall(r"(?<=\S) +(?=\S)", hidden)
    recovered_bits = "".join("1" if len(gap) == 2 else "0" for gap in gaps[:len(bits)])
    recovered = bytes(int(recovered_bits[i:i+8], 2) for i in range(0, len(recovered_bits), 8)).decode("utf-8")
    print("\nTEXT-CIRCULAR WHITESPACE STEGANOGRAPHY")
    print("Secret:", secret, "| Extracted:", recovered, "| Correct:", recovered == secret)
    print("Limitation: copy/paste, HTML rendering or text normalization may collapse repeated spaces.")

def image_steganography_demo():
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        print("Pillow/numpy not installed; skipping image steganography.")
        return

    image_path = Path("images/medical_scan.png")
    if image_path.exists():
        img = Image.open(image_path).convert("RGB")
    else:
        # Synthetic non-diagnostic carrier image for reproducible demonstration only.
        arr = np.zeros((256, 256, 3), dtype=np.uint8)
        for y in range(256):
            for x in range(256):
                arr[y, x] = ((x + y) % 256, (2*x + y) % 256, (x + 2*y) % 256)
        img = Image.fromarray(arr, "RGB")
        print("No images/medical_scan.png found; using a synthetic carrier image.")

    original = np.array(img, dtype=np.uint8)
    secret = "DEMO REPORT: PATIENT CONDITION STABLE"
    payload = len(secret).to_bytes(4, "big") + secret.encode("utf-8")
    bits = "".join(f"{byte:08b}" for byte in payload)
    flat = original.reshape(-1).copy()
    if len(bits) > len(flat):
        raise ValueError("Message exceeds image LSB capacity.")
    for i, bit in enumerate(bits):
        flat[i] = (int(flat[i]) & 0xFE) | int(bit)
    stego = flat.reshape(original.shape)
    extracted_bits = "".join(str(int(v) & 1) for v in flat[:len(bits)])
    extracted_bytes = bytes(int(extracted_bits[i:i+8], 2) for i in range(0, len(extracted_bits), 8))
    msg_len = int.from_bytes(extracted_bytes[:4], "big")
    recovered = extracted_bytes[4:4+msg_len].decode("utf-8")
    Image.fromarray(stego, "RGB").save(OUT / "encrypted_image.png")

    diff = original.astype(np.float64) - stego.astype(np.float64)
    mse = float(np.mean(diff ** 2))
    psnr = float("inf") if mse == 0 else 10 * math.log10((255 ** 2) / mse)
    changed = int(np.count_nonzero(original != stego))
    print("\nLSB STEGANOGRAPHY")
    print("Hidden report:", secret)
    print("Extracted report:", recovered)
    print("Extraction correct:", recovered == secret)
    print("Raw RGB LSB capacity (bytes):", original.size // 8)
    print("Payload bytes including 4-byte header:", len(payload))
    print("PSNR (dB):", round(psnr, 3))
    print("Changed channel values:", changed)
    # Pair-of-values chi-square diagnostic for LSB replacement. This is a simple
    # indicator, not a definitive steganalysis verdict.
    gray = np.array(Image.fromarray(stego, "RGB").convert("L"), dtype=np.uint8).reshape(-1)
    hist = np.bincount(gray, minlength=256)
    chi = 0.0
    for k in range(0, 256, 2):
        pair_total = int(hist[k] + hist[k+1])
        if pair_total:
            chi += ((int(hist[k]) - int(hist[k+1])) ** 2) / pair_total
    print("Simple pair-of-values chi-square statistic:", round(chi, 3))
    jpeg_path = OUT / "stego_jpeg_test.jpg"
    Image.fromarray(stego, "RGB").save(jpeg_path, quality=85)
    jpeg_pixels = np.array(Image.open(jpeg_path).convert("RGB"), dtype=np.uint8).reshape(-1)
    jpeg_bits = "".join(str(int(v) & 1) for v in jpeg_pixels[:len(bits)])
    jpeg_bytes = bytes(int(jpeg_bits[i:i+8], 2) for i in range(0, len(jpeg_bits), 8))
    try:
        jpeg_len = int.from_bytes(jpeg_bytes[:4], "big")
        jpeg_recovered = jpeg_bytes[4:4+jpeg_len].decode("utf-8")
        jpeg_ok = jpeg_recovered == secret
    except Exception:
        jpeg_ok = False
    print("JPEG quality-85 extraction survived:", jpeg_ok)
    print("Saved:", OUT / "encrypted_image.png")



def classical_lab_checksum(rows):
    """Order-sensitive educational checksum; not a cryptographic MAC."""
    modulus = 65521
    total = 0
    for index, row in enumerate(rows, start=1):
        value = sum((j + 1) * ord(ch) for j, ch in enumerate(row))
        total = (total + index * value) % modulus
    return total


def lab_table_tamper_demo():
    rows = [f"PT{20000+i},TEST{i%5},VALUE={100+i},STATUS=VERIFIED" for i in range(20)]
    original = classical_lab_checksum(rows)
    changed = rows.copy()
    changed[7] = changed[7].replace("VALUE=107", "VALUE=907")
    swapped = rows.copy()
    swapped[2], swapped[12] = swapped[12], swapped[2]
    print("\nLAB TABLE CHECKSUM (20 rows)")
    print("Original checksum:", original)
    print("Changed-cell checksum:", classical_lab_checksum(changed))
    print("Changed cell detected:", classical_lab_checksum(changed) != original)
    print("Swapped-row checksum:", classical_lab_checksum(swapped))
    print("Swapped row detected:", classical_lab_checksum(swapped) != original)
    weak_sum = lambda data: sum(ord(ch) for row in data for ch in row) % 65536
    print("Weak additive checksum unchanged by row swap:", weak_sum(rows) == weak_sum(swapped))
    # Show a weakness: because this is an unkeyed checksum, an attacker who can
    # recompute it can replace both data and checksum. It is not authentication.
    print("Security limitation: attacker can recompute this public checksum; it is not a MAC/signature.")


def image_entropy(array):
    import numpy as np
    values, counts = np.unique(array, return_counts=True)
    probabilities = counts.astype(float) / counts.sum()
    return float(-np.sum(probabilities * np.log2(probabilities)))


def image_cipher_demo():
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        print("Pillow/numpy not installed; skipping classical image-cipher demonstration.")
        return
    image_path = Path("images/medical_scan.png")
    if image_path.exists():
        original = np.array(Image.open(image_path).convert("L"), dtype=np.uint8)
    else:
        y, x = np.mgrid[0:256, 0:256]
        # Synthetic pattern only; not a diagnostic image.
        original = ((x * 2 + y + ((x // 24) % 2) * 50) % 256).astype(np.uint8)
        print("No medical_scan.png found; using synthetic 256x256 grayscale image.")

    # Method 1: intensity shift modulo 256.
    shift_key = 73
    shifted = ((original.astype(np.uint16) + shift_key) % 256).astype(np.uint8)
    recovered_shift = ((shifted.astype(np.int16) - shift_key) % 256).astype(np.uint8)

    # Method 2: deterministic pixel permutation (same permutation is inverse key).
    rng = random.Random(2026)
    permutation = list(range(original.size))
    rng.shuffle(permutation)
    flat = original.reshape(-1)
    permuted_flat = flat[permutation]
    permuted = permuted_flat.reshape(original.shape)
    inverse_permutation = [0] * len(permutation)
    for new_index, old_index in enumerate(permutation):
        inverse_permutation[old_index] = new_index
    recovered_perm = permuted_flat[inverse_permutation].reshape(original.shape)

    def psnr(a, b):
        mse = float(np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2))
        return float("inf") if mse == 0 else 10 * math.log10((255 ** 2) / mse)

    print("\nCLASSICAL IMAGE ENCRYPTION")
    print("Intensity shift decrypt correct:", bool(np.array_equal(original, recovered_shift)))
    print("Pixel permutation decrypt correct:", bool(np.array_equal(original, recovered_perm)))
    print("Original entropy:", round(image_entropy(original), 4))
    print("Shifted entropy:", round(image_entropy(shifted), 4))
    print("Permuted entropy:", round(image_entropy(permuted), 4))
    print("Shifted PSNR vs original:", round(psnr(original, shifted), 3))
    print("Permuted PSNR vs original:", round(psnr(original, permuted), 3))
    Image.fromarray(shifted).save(OUT / "image_intensity_shift.png")
    Image.fromarray(permuted).save(OUT / "image_pixel_permutation.png")
    # Histograms are saved as CSV for direct comparison.
    with (OUT / "image_histograms.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["intensity", "original", "shifted", "permuted"])
        h0 = np.bincount(original.reshape(-1), minlength=256)
        h1 = np.bincount(shifted.reshape(-1), minlength=256)
        h2 = np.bincount(permuted.reshape(-1), minlength=256)
        for i in range(256):
            writer.writerow([i, int(h0[i]), int(h1[i]), int(h2[i])])



def attack_length_experiment():
    base = "THE PATIENT RECORD CONTAINS DIAGNOSIS AND PRESCRIPTION DETAILS FROM THE REGIONAL HOSPITAL NETWORK. "
    results = []
    for size in [100, 1000, 10000, 100000]:
        plain = (base * (size // len(base) + 1))[:size]
        cipher = vigenere_encrypt(plain, "MEDICAL")
        ranked = likely_key_lengths(cipher, 12)
        estimate = ranked[0][0] if ranked else 0
        results.append({"ciphertext_letters": len(letters_only(cipher)),
                        "actual_key_length": 7,
                        "estimated_key_length": estimate,
                        "success": estimate == 7})
    with (OUT / "attack_results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print("\nVIGENERE KEY-LENGTH ATTACK EXPERIMENT")
    for item in results:
        print(item)
    print("Note: one deterministic test per length; repeat with varied plaintexts for a statistical success rate.")

def create_graphs():
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; use the CSV files to create graphs in Excel.")
        return
    # Performance graph from benchmark CSV.
    with (OUT / "experiment_results.csv").open(encoding="utf-8") as f:
        data = list(csv.DictReader(f))
    for cipher in sorted({r["cipher"] for r in data}):
        selected = [r for r in data if r["cipher"] == cipher]
        x = [int(r["message_length"]) for r in selected]
        y = [float(r["encryption_seconds"]) for r in selected]
        plt.plot(x, y, marker="o", label=cipher)
    plt.xlabel("Message length (characters)")
    plt.ylabel("Encryption time (seconds)")
    plt.title("Encryption time versus message length")
    plt.legend()
    plt.grid(True)
    plt.savefig(OUT / "performance_graph.png", dpi=160, bbox_inches="tight")
    plt.close()

    # Frequency graph from the generated frequency CSV.
    with (OUT / "frequency_results.csv").open(encoding="utf-8") as f:
        freq = list(csv.DictReader(f))
    labels = sorted({r["text_type"] for r in freq})
    letters = list(ALPHABET)
    width = 0.8 / len(labels)
    x_positions = list(range(len(letters)))
    for series_index, label in enumerate(labels):
        selected = [r for r in freq if r["text_type"] == label]
        values = [float(r["percentage"]) for r in selected]
        offsets = [x + (series_index - (len(labels)-1)/2) * width for x in x_positions]
        plt.bar(offsets, values, width=width, label=label)
    plt.xticks(x_positions, letters)
    plt.xlabel("Alphabet letter")
    plt.ylabel("Frequency (%)")
    plt.title("Plaintext and ciphertext letter-frequency histogram")
    plt.legend(fontsize="small")
    plt.grid(axis="y")
    plt.savefig(OUT / "frequency_graph.png", dpi=160, bbox_inches="tight")
    plt.close()

    sample = ("PATIENT RECORD TRANSFER DIAGNOSIS PRESCRIPTION " * 20)
    texts = {
        "Plaintext": sample,
        "Caesar": caesar_encrypt(sample, 3),
        "Monoalphabetic": mono_encrypt(sample, "QWERTYUIOPASDFGHJKLZXCVBNM"),
        "Vigenere": vigenere_encrypt(sample, "MEDICAL"),
        "Hill": hill_encrypt(sample, [[3,3],[2,5]]),
        "Columnar": columnar_encrypt(sample, "ZEBRA"),
    }
    ic_rows = [{"cipher": name, "index_of_coincidence": index_of_coincidence(value)} for name, value in texts.items()]
    with (OUT / "ic_results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ic_rows[0].keys())
        writer.writeheader()
        writer.writerows(ic_rows)
    plt.bar([r["cipher"] for r in ic_rows], [r["index_of_coincidence"] for r in ic_rows])
    plt.ylabel("Index of coincidence")
    plt.title("Index of coincidence by cipher")
    plt.xticks(rotation=25, ha="right")
    plt.grid(axis="y")
    plt.savefig(OUT / "ic_graph.png", dpi=160, bbox_inches="tight")
    plt.close()
    print("Saved performance_graph.png, frequency_graph.png and ic_graph.png")

def run_tests():
    sample = "PATIENT RECORD TRANSFER"
    mono_key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    hill_key = [[3, 3], [2, 5]]
    print("=" * 64)
    print("CSA51 - CRYPTOGRAPHY AND NETWORK SECURITY")
    print("=" * 64)
    print("PLAINTEXT:", sample)

    cases = [
        ("Caesar", lambda: caesar_encrypt(sample, 3), lambda c: caesar_decrypt(c, 3)),
        ("Monoalphabetic", lambda: mono_encrypt(sample, mono_key), lambda c: mono_decrypt(c, mono_key)),
        ("Vigenere", lambda: vigenere_encrypt(sample, "MEDICAL"), lambda c: vigenere_decrypt(c, "MEDICAL")),
        ("Hill", lambda: hill_encrypt(sample, hill_key), lambda c: hill_decrypt(c, hill_key)),
        ("Columnar", lambda: columnar_encrypt(sample, "ZEBRA"),
         lambda c: columnar_decrypt(c, "ZEBRA", len(sample))),
    ]
    all_ok = True
    for name, enc, dec in cases:
        cipher = enc()
        recovered = dec(cipher)
        ok = recovered == sample
        all_ok &= ok
        print(f"\n{name.upper()}")
        print("Ciphertext:", cipher)
        print("Decrypted :", recovered)
        print("Verification:", "PASS" if ok else "FAIL")

    # Extended mod-36 ID/dosage demonstration
    for value in ["PT20481", "AMOX500MG"]:
        cipher, original_count = hill36_encrypt(value)
        recovered = hill36_decrypt(cipher, original_count)
        ok = recovered == value
        all_ok &= ok
        print(f"\nHILL MOD-36: {value} -> {cipher} -> {recovered} : {'PASS' if ok else 'FAIL'}")

    # Edge cases
    assert caesar_decrypt(caesar_encrypt("", 3), 3) == ""
    assert vigenere_decrypt(vigenere_encrypt("PT-20481, AMOX 500MG!", "MEDICAL"), "MEDICAL") == "PT-20481, AMOX 500MG!"
    odd = "PATIENT"
    assert hill_decrypt(hill_encrypt(odd, hill_key), hill_key) == odd
    assert columnar_decrypt(columnar_encrypt("A B, C!", "ZEBRA"), "ZEBRA", len("A B, C!")) == "A B, C!"
    try:
        hill_inverse_2x2([[2, 4], [2, 4]], 26)
        raise AssertionError("Invalid Hill key was not rejected.")
    except ValueError:
        pass
    print("\nBoundary tests: PASS")

    # Analytical evidence
    print("\nKEY / ATTACK ANALYSIS")
    print("Caesar key space: 26 (25 non-identity shifts)")
    print("Monoalphabetic key space: 26! =", math.factorial(26))
    print("Vigenere key space (length 7):", 26 ** 7)
    print("Hill 2x2 invertible keys mod 26: 157248")
    print("Columnar 5-column permutations: 120")
    print("IC plaintext:", round(index_of_coincidence(sample), 5))
    print("Kasiski repeated-sequence distances (unique):", sorted(set(kasiski_distances(vigenere_encrypt(sample * 10, "MEDICAL"))))[:20])
    print("Likely Vigenere key lengths (top 5):", likely_key_lengths(vigenere_encrypt(sample * 20, "MEDICAL"))[:5])

    key, p, c, recovered_key = hill_known_plaintext_demo()
    print("\nHill known-plaintext demonstration")
    print("Actual key:", key)
    print("Recovered key:", recovered_key)
    print("Recovery correct:", recovered_key == key)

    save_frequency_csv((sample + " ") * 20)
    attack_length_experiment()
    lab_table_tamper_demo()
    image_cipher_demo()
    rows = benchmark()
    print("\nBENCHMARK RESULTS")
    for row in rows:
        print(row)
    print("\nSaved CSV files in outputs/.")
    create_graphs()
    text_whitespace_stego_demo()
    image_steganography_demo()
    print("\nALL TESTS COMPLETED:", "PASS" if all_ok else "CHECK FAILURES")


if __name__ == "__main__":
    run_tests()
