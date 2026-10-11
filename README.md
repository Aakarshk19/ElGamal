# ElGamal Cryptography Tool

Secure Message and File Encryption using Public-Key Cryptography.

This is an educational web application for an **Information and Network Security (INS)** assignment. It demonstrates the **ElGamal** public-key algorithm with a manual mathematical implementation (modular exponentiation and modular inverse). It also demonstrates **SHA-256** hashing and **hybrid file encryption**.

The interface is **light mode** (white / light-blue academic theme) and is designed for a college viva: keys, ciphertext pairs `(c1, c2)`, step-by-step math, and integrity checks are all visible on screen.

---

## 1. Project overview

The tool lets you:

- Generate an ElGamal public/private key pair
- Encrypt and decrypt text messages
- Upload files, compute SHA-256, encrypt, decrypt, and download
- Compare hashes after decryption to show **integrity**
- Inspect the actual integers used in each calculation

It is a local demonstration application. There is no database, no user accounts, and no cloud deployment.

---

## 2. Objectives

- Implement ElGamal **manually** (not via an ElGamal library)
- Show key generation, encryption, and decryption clearly
- Support file hashing with SHA-256
- Support file confidentiality using hybrid encryption
- Verify integrity after decryption
- Provide a clean, beginner-friendly UI for a viva demonstration

---

## 3. Technologies used

| Layer | Choice |
| --- | --- |
| Frontend | HTML, CSS, JavaScript |
| Backend | Python 3 + Flask |
| Hashing | Python standard library `hashlib` (SHA-256) |
| ElGamal | Custom module: `crypto/elgamal.py` |
| File payload encryption | AES-128-GCM via the `cryptography` package (symmetric layer only) |

**Important:** AES is used only to encrypt file bytes in the hybrid scheme. ElGamal itself is implemented with `pow(base, exp, mod)` and the extended Euclidean algorithm. No library performs ElGamal encrypt/decrypt.

---

## 4. What is ElGamal?

ElGamal is a public-key cryptosystem (1985) based on the difficulty of the **discrete logarithm problem** in a multiplicative group modulo a large prime `p`.

- Anyone can encrypt with the **public key** `(p, g, y)`
- Only the holder of the **private key** `x` can decrypt
- Encryption is **randomized**: a fresh ephemeral value `k` is chosen each time, so the same message encrypts to different ciphertext

---

## 5. Key generation

1. Select a large **safe prime** `p = 2q + 1` (both `p` and `q` prime)
2. Select a **generator** (primitive root) `g`
3. Select a private key `x` uniformly from `[2, p-2]`
4. Compute `y = g^x mod p`

- **Public key:** `(p, g, y)`
- **Private key:** `x`

The application displays `x` on purpose because this is an educational demo. A production system must never show or transmit the private key in a web page.

---

## 6. Encryption (text)

For a message that has been converted to an integer `m` with `0 < m < p`:

1. Choose a random ephemeral `k` (coprime to `p-1` in this implementation)
2. `c1 = g^k mod p`
3. `c2 = m × y^k mod p`
4. Ciphertext = `(c1, c2)`

Longer messages are split into blocks so each integer stays smaller than `p`. The UI still presents ciphertext as ElGamal pairs.

---

## 7. Decryption (text)

1. Shared value `s = c1^x mod p`
2. Modular inverse `s^{-1} mod p` (extended Euclidean algorithm)
3. `m = c2 × s^{-1} mod p`
4. Convert `m` back to UTF-8 text

If decryption succeeds, the UI reports:

`Decryption successful – original message recovered.`

---

## 8. File hashing

After a file is selected, **Calculate SHA-256 Hash** hashes the raw file bytes with SHA-256 (`hashlib`).

SHA-256 produces a fixed 256-bit digest. Changing even one bit of the file changes the hash (with overwhelming probability). This is used to demonstrate **integrity**, not secrecy.

---

## 9. File encryption (hybrid)

**ElGamal is not efficient for large files.** Encrypting every block of a PDF or image with ElGamal is slow and inflates ciphertext. Real systems use **hybrid encryption**.

This project labels the feature:

**Hybrid ElGamal File Encryption (ElGamal + AES-128-GCM)**

1. Read the file as bytes and store its SHA-256
2. Generate a random 16-byte AES session key
3. Encrypt the file with **AES-128-GCM**
4. Encrypt the session key integer with **ElGamal** (`c1`, `c2`)
5. Save a JSON package you can download (`.elgamal.json`)

The JSON package includes the original file name, original hash, ElGamal pair, AES nonce, and ciphertext. Files are processed in memory and are not stored permanently on the server.

Maximum demonstration size is 8 MB of file content (10 MB HTTP request).

---

## 10. Hash verification

After decryption the tool hashes the recovered bytes and compares them with the SHA-256 stored in the package.

- **Hash Match – File integrity verified** (confidentiality + integrity succeeded)
- **Hash Mismatch – File may have been modified/corrupted**

---

## 11. Project structure

```
elgamal-cryptography-tool/
├── app.py                 # Flask routes and validation
├── requirements.txt
├── README.md
├── crypto/
│   ├── __init__.py
│   ├── elgamal.py         # Manual ElGamal mathematics
│   ├── hashing.py         # SHA-256 helpers
│   └── hybrid.py          # Hybrid file encrypt/decrypt
├── templates/
│   └── index.html         # Light-mode dashboard
├── static/
│   ├── css/style.css
│   └── js/script.js
├── uploads/               # Placeholder (files are not kept)
├── outputs/               # Placeholder
└── tests/
    └── test_crypto.py
```

| File | Role |
| --- | --- |
| `app.py` | HTTP API: generate keys, encrypt/decrypt text and files, hash files |
| `crypto/elgamal.py` | Primes, generator, `y = g^x mod p`, encrypt, decrypt, modular inverse |
| `crypto/hashing.py` | SHA-256 and human-readable sizes |
| `crypto/hybrid.py` | Wrap AES session key with ElGamal; build/parse the downloadable package |
| `templates/index.html` | Dashboard, tabs, How ElGamal Works, calculations modal |
| `static/css/style.css` | Light professional cybersecurity styling |
| `static/js/script.js` | Browser calls to the API, downloads, integrity messages |

---

## 12. Installation

Use Python 3.10 or later.

```bash
cd ElGaman
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

---

## 13. How to run

```bash
python app.py
```

Then open a browser at:

**http://127.0.0.1:5000**

Stop the server with `Ctrl+C`.

---

## 14. Example usage

1. Click **Generate Keys** (256-bit recommended; 128-bit is faster for a short demo).
2. Open **Show Calculations** to see `p`, `g`, `x`, and `y = g^x mod p`.
3. **Text Encryption:** type `Hello World` → **Encrypt Message** → inspect `(c1, c2)` → **Decrypt Message**.
4. **File Encryption:** choose a `.txt` / `.pdf` / `.png` → **Calculate SHA-256 Hash** → **Encrypt File** → download the JSON package.
5. **Upload Encrypted File** → **Decrypt File** → confirm the hash match → download the original file name/type.

---

## 15. Limitations

- This is **not production cryptography**. Key sizes are chosen for a classroom demo, not for protecting real secrets.
- Private keys are displayed in the browser.
- Direct ElGamal on large files is intentionally **not** used as the bulk cipher; hybrid encryption is used and labelled as such.
- File size is capped for a local demo.
- AES-GCM authenticity protects the file payload, but the JSON package as a whole is not signed with a certificate infrastructure.
- Safe-prime generation can take several seconds, especially at 256 bits.

---

## 16. Future enhancements

- Larger key sizes (2048-bit) with progress feedback
- Optional raw ElGamal block mode for tiny files, shown next to hybrid mode
- Export/import of keys as PEM-like text files
- Side-by-side comparison of RSA, ElGamal, and ECC (still implemented by hand)
- Unit tests in CI and a printed lab report generator for the viva

---

## Academic note

Core ElGamal operations are implemented in `crypto/elgamal.py` using:

- Miller–Rabin probable primes
- Modular exponentiation: `pow(g, x, p)`
- Modular inverse: extended Euclidean algorithm

That is the implementation you should walk through in the viva.
This project is only for educational purposes and isnt a standard project.