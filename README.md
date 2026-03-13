# 🔐 AES-256 Vault

A local web app for encrypting and decrypting files using **AES-256-GCM** authenticated encryption with a password-derived key. Files are processed entirely on your machine — nothing is ever uploaded to a server or saved to disk beyond the temporary response.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Features

- **AES-256-GCM** — authenticated encryption that detects tampering
- **PBKDF2-HMAC-SHA256** key derivation with 200,000 iterations
- Random 16-byte salt and 12-byte nonce per encryption — no two outputs are alike
- Preserves the original filename inside the encrypted blob for seamless decryption
- Drag-and-drop UI with password strength meter and confirmation matching
- Zero storage — files are never written to disk on the server side beyond a transient temp file
- Max file size: **100 MB**

---

## Cryptographic Design

```
Encrypted file layout
─────────────────────────────────────────────────────
[ Magic header (7 B) ][ Salt (16 B) ][ Nonce (12 B) ]
[ Filename length (4 B) ][ Filename (variable) ]
[ AES-256-GCM ciphertext + 16-byte auth tag ]
```

The encryption key is never stored. It is derived fresh on every operation from your password + the embedded salt using PBKDF2.

---

## Requirements

- Python 3.8+
- pip packages: `flask` `cryptography`

---

## Installation & Usage

```bash
# 1. Clone the repo
git clone https://github.com/your-username/aes-vault.git
cd aes-vault

# 2. Install dependencies
pip install flask cryptography

# 3. Run the server
python app.py

# 4. Open in your browser
open http://localhost:5000
```

### Encrypting a file

1. Switch to the **Encrypt** tab
2. Drop or select any file (up to 100 MB)
3. Enter and confirm a strong password
4. Click **Encrypt & Download** — you'll receive `<filename>.aesenc`

### Decrypting a file

1. Switch to the **Decrypt** tab
2. Drop or select the `.aesenc` file
3. Enter the original password
4. Click **Decrypt & Download** — the original file is restored with its original name

---

## Project Structure

```
aes-vault/
├── app.py        # Flask backend — crypto logic and API routes
└── index.html    # Single-file frontend — drag & drop UI
```

---

## Security Notes

- The server processes files **in memory only**; temp files are written purely to satisfy Flask's `send_file` API and are not retained.
- The GCM authentication tag ensures that any modification to the ciphertext — including a wrong password — raises an explicit error rather than silently producing garbage output.
- This tool is designed for **local / trusted-network use**. For production deployments, add HTTPS and consider rate-limiting the `/encrypt` and `/decrypt` endpoints.

---

## License

MIT — do whatever you like, no warranty implied.
