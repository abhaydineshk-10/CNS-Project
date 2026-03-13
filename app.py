"""
AES File Encryptor — Flask Web Backend
Run: python3 app.py
Then open: http://localhost:5000
"""

import os
import sys
import struct
import tempfile
from flask import Flask, request, send_file, jsonify
from datetime import datetime

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.exceptions import InvalidTag  # type: ignore
except ImportError:
    print("❌ Run: pip install cryptography flask")
    sys.exit(1)

app = Flask(__name__, static_folder=".", template_folder=".")

MAGIC_HEADER  = b"AESGCM\x02"
SALT_SIZE     = 16
NONCE_SIZE    = 12
KEY_SIZE      = 32
ITERATIONS    = 200_000
ENCRYPTED_EXT = ".aesenc"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data, filename, password):
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key   = derive_key(password, salt)

    fname_bytes = filename.encode("utf-8")
    aesgcm      = AESGCM(key)
    ciphertext  = aesgcm.encrypt(nonce, data, None)

    result = bytearray()
    result += MAGIC_HEADER
    result += salt
    result += nonce
    result += struct.pack(">I", len(fname_bytes))
    result += fname_bytes
    result += ciphertext
    return bytes(result)


def decrypt_bytes(data, password):
    offset = 0

    magic = data[offset:offset + len(MAGIC_HEADER)]
    offset += len(MAGIC_HEADER)
    if magic != MAGIC_HEADER:
        raise ValueError("This file was not encrypted by this tool.")

    salt  = data[offset:offset + SALT_SIZE];  offset += SALT_SIZE
    nonce = data[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
    fname_len     = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
    orig_filename = data[offset:offset+fname_len].decode("utf-8"); offset += fname_len
    ciphertext    = data[offset:]

    key = derive_key(password, salt)
    try:
        aesgcm    = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong password or file has been tampered with.")

    return plaintext, orig_filename


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f        = request.files["file"]
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password is required"}), 400

    data     = f.read()
    if len(data) > MAX_FILE_SIZE:
        return jsonify({"error": "File too large (max 100MB)"}), 400

    try:
        encrypted = encrypt_bytes(data, f.filename, password)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ENCRYPTED_EXT)
    tmp.write(encrypted)
    tmp.close()

    out_name = f.filename + ENCRYPTED_EXT
    return send_file(tmp.name, as_attachment=True, download_name=out_name,
                     mimetype="application/octet-stream")


@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f        = request.files["file"]
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password is required"}), 400

    data = f.read()
    try:
        plaintext, orig_filename = decrypt_bytes(data, password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(plaintext)
    tmp.close()

    return send_file(tmp.name, as_attachment=True, download_name=orig_filename,
                     mimetype="application/octet-stream")


if __name__ == "__main__":
    print("=" * 50)
    print("  🔐 AES File Encryptor — Web UI")
    print("  Open: http://localhost:5000")
    print("=" * 50)
    app.run(debug=False, port=5000)