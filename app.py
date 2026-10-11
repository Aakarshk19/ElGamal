"""
ElGamal Cryptography Tool
Information and Network Security — educational demonstration.

Run: python app.py
Then open http://127.0.0.1:5000
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request, send_file
from io import BytesIO
from werkzeug.utils import secure_filename

from crypto.elgamal import (
    decrypt_text,
    encrypt_text,
    generate_keys,
    parse_key_int,
)
from crypto.hashing import format_size, sha256_hex
from crypto.hybrid import decrypt_file_package, encrypt_file_bytes

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "txt", "pdf", "jpg", "jpeg", "png", "gif", "docx", "csv", "xlsx",
    "json", "xml", "md", "zip", "bin", "webp", "ppt", "pptx", "doc",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(OUTPUTS_DIR, exist_ok=True)


def json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def read_keys_from_request(need_private: bool = False):
    data = request.get_json(silent=True) or {}
    form = request.form
    source = data if data else form
    try:
        p = parse_key_int(source.get("p"), "p")
        g = parse_key_int(source.get("g"), "g") if not need_private or source.get("g") else None
        y = parse_key_int(source.get("y"), "y") if source.get("y") not in (None, "") else None
        x = parse_key_int(source.get("x"), "x") if source.get("x") not in (None, "") else None
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    if need_private:
        if x is None:
            raise ValueError("Private key x is required for decryption. Generate keys first.")
        return p, g, y, x
    if g is None or y is None:
        raise ValueError("Public key (p, g, y) is required. Generate keys first.")
    return p, g, y, x


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/generate-keys")
def api_generate_keys():
    try:
        payload = request.get_json(silent=True) or {}
        bits = int(payload.get("bits") or 256)
        if bits not in (128, 160, 256):
            return json_error("Choose a key size of 128, 160, or 256 bits.")
        keys = generate_keys(bits=bits)
        return jsonify({"ok": True, **keys})
    except Exception as exc:
        return json_error(f"Key generation failed: {exc}", 500)


@app.post("/api/encrypt-text")
def api_encrypt_text():
    try:
        data = request.get_json(silent=True) or {}
        message = data.get("message", "")
        if not isinstance(message, str) or not message.strip():
            return json_error("Please enter a non-empty message to encrypt.")
        p, g, y, _ = read_keys_from_request(need_private=False)
        result = encrypt_text(message.strip(), p, g, y)
        return jsonify({"ok": True, **result})
    except ValueError as exc:
        return json_error(str(exc))
    except Exception as exc:
        return json_error(f"Encryption failed: {exc}", 500)


@app.post("/api/decrypt-text")
def api_decrypt_text():
    try:
        data = request.get_json(silent=True) or {}
        ciphertext = data.get("ciphertext")
        original_message = data.get("original_message")
        if not ciphertext:
            return json_error("No ciphertext is available. Encrypt a message first.")
        p, _, _, x = read_keys_from_request(need_private=True)
        result = decrypt_text(ciphertext, p, x)
        matched = (
            isinstance(original_message, str)
            and original_message.strip() == result["message"]
        )
        result["integrity_note"] = (
            "Decryption successful – original message recovered."
            if matched or original_message in (None, "")
            else "Decryption produced a message, but it does not match the original plaintext."
        )
        if original_message in (None, ""):
            result["integrity_note"] = "Decryption successful – original message recovered."
        return jsonify({"ok": True, **result})
    except ValueError as exc:
        return json_error(str(exc))
    except Exception as exc:
        return json_error(f"Decryption failed: {exc}", 500)


def _validate_upload(file_storage):
    if file_storage is None or not file_storage.filename:
        raise ValueError("Please choose a file first.")
    filename = secure_filename(file_storage.filename)
    if not filename:
        raise ValueError("The file name is not valid.")
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext and ext not in ALLOWED_EXTENSIONS and ext != "json":
        # still allow common types; json is used for encrypted packages
        if ext not in {"elgamal", "json"}:
            raise ValueError(
                f"File type .{ext} is not in the allowed list for this demonstration."
            )
    data = file_storage.read()
    if not data:
        raise ValueError("The selected file is empty.")
    return filename, data


@app.post("/api/hash-file")
def api_hash_file():
    try:
        filename, data = _validate_upload(request.files.get("file"))
        digest = sha256_hex(data)
        return jsonify(
            {
                "ok": True,
                "filename": filename,
                "size": len(data),
                "size_label": format_size(len(data)),
                "sha256": digest,
                "note": (
                    "SHA-256 generates a fixed-length hash representing the contents of the file. "
                    "Even a small change to the file should result in a different hash."
                ),
            }
        )
    except ValueError as exc:
        return json_error(str(exc))
    except Exception as exc:
        return json_error(f"Hashing failed: {exc}", 500)


@app.post("/api/encrypt-file")
def api_encrypt_file():
    try:
        filename, data = _validate_upload(request.files.get("file"))
        p = parse_key_int(request.form.get("p"), "p")
        g = parse_key_int(request.form.get("g"), "g")
        y = parse_key_int(request.form.get("y"), "y")
        result = encrypt_file_bytes(data, filename, p, g, y)
        buffer = BytesIO(result["package_bytes"])
        buffer.seek(0)
        response = send_file(
            buffer,
            as_attachment=True,
            download_name=result["download_name"],
            mimetype="application/json",
        )
        response.headers["X-Original-SHA256"] = result["original_sha256"]
        response.headers["X-Download-Name"] = result["download_name"]
        response.headers["X-Scheme"] = result["scheme"]
        return response
    except ValueError as exc:
        return json_error(str(exc))
    except Exception as exc:
        return json_error(f"File encryption failed: {exc}", 500)


@app.post("/api/encrypt-file-info")
def api_encrypt_file_info():
    """Same as encrypt-file but returns JSON (including calculations) plus a download payload."""
    try:
        filename, data = _validate_upload(request.files.get("file"))
        p = parse_key_int(request.form.get("p"), "p")
        g = parse_key_int(request.form.get("g"), "g")
        y = parse_key_int(request.form.get("y"), "y")
        result = encrypt_file_bytes(data, filename, p, g, y)
        return jsonify(
            {
                "ok": True,
                "download_name": result["download_name"],
                "original_sha256": result["original_sha256"],
                "original_size": result["original_size"],
                "size_label": format_size(result["original_size"]),
                "scheme": result["scheme"],
                "calculations": result["calculations"],
                "package_text": result["package_bytes"].decode("utf-8"),
            }
        )
    except ValueError as extra:
        return json_error(str(extra))
    except Exception as extra:
        return json_error(f"File encryption failed: {extra}", 500)


@app.post("/api/decrypt-file")
def api_decrypt_file():
    try:
        filename, data = _validate_upload(request.files.get("file"))
        p = parse_key_int(request.form.get("p"), "p")
        x = parse_key_int(request.form.get("x"), "x")
        result = decrypt_file_package(data, p, x)
        return jsonify(
            {
                "ok": True,
                "original_name": result["original_name"],
                "original_sha256": result["original_sha256"],
                "decrypted_sha256": result["decrypted_sha256"],
                "integrity_match": result["integrity_match"],
                "size": result["size"],
                "size_label": format_size(result["size"]),
                "calculations": result["calculations"],
                "file_b64": result["plaintext"].hex(),
                "uploaded_package_name": filename,
            }
        )
    except ValueError as exc:
        return json_error(str(exc))
    except Exception as extra:
        return json_error(f"File decryption failed: {extra}", 500)


@app.errorhandler(413)
def too_large(_error):
    return json_error("The uploaded file is too large for this demonstration (max 10 MB request).")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
