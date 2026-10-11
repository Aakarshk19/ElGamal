"""Tests for manual ElGamal, hashing, hybrid files, and Flask validation."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto.elgamal import decrypt_integer, decrypt_text, encrypt_integer, encrypt_text, generate_keys, modinv
from crypto.hashing import sha256_hex
from crypto.hybrid import decrypt_file_package, encrypt_file_bytes

from app import app


class ElGamalMathTests(unittest.TestCase):
    def test_modinv(self):
        self.assertEqual((3 * modinv(3, 11)) % 11, 1)

    def test_integer_roundtrip_small(self):
        p, g, x = 467, 2, 127
        y = pow(g, x, p)
        m = 100
        enc = encrypt_integer(m, p, g, y, k=7)
        dec = decrypt_integer(enc["c1"], enc["c2"], p, x)
        self.assertEqual(dec["m"], m)

    def test_text_roundtrip_generated_keys(self):
        keys = generate_keys(bits=128)
        p = int(keys["public_key"]["p"])
        g = int(keys["public_key"]["g"])
        y = int(keys["public_key"]["y"])
        x = int(keys["private_key"]["x"])
        self.assertEqual(y, pow(g, x, p))
        message = "Hello World"
        enc = encrypt_text(message, p, g, y)
        dec = decrypt_text(enc["ciphertext"], p, x)
        self.assertEqual(dec["message"], message)
        self.assertIn("c1", enc["display"])

    def test_empty_message_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_text("   ", 467, 2, 2)


class HashAndFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = generate_keys(bits=128)
        cls.p = int(cls.keys["public_key"]["p"])
        cls.g = int(cls.keys["public_key"]["g"])
        cls.y = int(cls.keys["public_key"]["y"])
        cls.x = int(cls.keys["private_key"]["x"])

    def test_sha256_changes(self):
        a = sha256_hex(b"assignment-file")
        b = sha256_hex(b"assignment-file!")
        self.assertEqual(len(a), 64)
        self.assertNotEqual(a, b)

    def test_hybrid_file_roundtrip_and_integrity(self):
        data = b"%PDF-demo\nINS ElGamal file bytes"
        enc = encrypt_file_bytes(data, "notes.pdf", self.p, self.g, self.y)
        dec = decrypt_file_package(enc["package_bytes"], self.p, self.x)
        self.assertEqual(dec["plaintext"], data)
        self.assertTrue(dec["integrity_match"])
        self.assertEqual(dec["original_name"], "notes.pdf")
        self.assertEqual(dec["original_sha256"], sha256_hex(data))

    def test_corrupt_package(self):
        with self.assertRaises(ValueError):
            decrypt_file_package(b"not-json", self.p, self.x)

    def test_wrong_private_key(self):
        data = b"secret-bytes"
        enc = encrypt_file_bytes(data, "a.txt", self.p, self.g, self.y)
        wrong_x = self.x ^ 1
        with self.assertRaises(ValueError):
            decrypt_file_package(enc["package_bytes"], self.p, wrong_x)


class FlaskApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_light_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("ElGamal Cryptography Tool", html)
        self.assertIn("Text Encryption", html)
        self.assertIn("File Encryption", html)

    def test_empty_text_rejected(self):
        res = self.client.post(
            "/api/encrypt-text",
            json={"message": "", "p": 467, "g": 2, "y": 2},
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["ok"])

    def test_hash_and_missing_file(self):
        res = self.client.post("/api/hash-file")
        self.assertEqual(res.status_code, 400)

        data = {"file": (io.BytesIO(b"hello from flask"), "sample.txt")}
        res = self.client.post("/api/hash-file", data=data, content_type="multipart/form-data")
        body = res.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["sha256"], sha256_hex(b"hello from flask"))

    def test_text_api_roundtrip(self):
        keys = generate_keys(bits=128)
        payload = {
            "message": "Hello World",
            "p": keys["public_key"]["p"],
            "g": keys["public_key"]["g"],
            "y": keys["public_key"]["y"],
        }
        enc = self.client.post("/api/encrypt-text", json=payload).get_json()
        self.assertTrue(enc["ok"])
        dec = self.client.post(
            "/api/decrypt-text",
            json={
                "ciphertext": enc["ciphertext"],
                "original_message": "Hello World",
                "p": keys["public_key"]["p"],
                "x": keys["private_key"]["x"],
            },
        ).get_json()
        self.assertTrue(dec["ok"])
        self.assertEqual(dec["message"], "Hello World")
        self.assertIn("Decryption successful", dec["integrity_note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
