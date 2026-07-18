#!/usr/bin/env python3
"""
patch_pe.py v2 - Post-build PE patching for static evasion.
  1. Forge realistic Rich Header (VS2022 profile, adaptive size)
  2. Set realistic PE timestamp instead of zeroing
  3. Inject low-entropy .pad section
  4. Fix PE checksum
"""

import sys
import os
import struct
import math
import random
import time
from datetime import datetime, timezone

_FILLER = (
    "Microsoft Visual C++ Runtime Library  "
    "Copyright (c) Microsoft Corporation. All rights reserved.  "
    "FileDescription  ProductName  CompanyName  LegalCopyright  "
    "FileVersion  ProductVersion  InternalName  OriginalFilename  "
    "This program requires Microsoft Windows.  "
    "The procedure entry point could not be located.  "
    "The ordinal could not be located in the dynamic link library.  "
).encode("ascii")

PAD_VSIZE = 0x8000


def align_up(n, a):
    return (n + a - 1) & ~(a - 1)


def entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    e = 0.0
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e


def forge_rich_header(pe):
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]

    # Wipe existing Rich Header if present
    rich_pos = pe.find(b"Rich")
    if rich_pos != -1 and rich_pos < e_lfanew:
        xk = struct.unpack_from("<I", pe, rich_pos + 4)[0]
        dans_enc = struct.pack("<I", 0x536E6144 ^ xk)
        start = pe.find(dans_enc, 0x40)
        if start != -1 and start < rich_pos:
            pe[start:rich_pos + 8] = b"\x00" * (rich_pos + 8 - start)

    # Start right after the 64-byte DOS header
    rich_start = 0x40
    avail = e_lfanew - rich_start
    # Overhead: DanS(4) + 3 pad(12) + Rich(4) + key(4) = 24 bytes
    # Each entry = 8 bytes (comp_id + count)
    max_entries = (avail - 24) // 8

    if max_entries < 2:
        print(f"[!] No room for Rich Header (e_lfanew=0x{e_lfanew:X}, {avail} bytes avail)")
        return

    vs_build = random.randint(37000, 37600)

    # Full entry pool, ordered by priority
    all_entries = [
        (0x0001, 0,        random.randint(25, 70)),
        (0x0104, vs_build, random.randint(12, 35)),
        (0x0105, vs_build, random.randint(5, 18)),
        (0x0102, vs_build, 1),
        (0x0004, 0,        random.randint(1, 4)),
        (0x0109, vs_build, random.randint(1, 3)),
    ]
    entries = all_entries[:max_entries]

    xor_key = random.randint(0x10000000, 0xFFFFFFFE)

    raw_dwords = [0x536E6144, 0, 0, 0]
    for prod, build, count in entries:
        comp_id = (prod << 16) | (build & 0xFFFF)
        raw_dwords.append(comp_id)
        raw_dwords.append(count)

    enc = bytearray()
    for dw in raw_dwords:
        enc += struct.pack("<I", dw ^ xor_key)
    enc += b"Rich"
    enc += struct.pack("<I", xor_key)

    pe[rich_start:rich_start + len(enc)] = enc
    remaining = e_lfanew - rich_start - len(enc)
    if remaining > 0:
        pe[rich_start + len(enc):e_lfanew] = b"\x00" * remaining

    print(f"[+] Rich Header forged (VS2022 ~{vs_build}, {len(entries)} entries, {len(enc)} bytes @ 0x{rich_start:X})")


def realistic_timestamp(pe):
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    ts_off = e_lfanew + 8
    now = int(time.time())
    ts = random.randint(now - 180 * 86400, now - 90 * 86400)
    struct.pack_into("<I", pe, ts_off, ts)
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    print(f"[+] PE timestamp set   (offset 0x{ts_off:X}, {dt.strftime('%Y-%m-%d')})")


def add_pad_section(pe):
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        print("[!] Not a valid PE, skipping .pad section")
        return pe

    fh_off  = e_lfanew + 4
    num_sec = struct.unpack_from("<H", pe, fh_off + 2)[0]
    opt_sz  = struct.unpack_from("<H", pe, fh_off + 16)[0]
    oh_off  = fh_off + 20

    sect_align = struct.unpack_from("<I", pe, oh_off + 32)[0]
    file_align = struct.unpack_from("<I", pe, oh_off + 36)[0]
    soi_off    = oh_off + 56

    sec_tbl       = fh_off + 20 + opt_sz
    new_hdr_off   = sec_tbl + num_sec * 40
    first_raw_ptr = struct.unpack_from("<I", pe, sec_tbl + 20)[0]

    if new_hdr_off + 40 > first_raw_ptr:
        print("[!] No room in section table for .pad - skipping entropy padding")
        return pe

    last_sec = sec_tbl + (num_sec - 1) * 40
    last_va   = struct.unpack_from("<I", pe, last_sec + 12)[0]
    last_vsz  = struct.unpack_from("<I", pe, last_sec + 8)[0]
    last_rptr = struct.unpack_from("<I", pe, last_sec + 20)[0]
    last_rsz  = struct.unpack_from("<I", pe, last_sec + 16)[0]

    new_va   = align_up(last_va + max(last_vsz, last_rsz), sect_align)
    new_rptr = align_up(last_rptr + last_rsz, file_align)
    new_rsz  = align_up(PAD_VSIZE, file_align)

    filler = (_FILLER * (new_rsz // len(_FILLER) + 1))[:new_rsz]

    hdr = bytearray(40)
    hdr[0:5] = b".pad\x00"
    struct.pack_into("<I", hdr, 8,  PAD_VSIZE)
    struct.pack_into("<I", hdr, 12, new_va)
    struct.pack_into("<I", hdr, 16, new_rsz)
    struct.pack_into("<I", hdr, 20, new_rptr)
    struct.pack_into("<I", hdr, 36, 0x40000040)

    struct.pack_into("<H", pe, fh_off + 2, num_sec + 1)
    struct.pack_into("<I", pe, soi_off, align_up(new_va + PAD_VSIZE, sect_align))
    pe[new_hdr_off: new_hdr_off + 40] = hdr

    if len(pe) < new_rptr:
        pe.extend(b"\x00" * (new_rptr - len(pe)))
    pe.extend(filler)

    print(f"[+] .pad section added  (VA=0x{new_va:X}, raw=0x{new_rptr:X}, {new_rsz // 1024} KB)")
    return pe


def fix_checksum(pe):
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    csum_off = e_lfanew + 4 + 20 + 64

    struct.pack_into("<I", pe, csum_off, 0)

    checksum = 0
    for i in range(0, len(pe) - 1, 2):
        if i == csum_off or i == csum_off + 2:
            continue
        word = pe[i] | (pe[i + 1] << 8)
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    if len(pe) % 2:
        checksum += pe[-1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(pe)

    struct.pack_into("<I", pe, csum_off, checksum & 0xFFFFFFFF)
    print(f"[+] PE checksum fixed  (0x{checksum & 0xFFFFFFFF:08X})")


def main():
    if len(sys.argv) < 2:
        print("Usage: patch_pe.py <binary>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"[-] File not found: {path}")
        sys.exit(1)

    with open(path, "rb") as f:
        pe = bytearray(f.read())

    before = entropy(bytes(pe))

    forge_rich_header(pe)
    realistic_timestamp(pe)
    pe = add_pad_section(pe)
    fix_checksum(pe)

    after = entropy(bytes(pe))

    with open(path, "wb") as f:
        f.write(pe)

    print(f"[+] Entropy : {before:.3f} -> {after:.3f}")


if __name__ == "__main__":
    main()
