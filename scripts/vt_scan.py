#!/usr/bin/env python3
"""Upload a file to VirusTotal v3 API and poll for results."""
import sys, os, time, json

try:
    import requests
except ImportError:
    print("[-] pip install requests"); sys.exit(1)

API_KEY = os.environ.get("VT_API_KEY", "")
BASE    = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}

POLL_INTERVAL = 30
MAX_POLLS     = 40

PRIORITY = ["Microsoft", "SentinelOne (Static ML)", "CrowdStrike",
            "Bitdefender", "Kaspersky", "ESET-NOD32"]

def upload(path):
    print(f"[*] Uploading {os.path.basename(path)} ({os.path.getsize(path)} bytes)...")
    with open(path, "rb") as f:
        r = requests.post(f"{BASE}/files", headers=HEADERS, files={"file": f})
    r.raise_for_status()
    aid = r.json()["data"]["id"]
    print(f"[+] Analysis ID: {aid}")
    return aid

def poll(aid):
    for i in range(1, MAX_POLLS + 1):
        print(f"[*] Poll {i}/{MAX_POLLS} (waiting {POLL_INTERVAL}s)...", end="\r")
        time.sleep(POLL_INTERVAL)
        r = requests.get(f"{BASE}/analyses/{aid}", headers=HEADERS)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]
        if data["status"] == "completed":
            print(f"\n[+] Analysis complete after {i * POLL_INTERVAL}s")
            return data
    print("\n[-] Timeout waiting for analysis")
    sys.exit(1)

def show(data):
    stats = data["stats"]
    total = sum(stats.values())
    det   = stats.get("malicious", 0) + stats.get("suspicious", 0)
    print(f"\n{'='*60}")
    print(f"  RESULT: {det}/{total}")
    print(f"{'='*60}")

    results = data.get("results", {})

    flagged = []
    for eng, info in sorted(results.items()):
        cat = info.get("category", "")
        if cat in ("malicious", "suspicious"):
            flagged.append((eng, info.get("result", "unknown")))

    if flagged:
        print(f"\n  Detections ({len(flagged)}):")
        for eng, res in flagged:
            marker = " <<<" if eng in PRIORITY else ""
            print(f"    - {eng}: {res}{marker}")

    print(f"\n  Priority engines:")
    for eng in PRIORITY:
        info = results.get(eng, {})
        cat  = info.get("category", "undetected")
        res  = info.get("result", "-")
        ok   = "CLEAN" if cat in ("undetected", "type-unsupported", "timeout", "confirmed-timeout", "failure") else f"DETECTED: {res}"
        print(f"    {eng}: {ok}")

    print()
    return det

def main():
    if len(sys.argv) < 2:
        print("Usage: vt_scan.py <file>"); sys.exit(1)
    if not API_KEY:
        print("[-] Set VT_API_KEY env var"); sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"[-] File not found: {path}"); sys.exit(1)

    aid  = upload(path)
    data = poll(aid)
    det  = show(data)
    sys.exit(0 if det == 0 else 1)

if __name__ == "__main__":
    main()
