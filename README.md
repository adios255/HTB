# 🎯 Hack The Box — Write-ups

Collection de mes write-ups de machines HTB. Chaque dossier contient une analyse détaillée du chemin de compromission, de la reconnaissance jusqu'au root.

> ⚠️ **Disclaimer** : contenu à but éducatif uniquement. Les write-ups de box **actives** sont gardés privés jusqu'à leur retrait, conformément à la politique de disclosure de HTB.

---

## 📋 Machines

| Box | OS | Difficulté | Techniques clés | Statut |
|-----|----|-----------:|-----------------|--------|
| [Bedside](./Bedside/) | 🐧 Linux | Medium | pdfminer.six RCE (pickle) · Docker · Vite LFI · torch.load privesc | ✅ |
| _à venir_ | | | | |

---

## 🏷️ Légende difficulté
🟢 Easy · 🟡 Medium · 🔴 Hard · ⚫ Insane

## 🔖 Tags techniques rencontrés
`web` · `upload-bypass` · `deserialization` · `container-escape` · `LFI` · `path-traversal` · `sudo-abuse` · `privesc` · `CVE`

---

## 📚 Méthodologie générale

1. **Recon** — scan de ports, énumération des services, fingerprinting
2. **Énumération** — web (vhosts, dirs, params), services, versions
3. **Foothold** — exploitation de la surface d'attaque initiale
4. **Post-exploitation** — énumération locale, recherche de creds
5. **Privesc** — sudo, SUID, cron, capabilities, kernel
6. **Documentation** — chaque étape reproductible

---

*Fait avec ☕ et beaucoup de `--path-as-is`.*
