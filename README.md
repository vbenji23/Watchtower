# 🛰 WatchTower — mini-SIEM

WatchTower est un **mini-SIEM** (Security Information and Event Management) écrit en Python avec Flask.
Il centralise les alertes de mes autres outils de sécurité et les affiche dans un dashboard web :

| Outil | Rôle | Alertes envoyées |
|---|---|---|
| **SSHTrap** | Honeypot SSH | tentatives de connexion, commandes tapées |
| **LogHunter** | Analyse de logs SSH/web | brute force, scans, path traversal |
| **MiniWAF** | Pare-feu applicatif (reverse proxy) | SQLi, XSS, RCE bloqués |

```
SSHTrap  ──┐
LogHunter ─┼──► API WatchTower (POST /api/alerts) ──► SQLite ──► Dashboard web
MiniWAF  ──┘
```

## ✨ Fonctionnalités

- **API de collecte** protégée par clé API (`X-API-Key`)
- **Dashboard** : compteurs, graphique des alertes par heure, répartition par outil
- **Filtres** par outil, gravité et IP
- **Top des IP attaquantes**
- **Profil d'IP** : chronologie de tout ce qu'une IP a fait sur tous les outils
- **Corrélation automatique** : une IP détectée par 2 outils différents ou plus déclenche une alerte `critical`
- **Connexion par mot de passe** au dashboard

## 🔒 Sécurité de l'application

- Requêtes SQL paramétrées (pas d'injection SQL)
- Échappement automatique des templates Jinja2 (pas de XSS, même si une alerte contient `<script>`)
- Validation stricte des champs reçus (IP vérifiée avec `ipaddress`, gravité et source en liste blanche, tailles limitées)
- Comparaison de la clé API et du mot de passe en temps constant (`hmac.compare_digest`)
- En-têtes HTTP de sécurité : `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- Cookies de session `HttpOnly` et `SameSite=Lax`
- Taille des requêtes limitée à 16 Ko
- Secrets lus dans les variables d'environnement, jamais dans le code
- Mode debug Flask désactivé

## 🚀 Installation (Windows / PowerShell)

```powershell
git clone https://github.com/vbenji23/watchtower.git
cd watchtower
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Définir les secrets (à refaire à chaque nouveau terminal) :

```powershell
$env:WATCHTOWER_API_KEY = "une-longue-cle-aleatoire"
$env:WATCHTOWER_PASSWORD = "un-mot-de-passe-solide"
```

> Astuce pour générer une clé : `python -c "import secrets; print(secrets.token_hex(32))"`

Lancer le serveur :

```powershell
python app.py
```

Puis ouvrir **http://127.0.0.1:5000** et se connecter.

Sous Linux / macOS, remplacer les lignes `$env:...` par `export WATCHTOWER_API_KEY="..."`.

## 🧪 Tester avec de fausses alertes

Dans un **deuxième** terminal (avec les mêmes variables d'environnement) :

```powershell
python send_test_alerts.py 100
```

Le dashboard se remplit avec 100 alertes réparties sur les 24 dernières heures.
Les IP utilisées sont des adresses de documentation (RFC 5737).

## 🔌 Brancher mes outils

Copier `watchtower_client.py` dans le dossier de l'outil, puis :

```python
from watchtower_client import send_alert

# Dans SSHTrap, quand quelqu'un tente de se connecter :
send_alert("sshtrap", "bruteforce_ssh", "high", ip_client, f"user={user} password={password}")

# Dans MiniWAF, quand une requête est bloquée :
send_alert("miniwaf", "sqli_blocked", "high", ip_client, requete_bloquee)

# Dans LogHunter, quand une attaque est détectée :
send_alert("loghunter", "ssh_bruteforce_detected", "high", ip, "42 échecs en 60 s")
```

Si WatchTower est éteint, `send_alert` affiche un message et renvoie `False` sans faire planter l'outil.

## 📡 API

### `POST /api/alerts`

En-têtes : `Content-Type: application/json` et `X-API-Key: <clé>`

```json
{
  "source": "sshtrap",
  "type": "bruteforce_ssh",
  "severity": "high",
  "src_ip": "203.0.113.10",
  "details": "user=root password=123456",
  "timestamp": "2026-11-19T18:20:00"
}
```

| Champ | Obligatoire | Valeurs |
|---|---|---|
| `source` | oui | `sshtrap`, `loghunter`, `miniwaf`, `test` |
| `type` | oui | texte libre (64 caractères max) |
| `severity` | oui | `low`, `medium`, `high`, `critical` |
| `src_ip` | oui | IPv4 ou IPv6 valide |
| `details` | non | texte (2000 caractères max) |
| `timestamp` | non | format ISO 8601, sinon l'heure de réception |

Réponses : `201` (ok), `400` (champ invalide), `401` (mauvaise clé API).

Exemple avec PowerShell :

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/alerts -Method Post `
  -Headers @{ "X-API-Key" = $env:WATCHTOWER_API_KEY } -ContentType "application/json" `
  -Body '{"source":"test","type":"demo","severity":"low","src_ip":"192.0.2.1"}'
```

## 📁 Structure

```
watchtower/
├── app.py               # serveur Flask : routes, API, sécurité
├── database.py          # base SQLite + règle de corrélation
├── config.py            # configuration (lue dans les variables d'environnement)
├── watchtower_client.py # client à copier dans les autres outils
├── send_test_alerts.py  # générateur de fausses alertes
├── templates/           # pages HTML (Jinja2)
└── static/              # CSS + graphiques (Chart.js)
```

## 🗺 Idées d'amélioration

- [ ] Géolocalisation des IP et carte du monde
- [ ] Plus de règles de corrélation (ex. : 10 alertes en 1 minute)
- [ ] Notifications (Discord, e-mail) pour les alertes critiques
- [ ] Export CSV des alertes
- [ ] Protection CSRF du formulaire de connexion et limitation des tentatives
- [ ] Déploiement avec Docker et HTTPS

## ⚠️ Avertissement

Projet réalisé dans un cadre pédagogique (Guardia Cybersecurity School). À utiliser uniquement sur des systèmes dont on a l'autorisation.
