"""
Petit client à copier dans SSHTrap, LogHunter et MiniWAF.
Il envoie une alerte à WatchTower. Aucune dépendance (bibliothèque standard).

Exemple :
    from watchtower_client import send_alert
    send_alert("sshtrap", "bruteforce_ssh", "high", "185.220.101.4", "user=root")
"""
import json
import os
import urllib.request
from datetime import datetime

WATCHTOWER_URL = os.environ.get("WATCHTOWER_URL", "http://127.0.0.1:5000/api/alerts")
WATCHTOWER_API_KEY = os.environ.get("WATCHTOWER_API_KEY", "change-moi-api-key")


def send_alert(source, type_, severity, src_ip, details="", timestamp=None):
    """Envoie une alerte. Renvoie True si WatchTower l'a acceptée.
    Ne plante jamais : si WatchTower est éteint, l'outil continue de tourner."""
    payload = {
        "source": source,
        "type": type_,
        "severity": severity,
        "src_ip": src_ip,
        "details": details,
        "timestamp": timestamp or datetime.now().isoformat(timespec="seconds"),
    }
    req = urllib.request.Request(
        WATCHTOWER_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": WATCHTOWER_API_KEY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 201
    except Exception as e:
        print(f"[watchtower] envoi impossible : {e}")
        return False
