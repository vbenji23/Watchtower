"""
Gestion de la base SQLite : création, insertion et requêtes.
Toutes les requêtes utilisent des paramètres (?) pour éviter les injections SQL.
"""
import sqlite3
from datetime import datetime, timedelta

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT NOT NULL,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    details    TEXT,
    timestamp  TEXT NOT NULL,
    received   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip   ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
"""


def get_connection():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row  # accès aux colonnes par leur nom
    return conn


def init_db():
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def insert_alert(source, type_, severity, src_ip, details, timestamp):
    """Ajoute une alerte puis lance la règle de corrélation."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (source, type, severity, src_ip, details, timestamp, received) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source, type_, severity, src_ip, details, timestamp, now_str()),
        )
        alert_id = cur.lastrowid
    correlate(src_ip)
    return alert_id


def correlate(src_ip):
    """
    Règle de corrélation : si une même IP a été vue par plusieurs outils
    différents, WatchTower crée une alerte critique (une seule par IP).
    """
    with get_connection() as conn:
        sources = [
            r["source"]
            for r in conn.execute(
                "SELECT DISTINCT source FROM alerts "
                "WHERE src_ip = ? AND source NOT IN ('watchtower', 'test')",
                (src_ip,),
            )
        ]
        if len(sources) < config.CORRELATION_MIN_SOURCES:
            return
        already = conn.execute(
            "SELECT 1 FROM alerts WHERE src_ip = ? AND source = 'watchtower'",
            (src_ip,),
        ).fetchone()
        if already:
            return
        conn.execute(
            "INSERT INTO alerts (source, type, severity, src_ip, details, timestamp, received) "
            "VALUES ('watchtower', 'correlation_multi_source', 'critical', ?, ?, ?, ?)",
            (src_ip, "IP vue par : " + ", ".join(sorted(sources)), now_str(), now_str()),
        )


def get_alerts(source=None, severity=None, ip=None, limit=200):
    """Liste des alertes avec filtres optionnels."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if source:
        query += " AND source = ?"
        params.append(source)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if ip:
        query += " AND src_ip LIKE ?"
        params.append(ip + "%")
    query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
    params.append(limit)
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(query, params)]


def get_stats():
    since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM alerts").fetchone()[0]
        last_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (since,)
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'critical'"
        ).fetchone()[0]
        by_source = {
            r["source"]: r["n"]
            for r in conn.execute("SELECT source, COUNT(*) AS n FROM alerts GROUP BY source")
        }
        by_severity = {
            r["severity"]: r["n"]
            for r in conn.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")
        }
    return {
        "total": total,
        "unique_ips": unique_ips,
        "last_24h": last_24h,
        "critical": critical,
        "by_source": by_source,
        "by_severity": by_severity,
    }


def get_timeline(hours=24):
    """Nombre d'alertes par heure sur les dernières `hours` heures."""
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT strftime('%Y-%m-%d %H:00', timestamp) AS h, COUNT(*) AS n "
            "FROM alerts WHERE timestamp >= ? GROUP BY h",
            (start.strftime("%Y-%m-%d %H:%M:%S"),),
        )
        counts = {r["h"]: r["n"] for r in rows}
    labels, values = [], []
    for i in range(hours):
        h = start + timedelta(hours=i)
        key = h.strftime("%Y-%m-%d %H:00")
        labels.append(h.strftime("%Hh"))
        values.append(counts.get(key, 0))
    return {"labels": labels, "values": values}


def get_top_ips(limit=10):
    with get_connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT src_ip, COUNT(*) AS n, COUNT(DISTINCT source) AS nb_sources "
                "FROM alerts GROUP BY src_ip ORDER BY n DESC LIMIT ?",
                (limit,),
            )
        ]


def get_ip_profile(ip):
    """Tout ce qu'une IP a fait, sur tous les outils (corrélation)."""
    with get_connection() as conn:
        alerts = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC, id DESC",
                (ip,),
            )
        ]
    if not alerts:
        return None
    return {
        "ip": ip,
        "alerts": alerts,
        "count": len(alerts),
        "sources": sorted({a["source"] for a in alerts}),
        "first_seen": min(a["timestamp"] for a in alerts),
        "last_seen": max(a["timestamp"] for a in alerts),
    }
