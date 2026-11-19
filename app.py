"""
WatchTower - mini-SIEM
Reçoit les alertes de SSHTrap, LogHunter et MiniWAF et les affiche dans un dashboard.

Lancer :  python app.py   puis ouvrir http://127.0.0.1:5000
"""
import hmac
import ipaddress
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)

import config
import database

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,     # le JavaScript ne peut pas lire le cookie
    SESSION_COOKIE_SAMESITE="Lax",    # protège contre une partie des attaques CSRF
    MAX_CONTENT_LENGTH=16 * 1024,     # 16 Ko max par requête
)


# ---------- Sécurité ----------

@app.after_request
def security_headers(resp):
    """En-têtes de sécurité HTTP ajoutés à chaque réponse."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self'; img-src 'self' data:"
    )
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def check_api_key():
    key = request.headers.get("X-API-Key", "")
    # compare_digest : comparaison en temps constant (évite les attaques temporelles)
    return hmac.compare_digest(key.encode(), config.API_KEY.encode())


# ---------- Authentification ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password.encode(), config.DASHBOARD_PASSWORD.encode()):
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Mot de passe incorrect"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Dashboard ----------

@app.route("/")
@login_required
def dashboard():
    source = request.args.get("source") or None
    severity = request.args.get("severity") or None
    ip = request.args.get("ip", "").strip() or None
    if source not in config.SOURCES:
        source = None
    if severity not in config.SEVERITIES:
        severity = None
    return render_template(
        "index.html",
        alerts=database.get_alerts(source, severity, ip),
        stats=database.get_stats(),
        top_ips=database.get_top_ips(),
        sources=config.SOURCES,
        severities=config.SEVERITIES,
        f_source=source, f_severity=severity, f_ip=ip or "",
    )


@app.route("/ip/<ip>")
@login_required
def ip_detail(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(400)
    profile = database.get_ip_profile(ip)
    if profile is None:
        abort(404)
    return render_template("ip.html", p=profile)


# ---------- API ----------

@app.route("/api/alerts", methods=["POST"])
def api_add_alert():
    """Point d'entrée des outils. Attend du JSON + en-tête X-API-Key."""
    if not check_api_key():
        return jsonify(error="clé API invalide"), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON attendu"), 400

    source = str(data.get("source", "")).lower()
    type_ = str(data.get("type", "")).strip()
    severity = str(data.get("severity", "")).lower()
    src_ip = str(data.get("src_ip", "")).strip()
    details = str(data.get("details", ""))[: config.MAX_DETAILS_LEN]
    timestamp = data.get("timestamp")

    # Validation de chaque champ
    if source not in config.SOURCES or source == "watchtower":
        return jsonify(error="source invalide"), 400
    if not type_ or len(type_) > config.MAX_TYPE_LEN:
        return jsonify(error="type invalide"), 400
    if severity not in config.SEVERITIES:
        return jsonify(error="severity invalide"), 400
    try:
        src_ip = str(ipaddress.ip_address(src_ip))
    except ValueError:
        return jsonify(error="src_ip invalide"), 400
    if timestamp:
        try:
            ts = datetime.fromisoformat(str(timestamp)).replace(tzinfo=None)
            timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return jsonify(error="timestamp invalide (format ISO attendu)"), 400
    else:
        timestamp = database.now_str()

    alert_id = database.insert_alert(source, type_, severity, src_ip, details, timestamp)
    return jsonify(status="ok", id=alert_id), 201


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(stats=database.get_stats(), timeline=database.get_timeline())


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, msg="Page introuvable"), 404


@app.errorhandler(400)
def bad_request(_):
    return render_template("error.html", code=400, msg="Requête invalide"), 400


database.init_db()

if __name__ == "__main__":
    if config.API_KEY == "change-moi-api-key" or config.DASHBOARD_PASSWORD == "admin":
        print("[!] Attention : tu utilises la clé API ou le mot de passe par défaut.")
        print("    Définis WATCHTOWER_API_KEY et WATCHTOWER_PASSWORD (voir README).")
    # debug=False : le mode debug de Flask permet d'exécuter du code à distance
    app.run(host="127.0.0.1", port=5000, debug=False)
