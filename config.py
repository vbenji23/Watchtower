"""
Configuration de WatchTower.
Les valeurs sensibles se lisent dans les variables d'environnement :
ne mets JAMAIS tes vraies clés directement dans ce fichier sur GitHub.
"""
import os

# Clé que SSHTrap, LogHunter et MiniWAF doivent envoyer dans l'en-tête X-API-Key
API_KEY = os.environ.get("WATCHTOWER_API_KEY", "change-moi-api-key")

# Mot de passe pour se connecter au dashboard
DASHBOARD_PASSWORD = os.environ.get("WATCHTOWER_PASSWORD", "admin")

# Clé secrète Flask (signe les cookies de session)
SECRET_KEY = os.environ.get("WATCHTOWER_SECRET", os.urandom(32).hex())

# Chemin de la base SQLite
DB_PATH = os.environ.get("WATCHTOWER_DB", "watchtower.db")

# Valeurs autorisées
SEVERITIES = ["low", "medium", "high", "critical"]
SOURCES = ["sshtrap", "loghunter", "miniwaf", "watchtower", "test"]

# Limites de taille pour éviter qu'on remplisse la base avec n'importe quoi
MAX_TYPE_LEN = 64
MAX_DETAILS_LEN = 2000

# Corrélation : une IP vue par au moins N outils différents => alerte critique
CORRELATION_MIN_SOURCES = 2
