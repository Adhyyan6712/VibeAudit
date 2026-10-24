# TaskBoard Demo Application Configuration (Fixed & Secure)
import os

API_KEY = os.environ.get("API_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "prod_fallback_random_key_placeholder")

# Cookie / Session settings (Hardened)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
