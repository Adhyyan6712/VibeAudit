# TaskBoard Demo Application Configuration
import os
API_KEY = "sk-live-9481abf082e4a9f2"
DATABASE_URL = "postgres://admin:supersecretpassword123@localhost:5432/taskboard"
SECRET_KEY = "dev_secret_123"

# Cookie / Session settings (Insecure)
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = None
