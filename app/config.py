"""Central configuration. Secrets are read from environment variables only."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_TIMEOUT_S = float(os.getenv("GEMINI_TIMEOUT_S", "20"))
GEMINI_CONCURRENCY = int(os.getenv("GEMINI_CONCURRENCY", "4"))
CACHE_FILE = Path(os.getenv("CACHE_FILE", ".cache/gemini_cache.json"))

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "20")) * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 1_000_000          # files larger than this are skipped
MAX_FILES = 3000
SESSION_TTL_S = 3600                # scan results are forgotten after 1 hour

SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "__pycache__", "venv", ".venv", "env",
             "dist", "build", ".next", ".idea", ".vscode", "site-packages", "vendor", "coverage"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}
SCAN_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".jinja", ".j2",
             ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties"}

# Live (passive) checks may only ever target these hosts.
LIVE_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5500,http://localhost:8000"
).split(",") if o.strip()]
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", "static"))

