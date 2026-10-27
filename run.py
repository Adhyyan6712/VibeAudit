"""VibeAudit Application Runner.

Launches FastAPI backend and serves the frontend at http://127.0.0.1:8000
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()
import uvicorn

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run("app.main:app", host=host, port=port, reload=True)

