"""In-memory scan store with automatic expiry. Uploaded source code is never stored; only masked findings."""
import threading
import time

from . import config
from .models import ScanResult


class Store:
    def __init__(self, ttl: int = config.SESSION_TTL_S):
        self._ttl = ttl
        self._data: dict[str, tuple[float, ScanResult]] = {}
        self._lock = threading.Lock()

    def _sweep(self):
        now = time.time()
        for k in [k for k, (t, _) in self._data.items() if now - t > self._ttl]:
            del self._data[k]

    def put(self, scan: ScanResult) -> None:
        with self._lock:
            self._sweep()
            self._data[scan.scan_id] = (time.time(), scan)

    def get(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            self._sweep()
            item = self._data.get(scan_id)
            return item[1] if item else None


STORE = Store()
