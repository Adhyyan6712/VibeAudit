"""File loading and filtering engine (FR-2).

Safely processes ZIP archives, folders, and sample projects.
Ignores binaries, node_modules, .git, and files > 1MB.
Never executes or imports user code.
"""
import os
import io
import zipfile
from typing import Dict, Tuple

MAX_FILE_SIZE = 1024 * 1024 # 1 MB
IGNORED_DIRS = {
    ".git", "node_modules", "__pycache__", ".pytest_cache",
    ".venv", "venv", "env", ".idea", ".vscode", "dist", "build"
}
IGNORED_EXTENSIONS = {
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".pdf", ".woff", ".woff2", ".ttf"
}

def is_text_file(filename: str, sample_bytes: bytes = b"") -> bool:
    ext = os.path.splitext(filename)[1].lower()
    if ext in IGNORED_EXTENSIONS:
        return False
    if b"\x00" in sample_bytes[:1024]:
        return False
    return True

def should_skip_path(path: str) -> bool:
    norm = path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    for part in parts:
        if part in IGNORED_DIRS:
            return True
    return False

def load_zip_bytes(zip_bytes: bytes) -> Dict[str, str]:
    """Reads a zip archive in memory and returns {rel_path: content}."""
    file_map: Dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if should_skip_path(info.filename):
                continue
            if info.file_size > MAX_FILE_SIZE:
                continue
            
            raw = zf.read(info)
            if not is_text_file(info.filename, raw):
                continue

            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    content = raw.decode("latin-1")
                except Exception:
                    continue
            
            # Normalize path (strip top-level common dir if any)
            clean_name = info.filename.replace("\\", "/").lstrip("/")
            file_map[clean_name] = content

    return _strip_single_root_folder(file_map)

def load_folder(folder_path: str) -> Dict[str, str]:
    """Reads a local folder and returns {rel_path: content}."""
    file_map: Dict[str, str] = {}
    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, folder_path).replace("\\", "/")
            if should_skip_path(rel):
                continue
            try:
                size = os.path.getsize(full)
                if size > MAX_FILE_SIZE:
                    continue
                with open(full, "rb") as fp:
                    raw = fp.read()
                if not is_text_file(f, raw):
                    continue
                try:
                    content = raw.decode("utf-8")
                except UnicodeDecodeError:
                    content = raw.decode("latin-1")
                file_map[rel] = content
            except Exception:
                continue
    return file_map

def _strip_single_root_folder(file_map: Dict[str, str]) -> Dict[str, str]:
    """If all files in zip start with 'TaskBoard/' or similar prefix, strip it for cleaner file paths."""
    if not file_map:
        return file_map
    first_parts = [k.split("/")[0] for k in file_map.keys() if "/" in k]
    if len(first_parts) == len(file_map) and len(set(first_parts)) == 1:
        prefix = first_parts[0] + "/"
        return {k[len(prefix):]: v for k, v in file_map.items()}
    return file_map
