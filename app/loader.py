"""Safe project loading. Uploaded code is only ever READ as text, never imported or executed."""
import io
import os
import posixpath
import zipfile
from dataclasses import dataclass, field

from . import config


@dataclass
class SourceFile:
    path: str
    text: str
    lines: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.lines:
            self.lines = self.text.splitlines()

    @property
    def name(self) -> str:
        return posixpath.basename(self.path)

    @property
    def ext(self) -> str:
        n = self.name.lower()
        return ".env" if n.startswith(".env") else posixpath.splitext(n)[1]


def _clean(name: str) -> str | None:
    """Normalise an archive path and reject traversal (zip-slip) attempts."""
    p = posixpath.normpath(name.replace("\\", "/")).lstrip("/")
    if p in ("", ".", "..") or p.startswith("../") or "/../" in p:
        return None
    return p


def _wanted(path: str) -> bool:
    parts = path.split("/")
    if any(d in config.SKIP_DIRS for d in parts[:-1]):
        return False
    name = parts[-1]
    if name in config.SKIP_FILES:
        return False
    low = name.lower()
    ext = ".env" if low.startswith(".env") else posixpath.splitext(low)[1]
    return ext in config.SCAN_EXTS


def _strip_common_root(files: list[SourceFile]) -> None:
    roots = {f.path.split("/")[0] for f in files if "/" in f.path}
    if len(roots) == 1 and files and all("/" in f.path for f in files):
        for f in files:
            f.path = f.path.split("/", 1)[1]


def _decode(raw: bytes) -> str | None:
    if b"\x00" in raw[:2048]:
        return None                       # binary
    return raw.decode("utf-8", errors="replace")


def load_zip(data: bytes) -> tuple[list[SourceFile], list[str]]:
    notes: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if sum(i.file_size for i in infos) > config.MAX_UNCOMPRESSED_BYTES:
        raise ValueError("The archive expands to more than 100 MB and was rejected.")
    files: list[SourceFile] = []
    skipped = 0
    for info in infos:
        if (info.external_attr >> 16) & 0o170000 == 0o120000:      # symlink
            skipped += 1
            continue
        path = _clean(info.filename)
        if path is None or not _wanted(path):
            skipped += 1
            continue
        if info.file_size > config.MAX_FILE_BYTES:
            notes.append(f"Skipped {path}: larger than 1 MB.")
            continue
        if len(files) >= config.MAX_FILES:
            notes.append(f"Stopped after {config.MAX_FILES} files.")
            break
        with zf.open(info) as fh:
            text = _decode(fh.read(config.MAX_FILE_BYTES + 1))
        if text is None:
            skipped += 1
            continue
        files.append(SourceFile(path, text))
    _strip_common_root(files)
    notes.append(f"Scanned {len(files)} files; skipped {skipped} (binaries, dependencies, unsupported types).")
    return files, notes


def load_dict(raw: dict[str, str]) -> tuple[list[SourceFile], list[str]]:
    files = []
    for name, text in raw.items():
        path = _clean(name)
        if path and _wanted(path) and len(text.encode()) <= config.MAX_FILE_BYTES:
            files.append(SourceFile(path, text))
    return files, [f"Scanned {len(files)} pasted files."]


def load_folder(root: str) -> tuple[list[SourceFile], list[str]]:
    files = []
    for dirpath, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in config.SKIP_DIRS]
        for n in names:
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if not _wanted(rel) or os.path.islink(full) or os.path.getsize(full) > config.MAX_FILE_BYTES:
                continue
            with open(full, "rb") as fh:
                text = _decode(fh.read())
            if text is not None:
                files.append(SourceFile(rel, text))
    return files, [f"Scanned {len(files)} files from folder."]
