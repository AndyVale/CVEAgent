from pathlib import Path
import hashlib


class JsonDiskCache:
    """Legacy JSON filenames and lazy writes, with no automatic expiration."""

    def __init__(self, directory: Path):
        self.directory = directory

    def path(self, prefix: str, key: str) -> Path:
        return self.directory / f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()}.json"

    @staticmethod
    def write(path: Path, payload: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
