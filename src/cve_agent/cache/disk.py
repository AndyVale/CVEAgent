from pathlib import Path
import hashlib
import os
import tempfile


class JsonDiskCache:
    """Legacy JSON filenames and lazy writes, with no automatic expiration."""

    def __init__(self, directory: Path):
        self.directory = directory

    def path(self, prefix: str, key: str) -> Path:
        return self.directory / f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()}.json"

    @staticmethod
    def write(path: Path, payload: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
