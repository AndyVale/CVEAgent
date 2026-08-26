from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class GuiPathError(ValueError):
    """Raised when a GUI-controlled path escapes its project-owned boundary."""


@dataclass(frozen=True)
class GuiPathPolicy:
    """Resolve every GUI-controlled path inside a narrow project-owned directory."""

    project_root: Path

    def __post_init__(self) -> None:
        root = Path(self.project_root).expanduser().resolve()
        if not root.is_dir():
            raise GuiPathError(f"project root does not exist: {root}")
        object.__setattr__(self, "project_root", root)

    @property
    def fixtures_root(self) -> Path:
        return self.project_root / "fixtures"

    @property
    def data_root(self) -> Path:
        return self.project_root / ".data"

    @property
    def cache_root(self) -> Path:
        return self.project_root / ".cache"

    def prepare_runtime_directories(self) -> None:
        for directory in (self.data_root, self.cache_root):
            if directory.is_symlink():
                raise GuiPathError(f"managed GUI directory cannot be a symbolic link: {directory}")
            directory.mkdir(exist_ok=True)
            self._require_managed_directory(directory)

    def configuration_file(self, value: Any, *, must_exist: bool = True) -> Path:
        path = self._resolve(value, "configuration path")
        if path.parent != self.project_root:
            raise GuiPathError("configuration files must be in the project root")
        self._require_suffix(path, {".toml"}, "configuration file")
        return self._require_file(path, "configuration file") if must_exist else path

    def gui_configuration_file(self, value: Any) -> Path:
        path = self.configuration_file(value)
        if path.name != "config.gui.toml":
            raise GuiPathError("the GUI can write only the project-root config.gui.toml")
        return path

    def taxonomy_file(self, value: Any, *, must_exist: bool = True) -> Path:
        path = self._resolve(value, "taxonomy path")
        self._require_within(path, self.fixtures_root, "taxonomy files must be inside fixtures/")
        self._require_suffix(path, {".json"}, "taxonomy file")
        return self._require_file(path, "taxonomy file") if must_exist else path

    def database_file(self, value: Any, *, must_exist: bool = False) -> Path:
        path = self._resolve(value, "database path")
        self._require_within(path, self.data_root, "database files must be inside .data/")
        self._require_suffix(path, {".db", ".sqlite", ".sqlite3"}, "database file")
        if path.exists() and not path.is_file():
            raise GuiPathError(f"database path is not a file: {path}")
        if not path.parent.is_dir():
            raise GuiPathError(f"database directory does not exist: {path.parent}")
        if must_exist and not path.is_file():
            raise GuiPathError(f"database file does not exist: {path}")
        return path

    def state_file(self, value: Any) -> Path:
        path = self._resolve(value, "GUI state path")
        self._require_within(path, self.data_root, "GUI state files must be inside .data/")
        self._require_suffix(path, {".json"}, "GUI state file")
        if path.exists() and not path.is_file():
            raise GuiPathError(f"GUI state path is not a file: {path}")
        if not path.parent.is_dir():
            raise GuiPathError(f"GUI state directory does not exist: {path.parent}")
        return path

    def cache_directory(self, value: Any) -> Path:
        path = self._resolve(value, "web cache path")
        self._require_within(path, self.cache_root, "web cache must be inside .cache/")
        if path.exists() and not path.is_dir():
            raise GuiPathError(f"web cache path is not a directory: {path}")
        return path

    def taxonomy_files(self) -> tuple[Path, ...]:
        return self._validated_files(self.fixtures_root.rglob("*.json"), self.taxonomy_file)

    def database_files(self) -> tuple[Path, ...]:
        candidates = (
            path
            for path in self.data_root.rglob("*")
            if path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}
        )
        return self._validated_files(candidates, self.database_file)

    def _resolve(self, value: Any, label: str) -> Path:
        if not isinstance(value, (str, Path)) or not str(value).strip():
            raise GuiPathError(f"{label} must be a non-empty path")
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.project_root / path
        return path.resolve()

    def _require_within(self, path: Path, root: Path, message: str) -> None:
        resolved_root = self._require_managed_directory(root)
        if path == resolved_root or not path.is_relative_to(resolved_root):
            raise GuiPathError(message)

    def _require_managed_directory(self, directory: Path) -> Path:
        if directory.is_symlink():
            raise GuiPathError(f"managed GUI directory cannot be a symbolic link: {directory}")
        resolved = directory.resolve()
        if not resolved.is_dir() or resolved.parent != self.project_root:
            raise GuiPathError(f"managed GUI directory is unavailable: {directory}")
        return resolved

    @staticmethod
    def _require_suffix(path: Path, suffixes: set[str], label: str) -> None:
        if path.suffix.lower() not in suffixes:
            allowed = ", ".join(sorted(suffixes))
            raise GuiPathError(f"{label} must use one of these extensions: {allowed}")

    @staticmethod
    def _require_file(path: Path, label: str) -> Path:
        if not path.is_file():
            raise GuiPathError(f"{label} does not exist: {path}")
        return path

    @staticmethod
    def _validated_files(candidates, validator) -> tuple[Path, ...]:
        validated: list[Path] = []
        for candidate in candidates:
            try:
                path = validator(candidate)
            except GuiPathError:
                continue
            if path not in validated:
                validated.append(path)
        return tuple(sorted(validated, key=lambda path: str(path).casefold()))
