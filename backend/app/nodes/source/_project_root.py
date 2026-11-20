from __future__ import annotations

import os
import stat
import zipfile
from collections import deque
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

_IGNORED_DIRS = {".git", ".gradle", "build", "target", "node_modules", "__MACOSX", ".idea"}


def safe_resolve_subdir(base_dir: Path, subdir: str | None) -> Path:
    base_resolved = base_dir.resolve()
    if not subdir or not subdir.strip():
        return base_resolved
    cleaned = subdir.strip().replace("\\", "/")
    if cleaned.startswith("/") or ":" in cleaned:
        raise ValueError(f"Invalid subdir '{subdir}': must be relative")
    parts = [p for p in cleaned.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise ValueError(f"Invalid subdir '{subdir}': '..' is forbidden")
    candidate = (base_resolved / "/".join(parts)).resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise ValueError(f"Invalid subdir '{subdir}': escapes workspace root")
    if not candidate.exists() or not candidate.is_dir():
        raise FileNotFoundError(f"Configured subdir '{subdir}' does not exist")
    return candidate


def detect_gradle_project_root(base_dir: Path, subdir: str | None = None) -> Path:
    """Resolve Gradle project root (folder with settings.gradle.kts / build.gradle.kts)."""
    start_dir = safe_resolve_subdir(base_dir, subdir)

    def _has_gradle_marker(folder: Path) -> bool:
        return any(
            (folder / name).is_file()
            for name in ("settings.gradle.kts", "build.gradle.kts", "settings.gradle", "build.gradle")
        )

    if _has_gradle_marker(start_dir):
        return start_dir

    # Breadth-first search by directory depth, preferring directories with settings.gradle(.kts)
    queue: deque[Path] = deque([start_dir])
    candidates_settings: list[Path] = []
    candidates_build: list[Path] = []
    while queue:
        current = queue.popleft()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        subdirs: list[Path] = []
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink() and entry.name not in _IGNORED_DIRS:
                if (entry / "settings.gradle.kts").is_file() or (entry / "settings.gradle").is_file():
                    candidates_settings.append(entry)
                elif (entry / "build.gradle.kts").is_file() or (entry / "build.gradle").is_file():
                    candidates_build.append(entry)
                subdirs.append(entry)
        if not candidates_settings and not candidates_build:
            queue.extend(subdirs)

    if candidates_settings:
        return candidates_settings[0]
    if candidates_build:
        return candidates_build[0]
    return start_dir


def safe_extract_zip(zip_path: Path, dest_dir: Path, max_files: int, max_total_bytes: int) -> None:
    """Safely extract zip archive: prevents zip-slip, symlinks, file count and size bombs."""
    dest_resolved = dest_dir.resolve()
    dest_resolved.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise ValueError(f"ZIP archive contains {len(infos)} entries, exceeding limit {max_files}")

        for info in infos:
            # Reject symlinks (Unix mode bits in upper 16 bits of external_attr)
            unix_mode = info.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise ValueError(f"ZIP archive contains forbidden symlink: {info.filename}")

            raw_name = info.filename.replace("\\", "/")
            if not raw_name or raw_name.startswith("/") or ":" in raw_name:
                raise ValueError(f"Forbidden path in ZIP archive: {info.filename}")

            posix = PurePosixPath(raw_name)
            if any(part == ".." for part in posix.parts):
                raise ValueError(f"Zip-slip path traversal detected in ZIP archive: {info.filename}")

            target_path = (dest_resolved / raw_name).resolve()
            if target_path != dest_resolved and dest_resolved not in target_path.parents:
                raise ValueError(f"Zip-slip target escapes extraction directory: {info.filename}")

            if info.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            file_count += 1
            if file_count > max_files:
                raise ValueError(f"ZIP file count exceeds limit {max_files}")

            if info.file_size > max_total_bytes or total_bytes + info.file_size > max_total_bytes:
                raise ValueError(f"ZIP uncompressed size exceeds limit {max_total_bytes} bytes")

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_total_bytes:
                        raise ValueError(f"ZIP uncompressed size exceeds limit {max_total_bytes} bytes")
                    dst.write(chunk)


def normalize_repo_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("Only https:// Git repository URLs are allowed")
    if not parsed.netloc or "@" in parsed.netloc or parsed.username or parsed.password:
        raise ValueError("Repository URL must not embed credentials")
    clean_path = parsed.path.rstrip("/")
    if clean_path.endswith(".git"):
        clean_path = clean_path[:-4]
    return f"https://{parsed.netloc.lower()}{clean_path}"


def validate_repo_allowlist(repo_url: str, allowlist: list[str]) -> str:
    normalized = normalize_repo_url(repo_url)
    allowed_normalized = {normalize_repo_url(item) for item in allowlist if item.strip()}
    if normalized not in allowed_normalized:
        raise PermissionError(
            f"Repository URL '{repo_url}' is outside configured GIT_CLONE_ALLOWLIST"
        )
    return repo_url.strip()
