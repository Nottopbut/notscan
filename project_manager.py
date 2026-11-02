"""
project_manager.py — разделение по проектам (workspace).

Каждый проект — отдельная папка внутри projects/ со своей БД,
настройками, автосохранёнными кредами и отчётами.

При запуске приложения создаётся новый проект:
    projects/project_YYYYMMDD_HHMMSS/
        history.db
        settings.json
        auth_session.json
        reports/
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

APP_DIR = Path(__file__).parent
PROJECTS_ROOT = APP_DIR / "projects"

PROJECT_SUBDIRS = ("reports",)


def get_projects_root() -> Path:
    """Возвращает корень проектов, создавая его при необходимости."""
    PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
    return PROJECTS_ROOT


def _sanitize(name: str) -> str:
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name).strip("._ ")
    return safe or "project"


def create_project(name: Optional[str] = None) -> Path:
    """
    Создаёт новую папку проекта (с подкаталогами) и возвращает её путь.

    Если имя не задано — генерируется из текущего времени.
    Если папка с таким именем уже существует — добавляется счётчик _2, _3, …
    """
    root = get_projects_root()
    base = _sanitize(name) if name else f"project_{time.strftime('%Y%m%d_%H%M%S')}"

    proj = root / base
    i = 2
    while proj.exists():
        proj = root / f"{base}_{i}"
        i += 1

    proj.mkdir(parents=True, exist_ok=True)
    for sub in PROJECT_SUBDIRS:
        (proj / sub).mkdir(exist_ok=True)
    return proj


def list_projects() -> list[Path]:
    """Возвращает список папок проектов (свежие первыми)."""
    root = get_projects_root()
    if not root.exists():
        return []
    return sorted(
        [p for p in root.iterdir() if p.is_dir()],
        key=lambda p: p.name,
        reverse=True,
    )


def _sanitize_name(name: str) -> str:
    """Sanitize без fallback «project» (для rename пустота — ошибка)."""
    return "".join(
        c if (c.isalnum() or c in "-_.") else "_"
        for c in (name or "")
    ).strip("._ ")


def rename_project(proj_dir, new_name: str) -> Path:
    """Переименовывает папку проекта внутри её родительского каталога.

    • имя санитизируется (пробелы/слеши/спецсимволы → ``_``);
    • пустое после sanitize имя → ValueError;
    • несуществующий путь / не директория → ValueError;
    • новое имя совпадает с текущим → возвращает путь без изменений;
    • target уже существует → ValueError (ничего не перезаписываем);
    • после rename пересоздаются подкаталоги (``reports``); файлы (history.db,
      settings.json, auth_session.json) переносятся вместе с папкой.

    Возвращает новый Path.
    """
    from pathlib import Path as _Path

    proj_dir = _Path(proj_dir)
    if not proj_dir.exists() or not proj_dir.is_dir():
        raise ValueError(f"Project directory does not exist: {proj_dir}")

    cleaned = _sanitize_name(str(new_name if new_name is not None else ""))
    if not cleaned:
        raise ValueError(
            "Project name is empty after sanitization (use letters/digits/-_.)"
        )

    if proj_dir.name == cleaned:
        return proj_dir  # no-op: имя не изменилось

    target = proj_dir.parent / cleaned
    if target.exists():
        raise ValueError(f"Project '{cleaned}' already exists: {target}")

    proj_dir.rename(target)
    for sub in PROJECT_SUBDIRS:
        (target / sub).mkdir(exist_ok=True)
    return target


def is_project_dir(path: Path) -> bool:
    """Грубая проверка, что папка похожа на проект (есть БД или она пустая)."""
    p = Path(path)
    return p.is_dir() and (not any(p.iterdir()) or (p / "history.db").exists() or (p / "settings.json").exists())
