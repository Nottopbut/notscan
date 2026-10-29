from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ThemeTokens:
    app_bg: str
    app_fg: str
    mono_bg: str
    mono_fg: str
    insert_fg: str
    select_bg: str


def get_tokens(mode: str) -> ThemeTokens:
    m = (mode or "dark").lower()
    if m == "light":
        return ThemeTokens(
            app_bg="#f6f7fb",
            app_fg="#111827",
            mono_bg="#ffffff",
            mono_fg="#111827",
            insert_fg="#111827",
            select_bg="#dbeafe",
        )
    # dark (catppuccin-like, soft contrast)
    return ThemeTokens(
        app_bg="#1e1e2e",
        app_fg="#cdd6f4",
        mono_bg="#11111b",
        mono_fg="#cdd6f4",
        insert_fg="#ffffff",
        select_bg="#313244",
    )


def get_ttkbootstrap_theme(mode: str) -> str:
    m = (mode or "dark").lower()
    # ttkbootstrap built-in themes: choose modern + readable defaults
    return "flatly" if m == "light" else "darkly"


def settings_path(project_dir: Path) -> Path:
    return project_dir / "settings.json"


def load_settings(project_dir: Path) -> dict[str, Any]:
    path = settings_path(project_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(project_dir: Path, data: dict[str, Any]) -> None:
    path = settings_path(project_dir)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def apply_text_theme(text_widget: Any, tokens: ThemeTokens) -> None:
    # Any: supports tk.Text and ttkbootstrap.scrolled widgets
    try:
        text_widget.configure(
            bg=tokens.mono_bg,
            fg=tokens.mono_fg,
            insertbackground=tokens.insert_fg,
            selectbackground=tokens.select_bg,
        )
    except Exception:
        return

