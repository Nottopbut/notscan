"""
tests/test_project_manager_rename.py — rename_project + db.close_all_connections.

Покрывает:
  • успешное переименование папки проекта с переносом файлов/подкаталогов;
  • sanitize имени (пробелы/слеши/скобки/точки) и no-op при том же имени;
  • ValueError: пустое после sanitize имя, collision, несуществующий путь,
    путь-файл вместо каталога; при ошибках исходная папка не меняется;
  • db.close_all_connections(): публичный wrapper, после закрытия соединений
    можно переименовать каталог проекта и открыть новую БД.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import db
import project_manager


@pytest.fixture()
def projects_root(tmp_path, monkeypatch):
    root = tmp_path / "projects"
    root.mkdir()
    monkeypatch.setattr(project_manager, "PROJECTS_ROOT", root)
    yield root


@pytest.fixture()
def clean_db(tmp_path):
    """Уводим глобальный db на tmp-путь и возвращаем после теста."""
    db_path = tmp_path / "dbstate.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "dbstate-closed.db")


class TestRenameProject:
    def test_rename_success_moves_files(self, projects_root):
        proj = project_manager.create_project("old-name")
        (proj / "history.db").write_bytes(b"SQLite-format-bytes")
        (proj / "settings.json").write_text('{"theme_mode": "dark"}')
        (proj / "auth_session.json").write_text("{}")
        (proj / "reports").mkdir(exist_ok=True)
        (proj / "reports" / "r.md").write_text("report")

        new_path = project_manager.rename_project(proj, "new name/v2..")

        assert new_path == projects_root / "new_name_v2"
        assert new_path.is_dir()
        assert not proj.exists()
        assert (new_path / "history.db").read_bytes() == b"SQLite-format-bytes"
        assert (new_path / "settings.json").read_text() == '{"theme_mode": "dark"}'
        assert (new_path / "auth_session.json").exists()
        assert (new_path / "reports" / "r.md").read_text() == "report"
        assert (new_path / "reports").is_dir()

    def test_same_name_is_noop(self, projects_root):
        proj = project_manager.create_project("keep")
        marker = proj / "history.db"
        marker.write_text("x")
        result = project_manager.rename_project(proj, "keep")
        assert result == proj
        assert proj.exists() and marker.read_text() == "x"

    def test_sanitize_special_chars(self, projects_root):
        proj = project_manager.create_project("src")
        new_path = project_manager.rename_project(proj, "  My Project (v2)!!! ")
        assert new_path.parent == projects_root
        name = new_path.name
        assert " " not in name and "/" not in name and "(" not in name
        assert name.startswith("My_Project")
        assert new_path.exists()

    def test_dot_slash_traversal_is_sanitized(self, projects_root):
        proj = project_manager.create_project("src2")
        new_path = project_manager.rename_project(proj, "../../etc/passwd")
        assert new_path.parent == projects_root, "переименование не должно выходить из projects root"
        assert ".." not in new_path.name
        assert "/" not in new_path.name

    @pytest.mark.parametrize("bad_name", ["", "   ", "///", "...", "???", "\x00"])
    def test_empty_after_sanitize_raises(self, projects_root, bad_name):
        proj = project_manager.create_project("valid")
        with pytest.raises(ValueError):
            project_manager.rename_project(proj, bad_name)
        assert proj.exists(), "при ValueError исходный проект не должен меняться"

    def test_collision_raises(self, projects_root):
        first = project_manager.create_project("alpha")
        second = project_manager.create_project("beta")
        with pytest.raises(ValueError):
            project_manager.rename_project(first, "beta")
        assert first.exists() and second.exists(), "collision не должен ничего перезаписывать"

    def test_nonexistent_path_raises(self, projects_root, tmp_path):
        with pytest.raises(ValueError):
            project_manager.rename_project(tmp_path / "no-such-project", "new")

    def test_file_path_raises(self, projects_root, tmp_path):
        fake = tmp_path / "not-a-dir.txt"
        fake.write_text("x")
        with pytest.raises(ValueError):
            project_manager.rename_project(fake, "new")

    def test_returns_pathlib_path(self, projects_root):
        proj = project_manager.create_project("a1")
        result = project_manager.rename_project(str(proj), "a2")
        assert isinstance(result, Path)
        assert result == projects_root / "a2"


class TestDbCloseAllConnections:
    def test_public_wrapper_exists_and_idempotent(self, clean_db):
        assert hasattr(db, "close_all_connections")
        assert callable(db.close_all_connections)
        db.get_conn()
        db.close_all_connections()
        db.close_all_connections()  # идемпотентно

    def test_close_then_rename_project_and_open_new_db(self, projects_root, clean_db):
        proj = project_manager.create_project("old-db-project")
        old_db = proj / "history.db"
        db.set_db_path(old_db)
        db.insert_history("GET", "http://example.test/a", {}, None, 200, {}, b"ok")
        # соединения живого потока (кэш) держат старый путь — закрываем
        db.get_conn()
        db.close_all_connections()

        new_path = project_manager.rename_project(proj, "renamed-db-project")
        assert not proj.exists()
        assert new_path.is_dir()
        new_db = new_path / "history.db"
        assert new_db.exists()

        db.set_db_path(new_db)
        assert db.get_db_path() == new_db
        row_id = db.insert_history(
            "POST", "http://example.test/b", {}, b"x", 201, {}, b"created"
        )
        assert row_id > 0
        assert db.fetch_history_by_id(row_id) is not None
