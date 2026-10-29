"""
tests/test_i18n.py — unit-тесты RU/EN i18n (без Tk): каталоги, tr(), hooks.

GUI-часть (перевод виджетов, язык после рестарта) — в tests/test_gui_catalog.py
под xvfb.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import i18n  # noqa: E402


class TestCatalog(unittest.TestCase):
    def setUp(self):
        self._lang = i18n.get_language()
        i18n.set_language("en")

    def tearDown(self):
        i18n.set_language(self._lang)

    def test_supported_languages(self):
        self.assertEqual(i18n.DEFAULT_LANGUAGE, "ru")
        self.assertEqual(i18n.available_languages(), ("en", "ru"))
        self.assertEqual(i18n.LANGUAGE_LABELS["en"], "English")
        self.assertEqual(i18n.LANGUAGE_LABELS["ru"], "Русский")

    def test_catalog_pairs_non_empty(self):
        self.assertGreater(len(i18n.MESSAGES), 200, "каталог подозрительно мал")
        for index, pair in enumerate(i18n.MESSAGES):
            self.assertEqual(len(pair), 2, f"pair #{index} must be (en, ru)")
            en, ru = pair
            self.assertIsInstance(en, str)
            self.assertIsInstance(ru, str)
            self.assertTrue(en.strip(), f"пустой EN в pair #{index}")
            self.assertTrue(ru.strip(), f"пустой RU в pair #{index}")
            self.assertEqual(en, en.strip(), f"EN с пробелами в pair #{index}: {en!r}")
            self.assertEqual(ru, ru.strip(), f"RU с пробелами в pair #{index}: {ru!r}")

    def test_no_duplicate_english_sources(self):
        english = [en for en, _ru in i18n.MESSAGES]
        self.assertEqual(len(english), len(set(english)), "дубликаты EN-исходников")

    def test_catalogs_have_same_keys_and_no_empty_values(self):
        cat_en = i18n.catalog("en")
        cat_ru = i18n.catalog("ru")
        self.assertEqual(set(cat_en), set(cat_ru), "наборы ключей EN/RU расходятся")
        self.assertGreater(len(cat_en), 200)
        for key, value in cat_en.items():
            self.assertTrue(str(key).strip())
            self.assertTrue(str(value).strip(), f"пустой EN для {key!r}")
        for key, value in cat_ru.items():
            self.assertTrue(str(value).strip(), f"пустой RU для {key!r}")


class TestTranslation(unittest.TestCase):
    def setUp(self):
        self._lang = i18n.get_language()
        i18n.set_language("en")

    def tearDown(self):
        i18n.set_language(self._lang)

    def test_normalize_language(self):
        self.assertEqual(i18n.normalize_language("RU"), "ru")
        self.assertEqual(i18n.normalize_language("ru-RU"), "ru")
        self.assertEqual(i18n.normalize_language("english"), "en")
        self.assertEqual(i18n.normalize_language(None), "ru")
        self.assertEqual(i18n.normalize_language("gibberish"), "ru")
        # D: стартовый язык — env override → settings → RU default
        self.assertEqual(
            i18n.resolve_language({}, environ={"NOTSCAN_UI_LANGUAGE": "en"}), "en")
        self.assertEqual(
            i18n.resolve_language({"ui_language": "en"}, environ={}), "en")
        self.assertEqual(i18n.resolve_language({}, environ={}), "ru")
        self.assertEqual(i18n.resolve_language(None, environ={}), "ru")
        self.assertEqual(i18n.language_label("ru"), "Русский")

    def test_ru_to_en_by_default(self):
        # Исходный код GUI смешан: RU-строки должны стать EN в en-режиме.
        self.assertEqual(i18n.tr("Настройки"), "Settings")
        self.assertEqual(i18n.tr("История"), "History")
        self.assertEqual(i18n.tr("Результаты"), "Results")
        self.assertTrue(i18n.tr("Сканирование выполняется — дождись завершения или "
                                "останови скан (Stop) перед сменой проекта.")
                        .startswith("A scan is running"))
        self.assertEqual(i18n.tr("Обучение"), "Tutorial")

    def test_en_to_ru(self):
        i18n.set_language("ru")
        self.assertEqual(i18n.tr("Settings"), "Настройки")
        self.assertEqual(i18n.tr("History"), "История")
        self.assertEqual(i18n.tr("Results"), "Результаты")
        self.assertEqual(i18n.tr("Tutorial"), "Обучение")
        # строка уже на RU — остаётся как есть
        self.assertEqual(i18n.tr("Настройки"), "Настройки")

    def test_fallback_returns_source(self):
        i18n.set_language("ru")
        self.assertEqual(i18n.tr("totally unknown string"), "totally unknown string")
        self.assertEqual(i18n.tr(""), "")
        self.assertEqual(i18n.tr(None), "")
        i18n.set_language("en")
        self.assertEqual(i18n.tr("неизвестная строка"), "неизвестная строка")

    def test_formatting_kwargs(self):
        i18n.set_language("en")
        self.assertEqual(
            i18n.tr("History: {shown} / {total}", shown=2, total=5),
            "History: 2 / 5",
        )
        i18n.set_language("ru")
        self.assertEqual(
            i18n.tr("History: {shown} / {total}", shown=2, total=5),
            "История: 2 / 5",
        )
        self.assertEqual(
            i18n.tr("Results: {shown} / {total}", shown=0, total=7),
            "Результаты: 0 / 7",
        )
        # неизвестный шаблон с форматированием: формат применяется к исходнику
        self.assertEqual(i18n.tr("Unknown {x}", x=3), "Unknown 3")
        # битый формат не падает
        self.assertEqual(i18n.tr("Unknown {x}"), "Unknown {x}")

    def test_forced_languages(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr_ru("Settings"), "Настройки")
        self.assertEqual(i18n.tr_ru("Настройки"), "Настройки")
        i18n.set_language("ru")
        self.assertEqual(i18n.tr_en("Настройки"), "Settings")
        self.assertEqual(i18n.tr_en("Settings"), "Settings")

    def test_translation_is_idempotent(self):
        for lang in ("en", "ru"):
            i18n.set_language(lang)
            for _en, ru in list(i18n.MESSAGES)[:50]:
                once = i18n.tr(ru)
                twice = i18n.tr(once)
                self.assertEqual(once, twice, f"не идемпотентно для {ru!r} ({lang})")

    def test_profiles_and_dynamic_templates_present(self):
        i18n.set_language("ru")
        for text in (
            "Quick", "Standard", "Full", "Custom",
            "Customize checks", "Advanced options", "Scan profile",
        ):
            self.assertNotEqual(i18n.tr(text), text, f"нет RU-перевода для {text!r}")


class _FakeMessageBox:
    """Фейковый модуль tkinter.messagebox для проверки hooks."""

    def __init__(self):
        self.calls = []

        def _make(name):
            def _fn(title=None, message=None, *args, **kwargs):
                self.calls.append((name, title, message))
                return "yes"
            return _fn

        for name in (
            "showinfo", "showwarning", "showerror",
            "askyesno", "askokcancel", "askretrycancel", "askquestion",
        ):
            setattr(self, name, _make(name))


class TestMessageBoxHooks(unittest.TestCase):
    def setUp(self):
        self._lang = i18n.get_language()
        self.fake_mb = _FakeMessageBox()

    def tearDown(self):
        i18n.set_language(self._lang)

    def test_hook_translates_title_and_message(self):
        i18n.set_language("ru")
        i18n.install_messagebox_hooks(self.fake_mb)
        result = self.fake_mb.askyesno("Clear history", "Удалить всю историю запросов?")
        self.assertEqual(result, "yes")
        self.assertEqual(
            self.fake_mb.calls[-1],
            ("askyesno", "Очистка истории", "Удалить всю историю запросов?"),
        )
        self.fake_mb.showinfo("Settings", "applies after restart")
        self.assertEqual(
            self.fake_mb.calls[-1],
            ("showinfo", "Настройки", "применяется после перезапуска"),
        )

    def test_hook_in_en_translates_ru_dialogs(self):
        i18n.set_language("en")
        i18n.install_messagebox_hooks(self.fake_mb)
        self.fake_mb.showerror("Ошибка", "Некорректный host/port прокси")
        self.assertEqual(
            self.fake_mb.calls[-1],
            ("showerror", "Error", "Invalid proxy host/port"),
        )

    def test_hook_is_idempotent(self):
        i18n.install_messagebox_hooks(self.fake_mb)
        first = self.fake_mb.showinfo
        i18n.install_messagebox_hooks(self.fake_mb)
        self.assertIs(self.fake_mb.showinfo, first, "hooks установлены повторно")
        self.assertTrue(getattr(first, "_notscan_i18n_hooked", False))


if __name__ == "__main__":
    unittest.main()
