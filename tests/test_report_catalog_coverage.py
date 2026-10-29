"""Отчёты: severity/рекомендации/SARIF покрывают ВСЕ чеки каталога.

Регресс: новые чеки (sqli_blind, SSI/HTML injection, passive/probe) раньше
получали GENERIC-рекомендацию и INFO-severity в fallback-пути отчётов.
"""

import os
import tempfile

import db
import report_export
from checks.catalog import CHECK_CATALOG


def test_every_check_has_recommendation():
    missing = [
        d.check_id for d in CHECK_CATALOG
        if report_export._recommendation_for(d.check_id)
        == report_export.GENERIC_RECOMMENDATION
    ]
    assert not missing, f"нет рекомендаций в отчётах для чеков: {missing}"


def test_fallback_severity_matches_catalog():
    wrong = []
    for d in CHECK_CATALOG:
        got = report_export._row_severity({"check_type": d.check_id})
        if got != d.severity:
            wrong.append((d.check_id, got, d.severity))
    assert not wrong, f"fallback severity не совпадает с каталогом: {wrong}"


def test_sqli_blind_report_mapping():
    assert report_export._row_severity({"check_type": "sqli_blind"}) == "HIGH"
    assert report_export.GENERIC_RECOMMENDATION != report_export._recommendation_for(
        "sqli_blind"
    )
    assert report_export._sarif_level("HIGH") == "error"
    # legacy-алиас XSS остаётся рабочим
    assert report_export._row_severity({"check_type": "xss"}) == "MEDIUM"


def test_report_export_new_checks_end_to_end():
    dbfile = tempfile.mktemp(suffix=".db")
    db.set_db_path(dbfile)
    db.init_db()
    try:
        rid = db.insert_scan_result(
            template_id="t-blind", worker_id=0, method="GET",
            url="http://x/blind?id=1", status_code=200, error=None,
            check_type="sqli_blind", payload="' AND 1=1-- -",
            evidence="Blind SQLi (boolean): status 200 vs 404",
        )
        db.upsert_scan_meta(scan_result_id=rid, detector="blind",
                            severity="HIGH", confidence=0.7, exploitability=0.6)
        data = report_export._build_report_data(limit=None)
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["severity"] == "HIGH"
        assert finding["check_type"] == "sqli_blind"
        assert report_export.GENERIC_RECOMMENDATION != finding["recommendation"]

        f = tempfile.mktemp(suffix=".json")
        assert report_export.export_json(f, limit=None) == 1
        os.remove(f)
    finally:
        if os.path.exists(dbfile):
            os.remove(dbfile)

def test_recommendations_exist_in_both_languages():
    import i18n

    saved = i18n.get_language()
    try:
        for lang, generic in (
            ("ru", report_export.GENERIC_RECOMMENDATION),
            ("en", report_export.GENERIC_RECOMMENDATION_EN),
        ):
            i18n.set_language(lang)
            missing = [
                d.check_id for d in CHECK_CATALOG
                if report_export._recommendation_for(d.check_id) == generic
            ]
            assert not missing, f"нет {lang}-рекомендации для чеков: {missing}"
    finally:
        i18n.set_language(saved)


def test_all_ru_recommendations_have_en_translation():
    import i18n

    saved = i18n.get_language()
    try:
        i18n.set_language("en")
        missing = [
            ct for ct in report_export.RECOMMENDATIONS
            if report_export._recommendation_for(ct) == report_export.GENERIC_RECOMMENDATION_EN
        ]
        assert not missing, f"нет EN-рекомендации: {missing}"
    finally:
        i18n.set_language(saved)
