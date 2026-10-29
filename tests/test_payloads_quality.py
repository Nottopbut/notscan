"""
Payloads quality tests.

Проверяет формат и качество payload-баз `payloads/*.txt`:
  • нет пустых строк-payload'ов, дубликатов внутри файла, пустых файлов;
  • одна строка = один payload, без multi-line/control-символов/не-BMP;
  • шапки `# Total: N payloads` совпадают с фактическим числом payload'ов;
  • минимальные объёмы payload-наборов соблюдены;
  • новые файлы ssi.txt / html_injection.txt в ожидаемом формате (маркеры, не-XSS);
  • `scanner_core.load_payloads` парсит все файлы, safe_mode отсекает только деструктивное;
  • time-based payload'ы синхронизированы с SQLI_TIME_PAYLOADS;
  • payload-файлы из checks/catalog.py (если каталог уже есть) существуют и непустые;
  • WAF-bypass секции (`# --- WAF bypass ---`) есть в ключевых наборах, содержат
    payload'ы, репрезентативные обфускации и только не-деструктивные строки.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAYLOADS_DIR = ROOT / "payloads"

sys.path.insert(0, str(ROOT))
import scanner_core  # noqa: E402

# Минимальные объёмы payload-наборов (защита от случайного отката баз).
# Значения 2026-10-29 включают WAF-bypass секции (task-16): старые минимумы
# подняты на число добавленных обфусцированных вариантов.
MIN_PAYLOAD_COUNTS = {
    "cmdi.txt": 578,
    "crlf.txt": 46,
    "deserialization.txt": 26,
    "file_upload.txt": 47,
    "idor.txt": 46,
    "ldapi.txt": 63,
    "nosqli.txt": 74,
    "open_redirect.txt": 317,
    "path_traversal.txt": 857,
    "sqli.txt": 703,
    "sqli_time.txt": 139,
    "ssrf.txt": 97,
    "ssti.txt": 167,
    "xpath.txt": 52,
    "xss.txt": 195,
    "xxe.txt": 103,
}

#: Общий объём payload-баз после WAF-bypass расширения (было 3298).
MIN_TOTAL_PAYLOADS = 3601

#: Ключевые наборы, в которые добавлена секция `# --- WAF bypass ---`.
WAF_BYPASS_FILES = (
    "sqli.txt", "xss.txt", "cmdi.txt", "path_traversal.txt", "ssrf.txt",
    "xxe.txt", "open_redirect.txt", "crlf.txt", "ssti.txt",
    "nosqli.txt", "ldapi.txt", "xpath.txt", "deserialization.txt",
    "file_upload.txt", "idor.txt",
)
WAF_BYPASS_MARKER = "# --- WAF bypass ---"

#: Репрезентативные обфускации: должны физически присутствовать в файле.
WAF_REPRESENTATIVE_MARKERS = {
    "sqli.txt": (
        "/*!50000UNION*/", "UN/**/ION", "%55nion", "UnIoN SeLeCt",
        "/*!50000or*/", "AND/**/1=1", "0x41=0x41", "CHAR(65)=CHAR(65)",
        "1e1=10",
    ),
    "xss.txt": (
        "<scr<script>ipt>", "<svg/onload=", "&#x3c;script", "\\u003cscript",
        "java%09script", "srcdoc", "vbscript:", "xlink:href=\"javascript:",
    ),
    "cmdi.txt": (
        "${IFS}", "$@", "%0a", "\\r\\n", "%3b", "`id", "c^m^d", "who^ami",
        "base64 -d",
    ),
    "path_traversal.txt": (
        "....//", "..%2f", "%252e%252e", "%c0%af", "..;/", "%5c", "..\\",
    ),
    "ssrf.txt": (
        "0x7f", "2130706433", "017700000001", "[::ffff:127.0.0.1]",
        "nip.io", "127.0.0.1@evil.com", "gopher://", "dict://", "file:///",
    ),
    "xxe.txt": (
        "<!ENTITY %", "XInclude", "xi:include", "soap:Envelope",
        "encoding=\"UTF-16\"",
    ),
    "open_redirect.txt": (
        "https:/\\", "\\/\\/evil.com", "trusted.com@evil.com",
        "evil.com@trusted.com", "%2F%2Fevil.com", "javascript:",
    ),
    "crlf.txt": (
        "%0d%0a", "\\r\\n", "%0a", "%E5%98%8D", "%u000d%u000a",
        "X-VulnScanner-CRLF-Test", "X-CRLF-Injected", "X-Injected",
    ),
    "ssti.txt": (
        "{#notscan#}", "{%print(", "{{7*7|abs}}", "|attr('__mul__')",
        "{{7|attr(", "os.popen('id')", "{{\\n7*7\\n}}", "%7B%7B7*7%7D%7D",
        "#{7*7}",
    ),
    "nosqli.txt": (
        "$expr", "$nor", "$elemMatch", "$options",
        "function(){return this.a==this.a}",
    ),
    "ldapi.txt": (
        "objectClass=*)", "\\2a", "%2a%29%28", "cn=*)",
    ),
    "xpath.txt": (
        "' or //*[1] or '1'='1", "count(//*)", "name(/*)", "%27%20or%20",
    ),
    "deserialization.txt": (
        "O:6:\"Marker\"", "notscan", "rO0AB", "AAEAAAD", "gAJ9cQ",
        "$type",
    ),
    "file_upload.txt": (
        "x.php.jpg", "x.jpg.php", "x.pHp5", "x.php%00.png",
        "::$DATA", "x.user.ini",
    ),
    "idor.txt": (
        "null", "undefined", "0x1f", "deadbeef", "MDAwMDAwMDAt",
        "YWRtaW4=",
    ),
}

# check_type → файл, как их подключает scanner_core.load_payloads (legacy filename_map).
CHECK_TO_FILE = {
    "cmdi": "cmdi.txt",
    "xss": "xss.txt",
    "xss_reflected": "xss.txt",
    "sqli": "sqli.txt",
    "sqli_time": "sqli_time.txt",
    "ssti": "ssti.txt",
    "path_traversal": "path_traversal.txt",
    "xxe": "xxe.txt",
    "ssrf": "ssrf.txt",
    "nosql_injection": "nosqli.txt",
    "ldap_injection": "ldapi.txt",
    "xpath_injection": "xpath.txt",
    "deserialization": "deserialization.txt",
    "crlf_injection": "crlf.txt",
    "open_redirect": "open_redirect.txt",
    "file_upload": "file_upload.txt",
    "idor": "idor.txt",
}


def payload_files() -> list[Path]:
    return sorted(PAYLOADS_DIR.glob("*.txt"))


def parse_payload_file(path: Path) -> list[str]:
    """Тот же формат, что и scanner_core.load_payloads: strip, skip пустых и '#'."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def header_total(path: Path) -> int | None:
    text = path.read_text(encoding="utf-8")
    m = re.search(r"^# Total: (\d+) payloads$", text, re.MULTILINE)
    return int(m.group(1)) if m else None


class TestPayloadFilesCommon(unittest.TestCase):
    def test_files_exist_and_not_empty(self):
        files = payload_files()
        self.assertGreaterEqual(len(files), 18, f"ожидалось >=18 payload-файлов, найдено {len(files)}")
        for path in files:
            payloads = parse_payload_file(path)
            self.assertGreater(len(payloads), 0, f"{path.name}: нет payload'ов")

    def test_no_duplicates_within_file(self):
        for path in payload_files():
            payloads = parse_payload_file(path)
            dups = {p for p in payloads if payloads.count(p) > 1}
            self.assertEqual(dups, set(), f"{path.name}: дубликаты {sorted(dups)[:5]}")

    def test_one_payload_per_line_no_whitespace_junk(self):
        for path in payload_files():
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.endswith("\n"), f"{path.name}: файл должен заканчиваться \\n")
            self.assertNotIn("\r", text, f"{path.name}: CR-символы в файле")
            lines = text.splitlines()
            for ln in lines:
                self.assertEqual(ln, ln.rstrip(), f"{path.name}: trailing whitespace: {ln!r}")
            for payload in parse_payload_file(path):
                self.assertEqual(payload, payload.strip(), f"{path.name}: лишние пробелы: {payload!r}")

    def test_no_multiline_control_or_non_bmp(self):
        for path in payload_files():
            for payload in parse_payload_file(path):
                self.assertNotIn("\n", payload)
                self.assertNotIn("\r", payload)
                self.assertFalse(
                    any(ord(c) < 0x20 for c in payload),
                    f"{path.name}: control-символ в {payload!r}",
                )
                self.assertFalse(
                    any(ord(c) > 0xFFFF for c in payload),
                    f"{path.name}: не-BMP символ в {payload!r}",
                )

    def test_header_total_matches_payload_count(self):
        for path in payload_files():
            total = header_total(path)
            self.assertIsNotNone(total, f"{path.name}: нет шапки '# Total: N payloads'")
            self.assertEqual(total, len(parse_payload_file(path)), f"{path.name}: шапка Total расходится")

    def test_payload_growth_not_regressed(self):
        for fname, minimum in MIN_PAYLOAD_COUNTS.items():
            path = PAYLOADS_DIR / fname
            self.assertTrue(path.exists(), f"{fname}: файл пропал")
            self.assertGreaterEqual(
                len(parse_payload_file(path)), minimum,
                f"{fname}: объём базы уменьшился (< {minimum})",
            )


class TestNewPayloadFiles(unittest.TestCase):
    def test_ssi_file_format(self):
        path = PAYLOADS_DIR / "ssi.txt"
        self.assertTrue(path.exists(), "ssi.txt отсутствует")
        payloads = parse_payload_file(path)
        self.assertGreaterEqual(len(payloads), 15)
        self.assertLessEqual(len(payloads), 25)
        self.assertEqual(len(payloads), len(set(payloads)), "SSI: дубликаты")
        for payload in payloads:
            self.assertIn("<!--#", payload, f"SSI payload без директивы: {payload!r}")
            self.assertIn("-->", payload, f"SSI payload без закрытия: {payload!r}")
        joined = "\n".join(payloads)
        for directive in ("echo", "printenv", "exec", "include", "config"):
            self.assertIn(directive, joined, f"SSI: нет директивы {directive}")

    def test_html_file_format(self):
        path = PAYLOADS_DIR / "html_injection.txt"
        self.assertTrue(path.exists(), "html_injection.txt отсутствует")
        payloads = parse_payload_file(path)
        self.assertGreaterEqual(len(payloads), 25)
        self.assertLessEqual(len(payloads), 40)
        self.assertEqual(len(payloads), len(set(payloads)), "HTML: дубликаты")
        markers = []
        for payload in payloads:
            self.assertIn("HTMLINJ_MARKER", payload, f"HTML payload без MARKER: {payload!r}")
            m = re.search(r'notscan="?(\d+)', payload, re.IGNORECASE)
            self.assertIsNotNone(m, f"HTML payload без notscan=<n>: {payload!r}")
            markers.append(m.group(1))
            self.assertIn("<", payload)
            self.assertIn(">", payload)
        self.assertEqual(len(markers), len(set(markers)), "HTML: номера notscan должны быть уникальны")

    def test_html_payloads_are_non_executable(self):
        """HTML-маркеры не должны быть XSS: без script/обработчиков/javascript:."""
        payloads = parse_payload_file(PAYLOADS_DIR / "html_injection.txt")
        for payload in payloads:
            low = payload.lower()
            for forbidden in ("<script", "onerror=", "onload=", "onfocus=", "javascript:", "<iframe"):
                self.assertNotIn(forbidden, low, f"HTML injection не должен быть XSS: {payload!r}")

    def test_new_files_have_no_unicode_escapes(self):
        for name in ("ssi.txt", "html_injection.txt"):
            text = (PAYLOADS_DIR / name).read_text(encoding="utf-8")
            self.assertIsNone(
                re.search(r"\\u[0-9a-fA-F]{4}", text),
                f"{name}: литеральные \\uXXXX-эскейпы запрещены",
            )


class TestLoadPayloads(unittest.TestCase):
    def test_all_known_check_types_load(self):
        for check_type, fname in CHECK_TO_FILE.items():
            payloads = scanner_core.load_payloads(check_type, safe_mode=False)
            self.assertGreater(len(payloads), 0, f"{check_type}: пусто (файл {fname})")

    def test_load_as_unsafe_matches_file_content(self):
        for check_type, fname in CHECK_TO_FILE.items():
            expected = parse_payload_file(PAYLOADS_DIR / fname)
            loaded = scanner_core.load_payloads(check_type, safe_mode=False)
            self.assertEqual(len(loaded), len(expected), f"{check_type}: load_payloads потерял строки")

    def test_safe_mode_filters_only_destructive(self):
        for check_type in CHECK_TO_FILE:
            unsafe = scanner_core.load_payloads(check_type, safe_mode=False)
            safe = scanner_core.load_payloads(check_type, safe_mode=True)
            self.assertTrue(set(safe).issubset(set(unsafe)), f"{check_type}: safe_mode добавил payload'ы")
            for payload in safe:
                self.assertFalse(
                    scanner_core._is_destructive_payload(payload),
                    f"{check_type}: деструктивный payload прошёл safe_mode: {payload!r}",
                )
            removed = set(unsafe) - set(safe)
            for payload in removed:
                self.assertTrue(
                    scanner_core._is_destructive_payload(payload),
                    f"{check_type}: safe_mode отфильтровал безопасный payload: {payload!r}",
                )

    def test_sqli_safe_mode_still_filters_legacy_destructive(self):
        unsafe = scanner_core.load_payloads("sqli", safe_mode=False)
        safe = scanner_core.load_payloads("sqli", safe_mode=True)
        self.assertGreater(len(unsafe), len(safe), "SQLI: в файле должны остаться деструктивные строки")
        self.assertGreaterEqual(len(unsafe) - len(safe), 1)

    def test_idor_payloads_stay_sql_free(self):
        payloads = scanner_core.load_payloads("idor", safe_mode=True)
        self.assertIn("1", payloads)
        self.assertIn("9999", payloads)
        for payload in payloads:
            self.assertNotIn("'", payload, f"IDOR: SQL-строка в IDOR-пайлоаде {payload!r}")
            self.assertNotIn("or 1=1", payload.lower())


class TestTimeBasedPayloads(unittest.TestCase):
    def test_sqli_time_list_synced_with_payload_file(self):
        from checks.injections import SQLI_TIME_PAYLOADS

        payloads = set(parse_payload_file(PAYLOADS_DIR / "sqli_time.txt"))
        self.assertGreaterEqual(len(SQLI_TIME_PAYLOADS), 20)
        for _pid, payload, threshold, _dbtype in SQLI_TIME_PAYLOADS:
            self.assertIn(payload, payloads,
                          f"time-based payload из SQLI_TIME_PAYLOADS отсутствует в файле: {payload!r}")
            self.assertGreaterEqual(float(threshold), 2.0)
            self.assertLessEqual(float(threshold), 5.0)

    def test_new_time_based_payloads_are_unique(self):
        payloads = parse_payload_file(PAYLOADS_DIR / "sqli_time.txt")
        self.assertEqual(len(payloads), len(set(payloads)))
        sleeps = [p for p in payloads if "SLEEP(2" in p or "SLEEP(3" in p
                  or "pg_sleep(2" in p or "pg_sleep(3" in p
                  or "WAITFOR DELAY '0:0:2'" in p or "WAITFOR DELAY '0:0:3'" in p]
        self.assertGreaterEqual(len(sleeps), 15, "ожидались быстрые 2-3-секундные payload'ы")


class TestCatalogIntegration(unittest.TestCase):
    def test_catalog_payload_files_exist(self):
        try:
            from checks.catalog import CHECK_CATALOG  # type: ignore
        except ImportError:
            self.skipTest("checks/catalog.py недоступен")
        for check in CHECK_CATALOG:
            payload_file = getattr(check, "payload_file", None)
            if not payload_file:
                continue
            path = PAYLOADS_DIR / payload_file
            self.assertTrue(path.exists(), f"{check.check_id}: нет payload-файла {payload_file}")
            self.assertGreater(len(parse_payload_file(path)), 0, f"{payload_file}: пустой")

    def test_new_files_wired_into_load_payloads(self):
        """После интеграции каталога load_payloads должен отдавать SSI/HTML файлы."""
        ssi = scanner_core.load_payloads("ssi_injection", safe_mode=True)
        html = scanner_core.load_payloads("html_injection", safe_mode=True)
        if not ssi and not html:
            self.skipTest("load_payloads не знает ssi_injection/html_injection")
        self.assertEqual(len(ssi), len(parse_payload_file(PAYLOADS_DIR / "ssi.txt")))
        self.assertEqual(len(html), len(parse_payload_file(PAYLOADS_DIR / "html_injection.txt")))


# ══════════════════════════════════════════════════════════════════
#  WAF-bypass секции (task-16)
# ══════════════════════════════════════════════════════════════════

def waf_section_text(path: Path) -> str:
    """Текст файла после маркера `# --- WAF bypass ---`."""
    text = path.read_text(encoding="utf-8")
    if WAF_BYPASS_MARKER not in text:
        return ""
    return text.split(WAF_BYPASS_MARKER, 1)[1]


def waf_section_payloads(path: Path) -> list[str]:
    """Payload'ы WAF-секции (комментарии/пустые строки игнорируются)."""
    return [
        ln.strip()
        for ln in waf_section_text(path).splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


class TestWafBypassSections(unittest.TestCase):
    def test_sections_present_in_key_files(self):
        for fname in WAF_BYPASS_FILES:
            path = PAYLOADS_DIR / fname
            self.assertTrue(path.exists(), f"{fname}: файл пропал")
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                WAF_BYPASS_MARKER, text,
                f"{fname}: нет секции '{WAF_BYPASS_MARKER}'",
            )
            # маркер должен быть один, не размазан по файлу
            self.assertEqual(
                text.count(WAF_BYPASS_MARKER), 1,
                f"{fname}: маркер WAF-секции встречается более одного раза",
            )

    def test_section_has_payloads(self):
        for fname in WAF_BYPASS_FILES:
            payloads = waf_section_payloads(PAYLOADS_DIR / fname)
            self.assertGreaterEqual(
                len(payloads), 8,
                f"{fname}: в WAF-секции только {len(payloads)} payload'ов",
            )
            self.assertEqual(
                len(payloads), len(set(payloads)),
                f"{fname}: дубликаты внутри WAF-секции",
            )

    def test_representative_obfuscations_present(self):
        for fname, markers in WAF_REPRESENTATIVE_MARKERS.items():
            text = (PAYLOADS_DIR / fname).read_text(encoding="utf-8")
            payloads_joined = "\n".join(parse_payload_file(PAYLOADS_DIR / fname))
            for marker in markers:
                self.assertIn(
                    marker, payloads_joined,
                    f"{fname}: нет репрезентативного WAF-варианта {marker!r}",
                )
            self.assertIn(WAF_BYPASS_MARKER, text, f"{fname}: нет WAF-секции")

    def test_waf_payloads_are_non_destructive(self):
        """WAF-bypass пробы — только чтение/инъекция, без разрушающих операций."""
        for fname in WAF_BYPASS_FILES:
            for payload in waf_section_payloads(PAYLOADS_DIR / fname):
                self.assertFalse(
                    scanner_core._is_destructive_payload(payload),
                    f"{fname}: деструктивный payload в WAF-секции: {payload!r}",
                )

    def test_total_payload_count_grew(self):
        grand_total = sum(
            len(parse_payload_file(path)) for path in payload_files()
        )
        self.assertGreaterEqual(
            grand_total, MIN_TOTAL_PAYLOADS,
            f"общий объём payload-баз уменьшился: {grand_total} < {MIN_TOTAL_PAYLOADS}",
        )

    def test_waf_sections_load_through_loader(self):
        """WAF-строки реально попадают в load_payloads (файлы читаются чеками)."""
        from checks.catalog import payload_file_for  # type: ignore

        relevant_checks = [
            "sqli", "xss_reflected", "cmdi", "path_traversal", "ssrf", "xxe",
            "open_redirect", "crlf_injection", "ssti", "nosql_injection",
            "ldap_injection", "xpath_injection", "deserialization",
            "file_upload", "idor",
        ]
        for check_id in relevant_checks:
            fname = payload_file_for(check_id)
            self.assertIsNotNone(fname, f"{check_id}: payload-файл не найден в каталоге")
            loaded = set(scanner_core.load_payloads(check_id, safe_mode=False))
            self.assertTrue(loaded, f"{check_id}: load_payloads вернул пусто")

            def _expected(payload: str) -> str:
                # CRLF-набор нормализуется loader'ом перед использованием.
                if check_id == "crlf_injection":
                    return scanner_core._normalize_crlf_payload(payload)
                return payload

            missing = [
                p for p in waf_section_payloads(PAYLOADS_DIR / fname)
                if _expected(p) not in loaded
            ]
            self.assertEqual(
                missing, [],
                f"{check_id}: WAF-payload'ы не загружаются через load_payloads: {missing[:3]}",
            )


if __name__ == "__main__":
    unittest.main()
