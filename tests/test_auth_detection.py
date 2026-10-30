"""Auth-error detection не должна путать обычные страницы со словом «login».

До фикса любая страница, в теле которой встречалось слово "login" (меню, ссылка
Logout и т.п.), считалась «сессия истекла» → каждый запрос скана запускал
relogin, из-за чего скан «висел» после нескольких запросов.
"""

import scanner_core


def test_normal_page_with_login_word_is_not_auth_error():
    page = "<html><body><nav><a>Login</a> <a>Logout</a></nav>Привет</body></html>"
    assert scanner_core._is_auth_error_response(200, {}, page) is False


def test_login_form_is_auth_error():
    page = ('<html><form method="post"><input type="text" name="user">'
            '<input type="password" name="pass"></form></html>')
    assert scanner_core._is_auth_error_response(200, {}, page) is True


def test_401_403_and_login_redirect_are_auth_errors():
    assert scanner_core._is_auth_error_response(401, {}, "") is True
    assert scanner_core._is_auth_error_response(403, {}, "") is True
    assert scanner_core._is_auth_error_response(
        302, {"Location": "/login.php"}, "") is True
    assert scanner_core._is_auth_error_response(
        302, {"Location": "/portal.php"}, "") is False


def test_http_redirect_away_from_login_is_not_auth_error():
    assert scanner_core._is_auth_error_response(
        301, {"Location": "https://example.com/home"}, "moved") is False
    assert scanner_core._is_auth_error_response(200, {"Location": "/login"}, "redirect body") is True


def test_session_cookie_overrides_stale_imported_cookie():
    merged = scanner_core._merge_session_headers(
        {"Cookie": "security_level=0; PHPSESSID=OLD", "X-Test": "1"},
        {"Cookie": "PHPSESSID=NEW"},
    )
    assert merged["Cookie"] == "security_level=0; PHPSESSID=NEW"
    assert "PHPSESSID=OLD" not in merged["Cookie"]
    assert merged["X-Test"] == "1"
    assert scanner_core._merge_cookie_headers("a=1; b=2", "b=3") == "a=1; b=3"
