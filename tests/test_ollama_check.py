from unittest.mock import MagicMock, patch

from scripts.check_ollama import _NoRedirect, check


def test_health_check_disables_proxies_and_bounds_response_read():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"models": [{"name": "phi4-mini:latest"}]}'
    opener = MagicMock()
    opener.open.return_value = response
    with patch("scripts.check_ollama.build_opener", return_value=opener) as build:
        ok, message = check("http://localhost:11434", "phi4-mini:latest")
    assert ok and "available" in message
    assert any(type(handler).__name__ == "ProxyHandler" and handler.proxies == {}
               for handler in build.call_args.args)
    response.read.assert_called_once_with(1_000_001)


def test_health_check_rejects_external_userinfo_paths_and_query_without_network():
    invalid = [
        "https://localhost:11434",
        "http://example.com:11434",
        "http://user@localhost:11434",
        "http://localhost:11434/api/tags",
        "http://localhost:11434/?target=outside",
        "http://localhost:badport",
    ]
    with patch("scripts.check_ollama.build_opener") as build:
        for url in invalid:
            ok, message = check(url)
            assert not ok and message
    build.assert_not_called()


def test_health_checker_redirect_handler_refuses_redirects():
    handler = _NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/") is None


def test_health_check_rejects_oversized_response():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b"x" * 1_000_001
    opener = MagicMock()
    opener.open.return_value = response
    with patch("scripts.check_ollama.build_opener", return_value=opener):
        ok, message = check("http://127.0.0.1:11434")
    assert not ok and "exceeded" in message


def test_health_check_rejects_malformed_model_entries():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"models": [null]}'
    opener = MagicMock()
    opener.open.return_value = response
    with patch("scripts.check_ollama.build_opener", return_value=opener):
        ok, message = check("http://localhost:11434")
    assert not ok and "model entry" in message
