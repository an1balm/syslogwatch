import io
import json
import urllib.error

import pytest

from syslogwatch import enrich


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _fake_urlopen(payload, capture=None, raise_error=None):
    def opener(request, timeout=None):
        if capture is not None:
            capture.append(request.full_url)
        if raise_error is not None:
            raise raise_error
        return FakeResponse(json.dumps(payload).encode())

    return opener


def test_stackexchange_search_unescapes_titles_and_keeps_links(monkeypatch):
    payload = {
        "items": [
            {"title": "DHCP logs showing (no free leases)", "link": "https://serverfault.com/q/1110324", "score": 12},
            {"title": "", "link": "https://serverfault.com/q/2", "score": 1},
        ]
    }
    monkeypatch.setattr(enrich.urllib.request, "urlopen", _fake_urlopen(payload))
    results = enrich.stackexchange_search("no free leases")
    assert results[0]["title"] == "DHCP logs showing (no free leases)"
    assert results[0]["url"] == "https://serverfault.com/q/1110324"
    assert len(results) == 1  # el título vacío se descarta


def test_github_search_returns_issue_links(monkeypatch):
    payload = {"items": [{"title": "ath11k crash &amp; OOM", "html_url": "https://github.com/o/r/issues/1", "comments": 7}]}
    monkeypatch.setattr(enrich.urllib.request, "urlopen", _fake_urlopen(payload))
    results = enrich.github_search("out of memory")
    assert results == [
        {"source": "github", "title": "ath11k crash & OOM", "url": "https://github.com/o/r/issues/1", "score": 7}
    ]


def test_http_fetcher_routes_each_provider(monkeypatch):
    seen = []
    payload = {"items": [{"title": "t", "link": "https://serverfault.com/q/1", "html_url": "https://github.com/a/b/issues/2"}]}
    monkeypatch.setattr(enrich.urllib.request, "urlopen", _fake_urlopen(payload, capture=seen))
    enrich.http_fetcher("stackexchange", "query")
    enrich.http_fetcher("github", "query")
    assert any("api.stackexchange.com" in url for url in seen)
    assert any("api.github.com" in url for url in seen)
    with pytest.raises(ValueError):
        enrich.http_fetcher("noexiste", "query")


def test_http_fetcher_survives_a_failing_site_and_moves_on(monkeypatch):
    payload = {"items": [{"title": "t", "link": "https://serverfault.com/q/1"}]}
    monkeypatch.setattr(
        enrich.urllib.request, "urlopen", _fake_urlopen(payload, raise_error=urllib.error.URLError("boom"))
    )
    assert enrich.http_fetcher("stackexchange", "query") == []


def test_http_get_sends_a_user_agent(monkeypatch):
    captured = {}

    def opener(request, timeout=None):
        captured["ua"] = request.get_header("User-agent")
        return FakeResponse(b'{"items": []}')

    monkeypatch.setattr(enrich.urllib.request, "urlopen", opener)
    enrich._http_get("https://api.github.com/x")
    assert captured["ua"] == enrich.USER_AGENT
