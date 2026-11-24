from datetime import datetime, timedelta

from syslogwatch.enrich import Reference, ReferenceResolver, keywords_from
from syslogwatch.rank import aggregate
from syslogwatch.parse import parse_line


def _findings(*texts, ip="192.168.1.1"):
    return aggregate([parse_line(t, source_ip=ip) for t in texts])


class FakeFetcher:
    def __init__(self, results=None, fail=False):
        self.calls = []
        self.results = results or [
            {"title": "dhcpd: no free leases", "url": "https://serverfault.com/q/1", "source": "stackexchange"}
        ]
        self.fail = fail

    def __call__(self, provider, query, timeout=8):
        self.calls.append((provider, query))
        if self.fail:
            raise OSError("sin red")
        return self.results


def test_curated_references_are_always_present(tmp_path):
    findings = _findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases")
    fetcher = FakeFetcher()
    ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher).resolve(findings)
    urls = [ref.url for ref in findings[0].references]
    assert "https://datatracker.ietf.org/doc/html/rfc3927" in urls


def test_external_results_are_added_once_and_marked_with_source(tmp_path):
    findings = _findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases")
    fetcher = FakeFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher)
    resolver.resolve(findings)
    external = [r for r in findings[0].references if r.source == "stackexchange"]
    assert external and external[0].title == "dhcpd: no free leases"
    assert len(set(r.url for r in findings[0].references)) == len(findings[0].references)


def test_cache_stops_the_second_lookup(tmp_path):
    findngs = _findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases")
    fetcher = FakeFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher)
    resolver.resolve(findngs)
    calls_first = len(fetcher.calls)
    resolver2 = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher)
    resolver2.resolve(_findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases"))
    assert len(fetcher.calls) == calls_first  # la segunda vez sale de caché


def test_expired_cache_is_refetched(tmp_path):
    findings = _findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases")
    fetcher = FakeFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher, ttl=timedelta(seconds=-1))
    resolver.resolve(findings)
    resolver.resolve(_findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases"))
    assert len(fetcher.calls) >= 2


def test_network_failure_degrades_but_does_not_raise(tmp_path):
    findings = _findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases")
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=FakeFetcher(fail=True))
    resolver.resolve(findings)
    assert resolver.degraded is True
    assert any(r.source == "catalogo" for r in findings[0].references)


def test_only_the_most_important_findings_are_enriched(tmp_path):
    texts = [
        "Nov 24 15:20:00 kern.crit kernel: Out of memory: Killed process 9",
        "Nov 24 15:20:01 user.info zcmdModuleCfg: CONFIG: Saving config - OK",
    ]
    findings = _findings(*texts)
    fetcher = FakeFetcher()
    ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher, min_score=40).resolve(findings)
    queried = {f.rule.id for f in findings if any(r.source == "stackexchange" for r in f.references)}
    assert "config-save-ok" not in queried


def test_a_barren_query_falls_back_to_the_message_keywords(tmp_path):
    class PickyFetcher:
        def __init__(self):
            self.calls = []

        def __call__(self, provider, query, timeout=8):
            self.calls.append((provider, query))
            if len(query.split()) > 4:  # la consulta larga no devuelve nada
                return []
            return [{"title": "free leases missing", "url": "https://serverfault.com/q/9", "source": "stackexchange"}]

    findings = _findings("Nov 24 15:20:00 daemon.err dhcpd: no free leases on subnet 192.168.1.0")
    fetcher = PickyFetcher()
    ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher).resolve(findings)
    assert any(r.url == "https://serverfault.com/q/9" for r in findings[0].references)
    assert len(fetcher.calls) >= 2  # probó la larga y luego la corta


def test_keywords_from_strips_timestamps_tags_and_numbers():
    text = "Nov 24 15:20:00 user.err dhcpd[123]: no free leases on subnet 192.168.1.0"
    keywords = keywords_from(text)
    assert "no free leases" in keywords
    assert "192.168.1.0" not in keywords


def test_reference_render_includes_https_link():
    ref = Reference(source="stackexchange", title="x", url="https://example.org/a")
    assert ref.markdown() == "[x](https://example.org/a)"
