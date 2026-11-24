"""Bordes de enrich: caché, escalera de consultas y umbrales de relevancia."""

import json

import pytest

from syslogwatch.enrich import ReferenceResolver, rank_results
from syslogwatch.parse import parse_line
from syslogwatch.rank import aggregate


def _finding(text="Nov 24 15:20:00 daemon.err dhcpd: no free leases", ip="192.168.1.1"):
    return aggregate([parse_line(text, source_ip=ip)])[0]


class CountingFetcher:
    def __init__(self, results=None):
        self.calls = []
        self.results = results if results is not None else [
            {"title": "no free leases fix", "url": "https://serverfault.com/q/1", "source": "stackexchange", "score": 5}
        ]

    def __call__(self, provider, query, timeout=8):
        self.calls.append((provider, query))
        return list(self.results)


# -- rank_results -------------------------------------------------------

def test_exactly_four_query_tokens_require_two_matches():
    query = "dhcp no free leases pool"  # 4 tokens con valor de búsqueda
    single = [{"title": "free as in beer", "url": "u1", "score": 10}]
    double = [{"title": "no free leases left", "url": "u2", "score": 1}]
    assert rank_results(single, query) == []
    assert rank_results(double, query)


def test_short_query_accepts_a_single_match():
    assert rank_results([{"title": "leases", "url": "u1", "score": 0}], "no leases")


def test_zero_matches_are_dropped_even_with_a_short_query():
    assert rank_results([{"title": "nothing here", "url": "u1", "score": 99}], "leases") == []


def test_results_are_ordered_by_overlap_then_by_api_score():
    query = "no free leases pool"
    results = [
        {"title": "leases problem", "url": "u1", "score": 1},           # 1 acierto
        {"title": "no free leases", "url": "u2", "score": 1},           # 2 aciertos
        {"title": "free leases pool", "url": "u3", "score": 1},         # 2 aciertos, mismo score
        {"title": "no free leases pool", "url": "u4", "score": 1},      # 3 aciertos
    ]
    assert [item["url"] for item in rank_results(results, query)] == ["u3", "u4", "u2"]


def test_limit_truncates_to_three_results():
    query = "no free leases"
    results = [{"title": "no free leases %d" % i, "url": "u%d" % i, "score": i} for i in range(6)]
    assert len(rank_results(results, query)) == 3


# -- resolvedor ---------------------------------------------------------

def test_sorting_is_stable_for_equal_overlap_and_score():
    query = "free leases"
    results = [
        {"title": "free leases a", "url": "u1", "score": 0},
        {"title": "free leases b", "url": "u2", "score": 0},
    ]
    assert [item["url"] for item in rank_results(results, query)] == ["u1", "u2"]


def test_no_cache_path_means_no_writes_and_no_errors(tmp_path):
    resolver = ReferenceResolver(cache_path=None, fetcher=CountingFetcher())
    finding = _finding()
    resolver.resolve([finding])
    assert finding.references  # funciona igual sin caché en disco


def test_corrupt_cache_file_is_ignored(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("{esto no es json", encoding="utf-8")
    resolver = ReferenceResolver(cache_path=path, fetcher=CountingFetcher())
    assert resolver._cache == {}


def test_cache_entry_without_timestamp_is_treated_as_missing(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text(json.dumps({"abc": {"results": [{"title": "x"}]}}), encoding="utf-8")
    resolver = ReferenceResolver(cache_path=path, fetcher=CountingFetcher())
    assert resolver._cached("github", "cualquiera") is None


def test_cache_write_failure_does_not_break_the_run(tmp_path):
    blocker = tmp_path / "no-es-directorio"
    blocker.write_text("x", encoding="utf-8")
    resolver = ReferenceResolver(cache_path=blocker / "cache.json", fetcher=CountingFetcher())
    finding = _finding()
    resolver.resolve([finding])  # no debe lanzar
    assert finding.references


def test_no_providers_means_no_external_lookup(tmp_path):
    fetcher = CountingFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher, providers=())
    resolver.resolve([_finding()])
    assert fetcher.calls == []


def test_zero_max_findings_disables_external_lookup(tmp_path):
    fetcher = CountingFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher, max_findings=0)
    resolver.resolve([_finding()])
    assert fetcher.calls == []


def test_resolver_stops_after_the_finding_limit(tmp_path):
    fetcher = CountingFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher, max_findings=1)
    a = _finding("Nov 24 15:20:00 kern.err kernel: nf_conntrack: table full, dropping packet")
    b = _finding("Nov 24 15:20:01 daemon.err dhcpd: no free leases")
    resolver.resolve([a, b])
    externals = [ref for ref in b.references if ref.source != "catalogo"]
    assert externals == []  # el segundo hallazgo ya quedó fuera del límite


def test_fetcher_that_always_fails_marks_the_resolver_degraded(tmp_path):
    def broken(provider, query, timeout=8):
        raise OSError("sin red")

    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=broken)
    resolver.resolve([_finding()])
    assert resolver.degraded is True


def test_duplicate_urls_from_two_providers_are_collapsed(tmp_path):
    shared = {"title": "no free leases", "url": "https://example.org/x", "score": 1}
    fetcher = CountingFetcher([shared])
    finding = _finding()
    ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher).resolve([finding])
    urls = [ref.url for ref in finding.references]
    assert urls.count("https://example.org/x") == 1


def test_queries_recorded_exclude_duplicates(tmp_path):
    fetcher = CountingFetcher()
    resolver = ReferenceResolver(cache_path=tmp_path / "c.json", fetcher=fetcher)
    resolver.resolve([_finding()])
    assert len(resolver.queries) == len(set(resolver.queries))
