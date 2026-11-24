"""Referencias externas: por qué falla y cómo se resuelve.

Tres capas, de más barata a más cara:

1. **Catálogo** — refs curadas dentro de cada regla (siempre presentes, sin red).
2. **Stack Exchange** — `api.stackexchange.com` (Server Fault, Super User, Stack Overflow).
3. **GitHub** — `api.github.com/search/issues` (mismo mensaje en el firmware o en el driver).

Todo se cachea en disco con TTL, y un fallo de red degrada el informe en vez de
romperlo: el análisis local nunca depende de Internet.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .rank import Finding

PROVIDERS: Tuple[str, ...] = ("stackexchange", "github")

STACKEXCHANGE_SITES = ("serverfault", "superuser", "stackoverflow")

USER_AGENT = "syslogwatch/0.1 (+local)"

_HEADER_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s*")
_LEVEL_RE = re.compile(r"\b[a-z0-9]+\.[a-z]+\b\s*")
_TAG_RE = re.compile(r"^[A-Za-z0-9_.\-/]+(\[\d+\])?:\s*")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"\b\d+\b")
_NON_WORD_RE = re.compile(r"[^A-Za-z0-9 _\-:./]+")

# Palabras sin valor de búsqueda; "no"/"not" se conservan porque invierten el sentido del error.
_STOPWORDS = frozenset(
    "the a an of on in to at for from with by as is are was were be been and or that this it its "
    "if then than which per via".split()
)


@dataclass(frozen=True)
class Reference:
    source: str
    title: str
    url: str
    score: Optional[int] = None

    def markdown(self) -> str:
        return f"[{self.title}]({self.url})"


def keywords_from(text: str, max_words: int = 8) -> str:
    """Extrae los términos útiles de un mensaje syslog para buscar en la web."""
    cleaned = _HEADER_RE.sub("", text or "")
    cleaned = _LEVEL_RE.sub(" ", cleaned)
    cleaned = _TAG_RE.sub("", cleaned)
    cleaned = _IPV4_RE.sub(" ", cleaned)
    cleaned = _HEX_RE.sub(" ", cleaned)
    cleaned = _NON_WORD_RE.sub(" ", cleaned)
    words = [
        w
        for w in cleaned.split()
        if len(w) > 1 and not w.isdigit() and w.lower() not in _STOPWORDS
    ]
    words = [w for w in (word.strip("-") for word in words) if w]
    return " ".join(words[:max_words])


def _tokens(text: str) -> set:
    return {word for word in re.findall(r"[a-z0-9]{3,}", (text or "").lower())}


def relevance(query: str, title: str) -> int:
    """Cuántas palabras de la consulta aparecen en el título del resultado."""
    return len(_tokens(query) & _tokens(title))


def rank_results(results: Sequence[dict], query: str, limit: int = 3) -> List[dict]:
    """Descarta lo que no comparte nada con la consulta y deja los más útiles.

    Las APIs devuelven parecidos semánticos muy flojos: sin este filtro, un fallo
    de OOM en un router acaba enlazando issues de integración continua ajenos.
    Con consultas largas se exigen dos palabras en común, no una, porque una sola
    («memory», «error») la comparte medio Internet.
    """
    threshold = 2 if len(_tokens(query)) >= 4 else 1
    scored = [
        (relevance(query, item.get("title", "")), int(item.get("score") or 0), item)
        for item in results
    ]
    relevant = [triple for triple in scored if triple[0] >= threshold]
    relevant.sort(key=lambda triple: (-triple[0], -triple[1]))
    return [item for _, _, item in relevant[:limit]]


def _http_get(url: str, timeout: int = 8) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URLs propias, https
        return json.loads(response.read().decode("utf-8", "replace"))


def _normalise_items(items, source: str, url_key: str, score_key: str) -> List[dict]:
    """Forma común de resultado: título sin entidades HTML, URL y una nota."""
    results = []
    for item in items:
        results.append(
            {
                "source": source,
                "title": html.unescape(item.get("title", "")).strip(),
                "url": item.get(url_key, ""),
                "score": int(item.get(score_key, 0)),
            }
        )
    return [r for r in results if r["url"] and r["title"]]


def stackexchange_search(query: str, timeout: int = 8, site: str = "serverfault") -> List[dict]:
    url = (
        "https://api.stackexchange.com/2.3/search/advanced"
        f"?order=desc&sort=relevance&pagesize=5&site={site}&q={urllib.parse.quote(query)}"
    )
    return _normalise_items(_http_get(url, timeout=timeout).get("items", []), "stackexchange", "link", "score")


def github_search(query: str, timeout: int = 8) -> List[dict]:
    url = f"https://api.github.com/search/issues?per_page=5&q={urllib.parse.quote(query)}"
    return _normalise_items(_http_get(url, timeout=timeout).get("items", []), "github", "html_url", "comments")


def http_fetcher(provider: str, query: str, timeout: int = 8) -> List[dict]:
    """Buscador real. Se inyecta en el resolvedor para poder testear sin red."""
    if provider == "stackexchange":
        merged: List[dict] = []
        for site in STACKEXCHANGE_SITES:
            try:
                merged.extend(stackexchange_search(query, timeout=timeout, site=site))
            except (urllib.error.URLError, OSError, ValueError):
                continue
            if len(merged) >= 4:
                break
        return merged[:5]
    if provider == "github":
        return github_search(query, timeout=timeout)
    raise ValueError(f"proveedor desconocido: {provider}")


class ReferenceResolver:
    """Amplía cada hallazgo con causas y remedios de fuera, con caché y degradación suave."""

    def __init__(
        self,
        cache_path: Optional[Path] = None,
        fetcher: Optional[Callable[..., List[dict]]] = None,
        ttl: timedelta = timedelta(days=7),
        min_score: int = 40,
        max_findings: int = 6,
        providers: Sequence[str] = PROVIDERS,
        timeout: int = 8,
    ):
        self.cache_path = Path(cache_path) if cache_path else None
        self.fetcher = fetcher or http_fetcher
        self.ttl = ttl
        self.min_score = min_score
        self.max_findings = max_findings
        self.providers = tuple(providers)
        self.timeout = timeout
        self.degraded = False
        self.queries: List[str] = []
        self._cache: Dict[str, dict] = self._load_cache()

    # -- caché ------------------------------------------------------------
    def _load_cache(self) -> Dict[str, dict]:
        if not self.cache_path or not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _key(provider: str, query: str) -> str:
        return hashlib.sha1(f"{provider}:{query}".encode("utf-8")).hexdigest()

    def _cached(self, provider: str, query: str) -> Optional[List[dict]]:
        record = self._cache.get(self._key(provider, query))
        if not record:
            return None
        try:
            stored = datetime.fromisoformat(record["at"])
        except (KeyError, ValueError):
            return None
        if datetime.now() - stored > self.ttl:
            return None
        return record.get("results", [])

    def _fetch(self, provider: str, query: str) -> List[dict]:
        cached = self._cached(provider, query)
        if cached is not None:
            return cached
        try:
            results = self.fetcher(provider, query, timeout=self.timeout) or []
        except Exception:  # noqa: BLE001 - cualquier fallo de red degrada, no rompe
            self.degraded = True
            results = []
        self._cache[self._key(provider, query)] = {
            "at": datetime.now().isoformat(timespec="seconds"),
            "provider": provider,
            "query": query,
            "results": results,
        }
        return results

    # -- API pública ------------------------------------------------------
    def query_for(self, finding: Finding) -> str:
        if finding.rule.query:
            return finding.rule.query
        sample = finding.samples[0] if finding.samples else finding.rule.title
        return keywords_from(sample)

    def query_candidates(self, finding: Finding) -> List[str]:
        """Escalera de consultas: de la más específica a la más corta.

        Los buscadores devuelven cero resultados con frases largas, así que si la
        primera no da nada se reintenta con las palabras clave del mensaje real.
        """
        candidates = [self.query_for(finding)]
        sample = finding.samples[0] if finding.samples else ""
        if sample:
            candidates.append(" ".join(keywords_from(sample, max_words=4).split()[:4]))
        ordered = []
        for candidate in candidates:
            if candidate and candidate not in ordered:
                ordered.append(candidate)
        return ordered

    def _search(self, provider: str, finding: Finding) -> List[dict]:
        for query in self.query_candidates(finding):
            ranked = rank_results(self._fetch(provider, query), query)
            if ranked:
                if query not in self.queries:
                    self.queries.append(query)
                return ranked
        return []

    def _external(self, position: int, finding: Finding) -> List[Reference]:
        """Referencias de fuera, sólo para los hallazgos que merecen la pena."""
        if position >= self.max_findings or finding.score < self.min_score or not self.providers:
            return []
        refs: List[Reference] = []
        for provider in self.providers:
            for item in self._search(provider, finding):
                refs.append(
                    Reference(
                        source=item.get("source", provider),
                        title=item.get("title", "sin título"),
                        url=item.get("url", ""),
                        score=item.get("score"),
                    )
                )
        return refs

    def resolve(self, findings: Iterable[Finding]) -> List[Finding]:
        """Añade referencias a los hallazgos (mutándolos) y devuelve la lista."""
        findings = list(findings)
        for position, finding in enumerate(findings):
            curated = [Reference("catalogo", ref.title, ref.url) for ref in finding.rule.refs]
            refs = curated + self._external(position, finding)
            seen = set()
            unique = []
            for ref in refs:
                if not ref.url or ref.url in seen:
                    continue
                seen.add(ref.url)
                unique.append(ref)
            finding.references = unique
        self._save_cache()
        return findings
