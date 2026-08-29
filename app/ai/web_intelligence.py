"""Apex web-intelligence layer for CyberShield AI.

This layer turns bounded public-web search into a structured research packet.
It is intentionally informational: web content can inform an answer, but can
never authorize host changes, quarantine, deletion, or other security actions.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from typing import Iterable
import hashlib
import re

from app.ai.web_research import WebResearch, WebResult


@dataclass(frozen=True)
class ResearchSource:
    title: str
    url: str
    domain: str
    snippet: str
    source_type: str
    trust: float
    fetched: bool = False
    content_excerpt: str = ""
    published: str | None = None


@dataclass(frozen=True)
class ResearchPacket:
    query: str
    sources: tuple[ResearchSource, ...]
    facts: tuple[str, ...]
    caveats: tuple[str, ...]
    queries: tuple[str, ...]
    generated_at: str
    research_id: str


class _PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg", "canvas"}:
            self.skip += 1
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "svg", "canvas"} and self.skip:
            self.skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self.skip:
            return
        text = re.sub(r"\s+", " ", data).strip()
        if text:
            self.parts.append(text)

    _in_title = False


class WebIntelligence:
    """Bounded, source-aware research orchestrator."""

    TRUST = {
        "gov": 0.98,
        "edu": 0.94,
        "official": 0.96,
        "docs": 0.94,
        "security_org": 0.93,
        "wiki": 0.70,
        "news": 0.78,
        "community": 0.58,
        "unknown": 0.48,
    }

    def __init__(self, searcher: WebResearch | None = None, max_sources: int = 8, fetch_pages: int = 3):
        self.searcher = searcher or WebResearch(timeout=7.0, max_results=max_sources)
        self.max_sources = max(3, min(int(max_sources), 10))
        self.fetch_pages = max(0, min(int(fetch_pages), 4))

    @staticmethod
    def _domain(url: str) -> str:
        try:
            return (urlparse(url).hostname or "").lower().strip(".")
        except Exception:
            return ""

    @classmethod
    def _trust(cls, domain: str, source: str, title: str) -> float:
        d = domain.lower()
        s = source.lower()
        t = title.lower()
        if d.endswith(".gov") or ".gov." in d:
            return cls.TRUST["gov"]
        if d.endswith(".edu") or ".ac." in d:
            return cls.TRUST["edu"]
        if s == "wikipedia" or "wikipedia.org" in d:
            return cls.TRUST["wiki"]
        if any(x in d for x in ("cisa.gov", "microsoft.com", "google.com", "mozilla.org", "apple.com", "nvd.nist.gov", "mitre.org")):
            return cls.TRUST["official"]
        if any(x in t for x in ("official documentation", "documentation", "security advisory", "security bulletin")):
            return cls.TRUST["docs"]
        if any(x in d for x in ("reddit.com", "stackoverflow.com", "stackexchange.com")):
            return cls.TRUST["community"]
        if any(x in d for x in ("reuters.com", "apnews.com", "bbc.com", "nytimes.com")):
            return cls.TRUST["news"]
        return cls.TRUST["unknown"]

    @staticmethod
    def _query_variants(query: str, language: str) -> list[str]:
        q = re.sub(r"\s+", " ", (query or "").strip())
        if not q:
            return []
        variants = [q]
        low = q.lower()
        if any(x in low for x in ("latest", "today", "bugun", "hozir", "current", "now", "so'nggi")):
            variants.append(q + " official advisory")
        if any(x in low for x in ("virus", "malware", "phishing", "ransomware", "cve", "vulnerability")):
            variants.append(q + " security advisory")
        if language == "uz":
            variants.append(q + " official source")
        return list(dict.fromkeys(variants))[:3]

    @staticmethod
    def _clean_excerpt(text: str, limit: int = 1800) -> str:
        text = re.sub(r"\s+", " ", text or "").strip()
        return text[:limit]

    def _fetch(self, result: WebResult) -> tuple[bool, str]:
        try:
            req = Request(result.url, headers={
                "User-Agent": "CyberShield-AI/24.0 (defensive research client)",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.1",
            })
            with urlopen(req, timeout=self.searcher.timeout) as response:
                content_type = str(response.headers.get("Content-Type", "")).lower()
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return False, ""
                raw = response.read(700_000).decode("utf-8", "replace")
            parser = _PageText()
            parser.feed(raw)
            return True, self._clean_excerpt(" ".join(parser.parts))
        except Exception:
            return False, ""

    def research(self, query: str, *, language: str = "uz") -> ResearchPacket:
        variants = self._query_variants(query, language)
        collected: list[WebResult] = []
        for variant in variants:
            # Keep the existing search() API so offline/unit-test monkeypatches remain valid.
            collected.extend(self.searcher.search(variant, language=language))
            if len(collected) >= self.max_sources * 2:
                break

        seen: set[str] = set()
        normalized: list[ResearchSource] = []
        for result in collected:
            url = result.url.split("#", 1)[0]
            domain = self._domain(url)
            key = hashlib.sha256(url.lower().encode()).hexdigest()[:20]
            if not domain or key in seen:
                continue
            seen.add(key)
            normalized.append(ResearchSource(
                title=result.title[:240], url=url, domain=domain,
                snippet=self._clean_excerpt(result.snippet, 700),
                source_type=result.source,
                trust=round(self._trust(domain, result.source, result.title), 2),
                published=result.published,
            ))

        normalized.sort(key=lambda x: (x.trust, bool(x.published), bool(x.snippet)), reverse=True)
        normalized = normalized[:self.max_sources]

        fetched = 0
        enriched: list[ResearchSource] = []
        for src in normalized:
            if fetched < self.fetch_pages and src.trust >= 0.78:
                ok, excerpt = self._fetch(WebResult(src.title, src.url, src.snippet, src.source_type))
                if ok and excerpt:
                    fetched += 1
                    src = ResearchSource(**{**asdict(src), "fetched": True, "content_excerpt": excerpt})
            enriched.append(src)

        facts: list[str] = []
        for src in enriched:
            text = src.content_excerpt or src.snippet
            if text:
                facts.append(f"[{len(facts)+1}] {src.title}: {text[:900]}")

        caveats: list[str] = []
        domains = {x.domain for x in enriched}
        if len(domains) < 2 and enriched:
            caveats.append("Source diversity is limited; treat the result as provisional.")
        if not enriched:
            caveats.append("No reachable public source was found; do not invent an answer.")
        if any(x.trust < .60 for x in enriched):
            caveats.append("Some sources have lower provenance confidence and should be corroborated.")

        now = datetime.now(timezone.utc).isoformat()
        rid = hashlib.sha256((query + "|" + now[:13] + "|" + "|".join(x.url for x in enriched)).encode()).hexdigest()[:24]
        return ResearchPacket(query[:1000], tuple(enriched), tuple(facts[:self.max_sources]), tuple(caveats), tuple(variants), now, rid)
