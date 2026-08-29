"""Local-first, multi-source web research for CyberShield AI.

Web research is informational only. It never authorizes host changes or security actions.
The client uses public HTTP endpoints, strict limits, source diversity, caching, and
explicit uncertainty. No API key is required.
"""
from __future__ import annotations
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json, re, time, threading
from typing import List

@dataclass
class WebResult:
    title: str
    url: str
    snippet: str
    source: str = "web"
    published: str | None = None
    score: float = 0.0

class _DDGParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.results=[]; self.mode=""; self.title=""; self.snippet=""; self.href=""
    def handle_starttag(self, tag, attrs):
        a=dict(attrs); cls=a.get("class","")
        if tag=="a" and "result__a" in cls:
            self.mode="title"; self.title=""; self.href=a.get("href","")
        elif tag in {"a","div"} and ("result__snippet" in cls or "result-snippet" in cls):
            self.mode="snippet"; self.snippet=""
    def handle_data(self,data):
        if self.mode=="title": self.title+=data
        elif self.mode=="snippet": self.snippet+=data
    def handle_endtag(self,tag):
        if tag=="a" and self.mode=="title":
            if self.href: self.results.append(WebResult(re.sub(r"\s+"," ",self.title).strip(),self.href,"", "duckduckgo"))
            self.mode=""
        elif self.mode=="snippet" and tag in {"div","a"}:
            if self.results and not self.results[-1].snippet: self.results[-1].snippet=re.sub(r"\s+"," ",self.snippet).strip()
            self.mode=""

def _decode(url):
    try:
        q=parse_qs(urlparse(url).query)
        return q.get("uddg",[url])[0]
    except Exception: return url

def _host(url):
    try:return (urlparse(url).hostname or "").lower()
    except Exception:return ""

class WebResearch:
    """Bounded multi-source research client with graceful offline behavior."""
    def __init__(self, timeout: float=7.0, max_results:int=8):
        self.timeout=max(.5,min(timeout,15.0)); self.max_results=max(1,min(max_results,10)); self._cache={}; self._lock=threading.Lock()
        self._ddg=["https://html.duckduckgo.com/html/?","https://lite.duckduckgo.com/lite/?"]
    def _get(self,url,accept="text/html"):
        req=Request(url,headers={"User-Agent":"CyberShield-AI/23.0 (defensive research client)","Accept":accept})
        with urlopen(req,timeout=self.timeout) as r:return r.read(900_000).decode("utf-8","replace")
    def _ddg_search(self,q,lang):
        for base in self._ddg:
            try:
                url=base+urlencode({"q":q,"kl":{"uz":"wt-wt","en":"us-en","ru":"ru-ru"}.get(lang,"wt-wt")})
                parser=_DDGParser(); parser.feed(self._get(url))
                out=[]
                for x in parser.results:
                    x.url=_decode(x.url); h=_host(x.url)
                    if not x.title or not x.url.startswith(("http://","https://")) or not h: continue
                    if "duckduckgo.com" in h: continue
                    out.append(x)
                    if len(out)>=self.max_results: break
                if out:return out
            except Exception: continue
        return []
    def _wiki(self,q,lang):
        # Wikipedia is useful for broad factual topics, but is never treated as a security verdict.
        try:
            langcode={"uz":"uz","en":"en","ru":"ru"}.get(lang,"en")
            data=json.loads(self._get("https://"+langcode+".wikipedia.org/w/api.php?"+urlencode({"action":"query","list":"search","srsearch":q,"format":"json","utf8":1,"srlimit":4}),"application/json"))
            out=[]
            for item in data.get("query",{}).get("search",[]):
                title=item.get("title",""); snippet=re.sub(r"<[^>]+>","",item.get("snippet", ""))
                if title: out.append(WebResult(title,"https://"+langcode+".wikipedia.org/wiki/"+title.replace(" ","_"),snippet,"wikipedia",score=.45))
            return out
        except Exception:return []
    def search(self,query:str,*,language="uz") -> List[WebResult]:
        q=re.sub(r"\s+"," ",(query or "").strip())
        if not q:return []
        key=(q.lower(),language)
        with self._lock:
            hit=self._cache.get(key)
            if hit and time.time()-hit[0] < 180: return list(hit[1])
        results=self._ddg_search(q,language)
        # Add an independent broad source for knowledge questions; never use it as malware proof.
        if len(results)<self.max_results and len(q.split())<=12:
            results += self._wiki(q,language)
        # Rank by source diversity and useful URL/title signals; deduplicate hosts/URLs.
        seen=set(); out=[]
        for r in results:
            u=r.url.split("#",1)[0]; keyu=u.lower()
            if keyu in seen: continue
            seen.add(keyu)
            host=_host(u); r.score += .15 if u.startswith("https://") else 0
            r.score += .10 if host and not any(x in host for x in ("example.com","localhost")) else 0
            out.append(r)
        out.sort(key=lambda x:x.score,reverse=True)
        out=out[:self.max_results]
        with self._lock:self._cache[key]=(time.time(),list(out))
        return out
