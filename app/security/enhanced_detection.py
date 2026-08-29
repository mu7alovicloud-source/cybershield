"""Layered defensive detection helpers.

Purely observational/static: never executes files or follows URLs.  The helpers
normalize evidence from filename/content and URL syntax so the core engines can
correlate independent indicators without pretending that heuristics are proof.
"""
from __future__ import annotations
import ipaddress, re, unicodedata
from pathlib import Path
from urllib.parse import urlsplit, unquote

HIGH_RISK_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "gq", "tk", "ml", "cf"}
DANGEROUS_EXTENSIONS = {".exe",".scr",".msi",".js",".jse",".vbs",".vbe",".ps1",".bat",".cmd",".hta",".iso",".lnk",".jar"}
LURE_WORDS = {"login","signin","verify","verification","password","wallet","payment","invoice","account","security","unlock","confirm","update","support","reset","suspended"}
BRANDS = {"microsoft","office","google","apple","paypal","amazon","netflix","steam","telegram","facebook","instagram","binance","adobe","docusign","dropbox","onedrive","payme","click","uzum","humo"}
CONFUSABLES = str.maketrans({"а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","к":"k","м":"m","т":"t","і":"i","ј":"j"})

def _registrable(host: str) -> str:
    labels=[x for x in host.lower().strip('.').split('.') if x]
    return '.'.join(labels[-2:]) if len(labels)>=2 else host.lower().strip('.')

def url_signals(raw_url: str) -> list[dict]:
    raw=(raw_url or '').strip(); out=[]
    try:
        u=urlsplit(raw if '://' in raw else 'https://'+raw)
        host=(u.hostname or '').lower().rstrip('.')
    except ValueError:
        return [{"code":"URL_PARSE","score":35,"severity":"high","reason":"URL parsing failed"}]
    if not host: return [{"code":"URL_NO_HOST","score":35,"severity":"high","reason":"URL has no hostname"}]
    try: ipaddress.ip_address(host); out.append({"code":"URL_IP","score":28,"severity":"high","reason":"URL uses a raw IP address"})
    except ValueError: pass
    labels=host.split('.')
    if len(labels)>4: out.append({"code":"URL_DEEP_SUBDOMAIN","score":10,"severity":"medium","reason":"Deep subdomain chain"})
    if labels and labels[-1] in HIGH_RISK_TLDS: out.append({"code":"URL_RISK_TLD","score":8,"severity":"medium","reason":f"High-risk TLD: .{labels[-1]}"})
    if any(ord(c)>127 for c in host):
        normalized=unicodedata.normalize('NFKC',host).translate(CONFUSABLES)
        if normalized!=host: out.append({"code":"URL_HOMOGRAPH","score":30,"severity":"high","reason":"Unicode/confusable hostname detected"})
        else: out.append({"code":"URL_UNICODE","score":15,"severity":"medium","reason":"Non-ASCII hostname"})
    decoded=unquote(raw).lower(); tokens=set(re.findall(r'[a-z0-9]+', decoded))
    lure=sorted(tokens & LURE_WORDS)
    if lure: out.append({"code":"URL_LURE","score":min(24,5+4*len(lure)),"severity":"medium","reason":"Credential/payment lure terms: "+', '.join(lure[:8])})
    reg=_registrable(host)
    for brand in BRANDS:
        if brand in host and not reg.startswith(brand+'.'):
            out.append({"code":"URL_BRAND_MISUSE","score":24,"severity":"high","reason":f"Brand name appears in unrelated registrable domain: {brand}"}); break
    if '@' in raw: out.append({"code":"URL_USERINFO","score":28,"severity":"high","reason":"URL contains user-info/@ deception pattern"})
    if raw.count('%')>=8: out.append({"code":"URL_OBFUSCATION","score":14,"severity":"medium","reason":"Heavy percent-encoding"})
    if re.search(r'(?i)(https?%3a|https?://.*https?://)',raw): out.append({"code":"URL_NESTED_REDIRECT","score":24,"severity":"high","reason":"Nested/encoded redirect URL"})
    if re.search(r'(?i)\.(?:exe|scr|msi|js|jse|vbs|bat|cmd|ps1|hta|iso|lnk)(?:$|[?#])',u.path or ''): out.append({"code":"URL_PAYLOAD","score":26,"severity":"high","reason":"URL path ends in executable/script payload"})
    if len(raw)>220: out.append({"code":"URL_LONG","score":8,"severity":"medium","reason":"Unusually long URL"})
    return out

def file_name_signals(path: str|Path) -> list[dict]:
    p=Path(path); name=p.name.lower(); out=[]; suffixes=[s.lower() for s in p.suffixes]
    if len(suffixes)>=2 and suffixes[-1] in DANGEROUS_EXTENSIONS:
        if suffixes[-2] in {'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.jpg','.jpeg','.png','.txt','.rtf','.zip'}:
            out.append({"code":"DOUBLE_EXTENSION","score":30,"severity":"high","reason":"Document/media double-extension masquerade"})
    if name.startswith('.') and p.suffix.lower() in DANGEROUS_EXTENSIONS: out.append({"code":"HIDDEN_EXECUTABLE","score":12,"severity":"medium","reason":"Hidden executable/script filename"})
    return out
