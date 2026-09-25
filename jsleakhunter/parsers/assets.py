import re
from urllib.parse import urljoin, urldefrag

def discover_assets(html, base):
    found=[]
    for src in re.findall(r'''<(?:script|link)[^>]+(?:src|href)=["']([^"']+)["']''', html, re.I):
        u=urldefrag(urljoin(base,src))[0]
        if u not in found: found.append(u)
    return found

def extract_inline(html):
    return re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', html, re.I|re.S)
