"""Safe local/remote scan orchestration. Network requests are GET-only and passive."""
import asyncio, time, json
from pathlib import Path
from urllib.parse import urlparse
from .detectors import DetectorEngine
from .models import ScanSummary, Finding
from .parsers import discover_assets, extract_inline

class Scanner:
 def __init__(self, threads=10, timeout=15, proxy=None, verify=True, headers=None, engine=None, max_bytes=15_000_000):
  self.threads=threads; self.timeout=timeout; self.proxy=proxy; self.verify=verify; self.headers=headers or {}; self.engine=engine or DetectorEngine(); self.max_bytes=max_bytes; self.findings=[]; self.sources=set(); self.urls=set(); self.summary=ScanSummary()
 async def scan_files(self, paths):
  for p in paths:
   path=Path(p)
   if path.is_dir(): await self.scan_files([x for x in path.rglob('*') if x.is_file()])
   elif path.is_file():
    try: self.scan_text(path.read_text(errors='replace'), str(path))
    except OSError: pass
  return self.findings
 def scan_text(self,text,source):
  self.sources.add(source); self.summary.files += 1; self.findings.extend(self.engine.scan(text,source))
 async def scan_urls(self, urls, discover=True, depth=0):
  try:
   import httpx
  except ImportError as exc:
   raise RuntimeError('Remote scanning requires httpx; install requirements.txt') from exc
  queue=list(dict.fromkeys(urls)); sem=asyncio.Semaphore(self.threads); visited=set(); next_urls=[]
  limits=httpx.Limits(max_connections=self.threads, max_keepalive_connections=self.threads)
  async with httpx.AsyncClient(headers=self.headers, timeout=self.timeout, proxy=self.proxy, verify=self.verify, follow_redirects=True, limits=limits) as client:
   async def one(url):
    if url in visited: return
    visited.add(url); self.urls.add(url)
    async with sem:
     try:
      r=await client.get(url); r.raise_for_status(); text=r.text[:self.max_bytes]
      self.scan_text(text,url)
      if discover and ('html' in r.headers.get('content-type','') or '<script' in text.lower()):
       for asset in discover_assets(text,url):
        if asset not in visited and (asset.endswith(('.js','.mjs','.json','.map')) or depth>0): next_urls.append(asset)
       for inline in extract_inline(text): self.scan_text(inline,url+'#inline')
     except (httpx.HTTPError, UnicodeError): return
   await asyncio.gather(*(one(u) for u in queue))
   if next_urls: await self.scan_urls(next_urls,False,0)
  self.summary.urls=len(self.urls); self.summary.findings=len(self.findings); self.summary.severities={}
  for f in self.findings: self.summary.severities[f.severity]=self.summary.severities.get(f.severity,0)+1
  return self.findings
 def scan_text_sync(self,text,source): self.scan_text(text,source); return self.findings
