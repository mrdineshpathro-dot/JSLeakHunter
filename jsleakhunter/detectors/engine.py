"""Extensible layered signature engine; detectors are data-driven and passive."""
import re
from pathlib import Path
from jsleakhunter.models import Finding
from jsleakhunter.entropy.scoring import shannon_entropy, looks_placeholder

PATTERNS = [
 ("AWS Access Key ID","Cloud","CRITICAL",r"\bAKIA[0-9A-Z]{16}\b",97),
 ("GitHub Token","Git","HIGH",r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",96),
 ("GitLab Token","Git","HIGH",r"\bglpat-[A-Za-z0-9_\-]{20,}\b",95),
 ("Google API Key","Cloud","HIGH",r"\bAIza[0-9A-Za-z_\-]{35}\b",95),
 ("Stripe Secret Key","SaaS","CRITICAL",r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",96),
 ("Slack Token","SaaS","HIGH",r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",94),
 ("SendGrid API Key","SaaS","HIGH",r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b",94),
 ("Twilio API Key","SaaS","HIGH",r"\bSK[0-9a-fA-F]{32}\b",91),
 ("JWT Token","Authentication","HIGH",r"\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b",92),
 ("Private Key","Private Key","CRITICAL",r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",99),
 ("Database URL","Database","CRITICAL",r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql)://[^\s\"']+",90),
 ("Bearer Token","Authentication","HIGH",r"\bBearer\s+[A-Za-z0-9_\-.=]{16,}",88),
]
GENERIC = re.compile(r"(?i)(api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key|database[_-]?url|credential)\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']")

class DetectorEngine:
 def __init__(self, custom_rules=None, excludes=None):
  self.patterns = list(PATTERNS); self.excludes = [re.compile(x, re.I) for x in (excludes or [])]
  for rule in custom_rules or []:
   try: self.patterns.append((rule['name'], rule.get('category','Custom'), rule.get('severity','MEDIUM').upper(), rule['regex'], int(rule.get('confidence',85))))
   except (KeyError, TypeError, ValueError): continue
 def scan(self, text: str, source: str) -> list[Finding]:
  out=[]; seen=set(); lines=text.splitlines() or [text]
  def add(name,cat,sev,val,conf,line,det):
   key=(name,val)
   if key in seen or any(x.search(val) for x in self.excludes) or looks_placeholder(val): return
   seen.add(key); ent=shannon_entropy(val); boost=4 if ent>=3.5 else (-12 if ent<2.0 else 0)
   out.append(Finding(name,cat,sev,max(1,min(99,conf+boost)),source,line,val,lines[line-1][:240],ent,det))
  for name,cat,sev,pat,conf in self.patterns:
   for m in re.finditer(pat,text): add(name,cat,sev,m.group(0),conf,text.count('\n',0,m.start())+1,"signature")
  for m in GENERIC.finditer(text):
   val=m.group(2); line=text.count('\n',0,m.start())+1
   add(f"Generic {m.group(1).replace('_',' ').title()}","Generic", "MEDIUM",val,72,line,"keyword-proximity")
  return out
