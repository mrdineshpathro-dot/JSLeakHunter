import csv, json, html
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import asdict
from jsleakhunter.models import Finding

def payload(findings, show=False, redact=False): return {'tool':'JSLeakHunter','version':'1.0.0','generated_at':datetime.now(timezone.utc).isoformat(),'findings':[f.to_dict(show,redact) for f in findings]}
def write_report(findings,path,fmt=None,show=False,redact=False):
 p=Path(path); fmt=(fmt or p.suffix.lstrip('.') or 'json').lower(); data=payload(findings,show,redact)
 if fmt=='json': p.write_text(json.dumps(data,indent=2))
 elif fmt=='csv':
  rows=[f.to_dict(show,redact) for f in findings]
  with p.open('w',newline='') as h:
   w=csv.DictWriter(h,fieldnames=list(rows[0]) if rows else ['secret_type']); w.writeheader(); w.writerows(rows)
 elif fmt in ('md','markdown'):
  p.write_text('# JSLeakHunter Report\n\n| Severity | Type | Confidence | Source | Line | Value |\n|---|---|---:|---|---:|---|\n' + ''.join(f'| {f.severity} | {f.secret_type} | {f.confidence}% | {f.source} | {f.line} | {f.masked(show,redact)} |\n' for f in findings))
 elif fmt in ('html','htm'):
  rows=''.join(f'<tr><td class="{f.severity.lower()}">{html.escape(f.severity)}</td><td>{html.escape(f.secret_type)}</td><td>{f.confidence}%</td><td>{html.escape(f.source)}</td><td>{f.line}</td><td><code>{html.escape(f.masked(show,redact))}</code></td></tr>' for f in findings)
  p.write_text(f'''<!doctype html><meta charset="utf-8"><title>JSLeakHunter Report</title><style>body{{font:15px system-ui;background:#101322;color:#e8ecff;padding:32px}}table{{width:100%;border-collapse:collapse}}td,th{{padding:12px;border-bottom:1px solid #303957;text-align:left}}.critical{{color:#ff668d}}.high{{color:#ffb86b}}.medium{{color:#ffe66d}}code{{color:#8be9fd}}</style><h1>🔍 JSLeakHunter</h1><p>Generated {data['generated_at']} · {len(findings)} findings</p><table><tr><th>Severity</th><th>Type</th><th>Confidence</th><th>Source</th><th>Line</th><th>Value</th></tr>{rows}</table>''')
 else: raise ValueError(f'Unsupported report format: {fmt}')
 return p
