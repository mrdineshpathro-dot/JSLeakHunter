import argparse, asyncio, json, sys, time, re
from pathlib import Path
from . import __version__, __author__
from .scanner import Scanner
from .detectors import DetectorEngine
from .reporters import write_report
from .database import History
from .config import load_config

try:
 from rich.console import Console
 from rich.panel import Panel
 from rich.table import Table
 from rich.progress import track
 console=Console()
except ImportError:
 class C:
  def print(self,*a,**k): print(*a)
 console=C()
 def Panel(x,**k): return x
 def Table(*a,**k): return None
 def track(x,**k): return x

BANNER='''[bold cyan]     ██╗███████╗██╗     ███████╗ █████╗ ██╗  ██╗██╗   ██╗████████╗███████╗██████╗
     ██║██╔════╝██║     ██╔════╝██╔══██╗██║ ██╔╝██║   ██║╚══██╔══╝██╔════╝██╔══██╗
     ██║███████╗██║     █████╗  ███████║█████╔╝ ██║   ██║   ██║   █████╗  ██████╔╝
     ██║╚════██║██║     ██╔══╝  ██╔══██║██╔═██╗ ██║   ██║   ██║   ██╔══╝  ██╔══██╗
     ██║███████║███████╗███████╗██║  ██║██║  ██╗╚██████╔╝   ██║   ███████╗██║  ██║
     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝[/bold cyan]'''
def banner(): console.print(BANNER); console.print('[bold white]JSLeakHunter[/] [cyan]v%s[/] — JavaScript Secret & Credential Scanner\n[dim]Author: %s · https://buymeacoffee.com/mrdineshpathro[/dim]'%( __version__,__author__))
def load_rules(path):
 if not path:return []
 try:
  import yaml; x=yaml.safe_load(Path(path).read_text()); return x if isinstance(x,list) else x.get('rules',[])
 except Exception as e: console.print(f'[yellow]Warning: custom rules unavailable: {e}[/]'); return []
def parser():
 p=argparse.ArgumentParser(prog='jsleakhunter',description='Defensive JavaScript Secret & Credential Scanner')
 sub=p.add_subparsers(dest='command')
 s=sub.add_parser('scan',help='scan URLs, files, directories, or stdin'); s.add_argument('targets',nargs='*'); s.add_argument('--js');s.add_argument('--file');s.add_argument('--dir');s.add_argument('--list');s.add_argument('--site');s.add_argument('--stdin',action='store_true');s.add_argument('--depth',type=int,default=1);s.add_argument('--threads',type=int,default=10);s.add_argument('--timeout',type=float,default=15);s.add_argument('--proxy');s.add_argument('--insecure',action='store_true');s.add_argument('--header',action='append',default=[]);s.add_argument('--output');s.add_argument('--show-secrets',action='store_true');s.add_argument('--redact',action='store_true');s.add_argument('--rules');s.add_argument('--exclude-pattern',action='append',default=[]);s.add_argument('--ci',action='store_true');s.add_argument('--fail-on',choices=['critical','high','medium','low','info']);s.add_argument('--no-banner',action='store_true')
 sub.add_parser('history'); sub.add_parser('version'); sub.add_parser('doctor'); sub.add_parser('rules'); sub.add_parser('about')
 return p
def do_scan(a):
 if not a.no_banner: banner()
 cfg=load_config(); targets=list(a.targets)
 if a.js: targets.append(a.js)
 if a.site: targets.append(a.site)
 if a.list: targets += [x.strip() for x in Path(a.list).read_text().splitlines() if x.strip()]
 if a.stdin: targets += [x.strip() for x in sys.stdin if x.strip()]
 files=[]
 for x in targets:
  if not re.match(r'^https?://',x): files.append(x)
 if a.file: files.append(a.file)
 if a.dir: files.append(a.dir)
 headers={}
 for h in a.header:
  if ':' in h: k,v=h.split(':',1);headers[k.strip()]=v.strip()
 engine=DetectorEngine(load_rules(a.rules),a.exclude_pattern)
 scanner=Scanner(a.threads,a.timeout,a.proxy,not a.insecure,headers,engine)
 start=time.perf_counter()
 if files: asyncio.run(scanner.scan_files(files))
 urls=[x for x in targets if re.match(r'^https?://',x)]
 if urls:
  try: asyncio.run(scanner.scan_urls(urls,True,a.depth))
  except RuntimeError as e: console.print(f'[red]✘ {e}[/]'); return 2
 scanner.summary.elapsed=time.perf_counter()-start
 findings=[]
 for f in scanner.findings:
  if not any(f.fingerprint==x.fingerprint for x in findings): findings.append(f)
 console.print(Panel(f'[bold]Targets[/]: {len(targets)}    [bold]Files[/]: {scanner.summary.files}    [bold]URLs[/]: {scanner.summary.urls}\n[bold]Findings[/]: {len(findings)}    [red]Critical: {sum(x.severity=="CRITICAL" for x in findings)}[/]    [yellow]High: {sum(x.severity=="HIGH" for x in findings)}[/]\n[dim]Elapsed: {scanner.summary.elapsed:.2f}s[/]',title='🔍 Scan Summary'))
 if findings:
  try:
   t=Table('Severity','Secret type','Confidence','Source','Line','Masked value')
   for f in findings:t.add_row(f.severity,f.secret_type,f'{f.confidence}%',f.source,str(f.line),f.masked(a.show_secrets,a.redact))
   console.print(t)
  except Exception:
   for f in findings: console.print(f'{f.severity} {f.secret_type} {f.confidence}% {f.source}:{f.line} {f.masked(a.show_secrets,a.redact)}')
 if a.output: write_report(findings,a.output,show=a.show_secrets,redact=a.redact); console.print(f'[green]✔ Report written to {a.output}[/]')
 if a.ci or a.fail_on:
  rank={'INFO':0,'LOW':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4}; threshold=rank.get((a.fail_on or 'high').upper(),3)
  return 1 if any(rank.get(f.severity,0)>=threshold for f in findings) else 0
 return 0
def main(argv=None):
 a=parser().parse_args(argv)
 if a.command in (None,'about'):
  if a.command is None: parser().print_help(); return 0
  banner(); console.print(Panel('Purpose: JavaScript Secret & Credential Scanner\nPlatform: Kali Linux\nSupport: https://buymeacoffee.com/mrdineshpathro.com',title='About')); return 0
 if a.command=='scan': return do_scan(a)
 if a.command=='version': print(__version__); return 0
 if a.command=='rules':
  from .detectors.engine import PATTERNS
  print(f'{len(PATTERNS)} built-in signatures; use --rules custom.yaml'); return 0
 if a.command=='history':
  for row in History().list(): print(row)
  return 0
 if a.command=='doctor':
  console.print(Panel(f'Python {sys.version.split()[0]}\nSQLite: OK\nConfig: {Path("~/.config/jsleakhunter/config.yaml").expanduser()}\nVersion: {__version__}',title='🩺 JSLeakHunter Doctor')); return 0
if __name__=='__main__': sys.exit(main())
