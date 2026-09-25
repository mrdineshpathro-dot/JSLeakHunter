from pathlib import Path

def load_config(path=None):
 p=Path(path or '~/.config/jsleakhunter/config.yaml').expanduser()
 if not p.exists(): return {}
 try:
  import yaml
  return yaml.safe_load(p.read_text()) or {}
 except Exception: return {}
