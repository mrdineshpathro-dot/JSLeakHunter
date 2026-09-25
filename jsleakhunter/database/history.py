import sqlite3, json, time
from pathlib import Path
class History:
 def __init__(self,path='~/.local/share/jsleakhunter/history.db'):
  self.path=Path(path).expanduser(); self.path.parent.mkdir(parents=True,exist_ok=True); self.db=sqlite3.connect(self.path); self.db.execute('create table if not exists scans(id integer primary key, created real, target text, findings text)'); self.db.commit()
 def add(self,target,findings):
  self.db.execute('insert into scans(created,target,findings) values(?,?,?)',(time.time(),target,json.dumps([f.to_dict() for f in findings]))); self.db.commit()
 def list(self): return self.db.execute('select id,created,target from scans order by id desc').fetchall()
