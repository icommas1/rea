"""Measure sampled aggregate RSS for one local native analysis; Linux only."""
import json, os, subprocess, time
from pathlib import Path
root=Path(__file__).resolve().parent.parent
code="""
import {analyze} from './src/adapter.mjs';
import {mkdtemp,rm} from 'node:fs/promises';
const root=await mkdtemp('/tmp/rea-rss-');
try {const r=await analyze('/usr/bin/true',{root,signal:AbortSignal.timeout(30000)});
console.log(JSON.stringify({bytes:r.artifact.bytes,sections:r.layout.sections.length,symbols:r.layout.symbols.length,relocations:r.layout.relocations.length,diagnostics:r.diagnostics}));}
finally {await rm(root,{recursive:true,force:true});}
"""
start=time.monotonic()
p=subprocess.Popen(['node','--max-old-space-size=128','--input-type=module','-e',code],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
peak=0
while p.poll() is None:
    rows={}
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal(): continue
        try:
            data={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (item/'status').read_text().splitlines() if ':' in line}
            rows[int(item.name)]=(int(data['PPid']),int(data.get('VmRSS','0 kB').split()[0]))
        except (OSError,KeyError,ValueError): pass
    descendants={p.pid}
    while True:
        new={pid for pid,(parent,rss) in rows.items() if parent in descendants}
        if new<=descendants: break
        descendants|=new
    peak=max(peak,sum(rows.get(pid,(0,0))[1] for pid in descendants))
    time.sleep(.01)
out,err=p.communicate()
print(json.dumps({'exitCode':p.returncode,'sampledAggregatePeakRSSKiB':peak,'elapsedSeconds':round(time.monotonic()-start,3),'sampleIntervalSeconds':.01,'analysis':json.loads(out) if p.returncode==0 else None,'stderr':err.decode()[:1000]},indent=2))
raise SystemExit(p.returncode)
