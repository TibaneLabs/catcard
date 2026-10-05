#!/usr/bin/env python3
"""Deepest stack path through a firmware image, from its disassembly.

    llvm-objdump -d --no-show-raw-insn -C target/thumbv7em-none-eabihf/release/catcard-fw > fw.dis
    python3 tools/stackdepth.py fw.dis catcard_fw::menu::run [substring]
    EXCLUDE=hsm::run python3 tools/stackdepth.py fw.dis catcard_fw::menu::run together_as

Each function's frame is its `push`/`vpush` and `sub sp` amounts; edges are direct
`bl`/`b` calls. With a substring, the path is the deepest one that passes through a function whose
name contains it. Calls through function pointers and trait objects are not followed, so
this is a floor on what such a path uses, not a ceiling.

Why: the menu runs as a kernel task with an 8192-word (32 KB) stack and no guard. A TSS
signing session reached about 37.8 KB from Sign -> message and froze the Q1 at the
address screen (2026-10-06). EXCLUDE drops calls to names containing any of its
comma-separated parts, to measure a route that avoids one.
"""
import re,sys,functools
sys.setrecursionlimit(100000)
path=sys.argv[1]; roots=sys.argv[2].split(','); through=sys.argv[3] if len(sys.argv)>3 else None
import os
EXCLUDE=[x for x in os.environ.get('EXCLUDE','').split(',') if x]
d=open(path).read().split('\n')
cur=None; frames={}; calls={}
for l in d:
    m=re.match(r'^[0-9a-f]+ <(.*)>:$',l)
    if m: cur=m.group(1); frames.setdefault(cur,0); calls.setdefault(cur,set()); continue
    if cur is None: continue
    for pat in [r'\bsub(?:\.w)?\s+sp,\s*(?:sp,\s*)?#(0x[0-9a-f]+|\d+)', r'\bsubw\s+sp,\s*sp,\s*#(0x[0-9a-f]+|\d+)']:
        m=re.search(pat,l)
        if m: frames[cur]+=int(m.group(1),0)
    m=re.search(r'\bpush(?:\.w)?\s+\{([^}]*)\}',l)
    if m: frames[cur]+=4*len(m.group(1).split(','))
    m=re.search(r'\bvpush\s+\{([^}]*)\}',l)
    if m:
        regs=m.group(1).split(',')
        n=0
        for r in regs:
            r=r.strip()
            if '-' in r:
                a,b=r.split('-'); n+=int(b[1:])-int(a[1:])+1
            else: n+=1
        frames[cur]+=8*n
    m=re.search(r'\bb(?:l|\.w|)\s+0x[0-9a-f]+ <([^>+]*)(?:\+0x[0-9a-f]+)?>',l)
    if m and m.group(1)!=cur and not any(x in m.group(1) for x in EXCLUDE): calls[cur].add(m.group(1))
memo={}
onstack=set()
def depth(f):
    if f in memo: return memo[f]
    if f in onstack: return (0,[])
    onstack.add(f)
    best=(0,[])
    for c in calls.get(f,()):
        dd=depth(c)
        if dd[0]>best[0]: best=dd
    onstack.discard(f)
    r=(frames.get(f,0)+best[0],[f]+best[1])
    memo[f]=r; return r
def depth_through(f, target, seen=None):
    # deepest path from f that passes through a node containing target
    memo2={}
    stk=set()
    def go(g):
        if g in memo2: return memo2[g]
        if g in stk: return None
        stk.add(g)
        if target in g:
            r=depth(g)
        else:
            best=None
            for c in calls.get(g,()):
                dd=go(c)
                if dd and (best is None or dd[0]>best[0]): best=dd
            r=(frames.get(g,0)+best[0],[g]+best[1]) if best else None
        stk.discard(g); memo2[g]=r; return r
    return go(f)
for r in roots:
    cands=[k for k in frames if k==r] or [k for k in frames if k.startswith(r)]
    for k in cands[:1]:
        res=depth_through(k,through) if through else depth(k)
        if not res: print(k,'no path'); continue
        tot,p=res
        print(f"ROOT {k[:80]}  total {tot} bytes")
        acc=0
        for f in p:
            acc+=frames.get(f,0)
            if frames.get(f,0)>=300: print(f"  {frames.get(f,0):6d} {acc:6d} {f[:120]}")
