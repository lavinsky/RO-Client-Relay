#!/usr/bin/env python3
"""Synthetic local dispatch benchmark. No Gadget, desktop or external network.

The old route uses its actual configured 400ms delay; the new route receives an
immediate fake client completion. This measures relay scheduling only, not RTT.
Run the same script with --repo pointing to a git-archive of the baseline.
"""
import argparse
import contextlib
import io
import json
from pathlib import Path
import queue
import sys
import threading
import time

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
ap.add_argument('--count',type=int,default=20)
a=ap.parse_args()
sys.path.insert(0,str(a.repo))
from relay.runtime import Capture

samples=[]
packets=[bytes.fromhex(x) for x in ('5f03010203','37040102030407',
                                  '38040a001c0001020304','f40a0a001c000102030400')]
if hasattr(Capture,'_egress_enqueue'):
    from types import SimpleNamespace
    c=Capture.__new__(Capture)
    c._egress_q=queue.Queue()
    c._egress_interval=c._egress_action_gap=0.4
    c._egress_max_age=0.8
    done=threading.Event()
    began=0
    def dispatch(*args):
        samples.append((time.monotonic_ns()-began)/1e6)
        done.set()
    c._on_inbound_split=dispatch
    threading.Thread(target=c._egress_drain,daemon=True).start()
    for i in range(a.count):
        done.clear();began=time.monotonic_ns()
        c._egress_enqueue(packets[i%len(packets)],'S')
        if not done.wait(2):raise RuntimeError('baseline dispatch timed out')
    implementation='baseline actual configured pacing, fake native dispatch'
else:
    from relay.commands import CommandPipeline
    def dispatch(c):
        samples.append((time.monotonic_ns()-c['received_ns'])/1e6)
        return True
    p=CommandPipeline(dispatch,lambda *a:None,lambda *a:None)
    p.session(True)
    for i in range(a.count):
        p.accept(packets[i%len(packets)],'S')
        p.observe(dict(tag='SCRAMBLE',hit='consumed',token=p.current['token'],epoch=p.epoch))
    implementation='readiness pipeline, immediate synthetic native ACK'
samples.sort()
summary={label:samples[max(0,(len(samples)*percent+99)//100-1)]
         for label,percent in (('median',50),('p95',95),('p99',99),('max',100))}
print(json.dumps(dict(kind='OFFLINE SYNTHETIC; NOT RTT',implementation=implementation,
                      n=len(samples),dispatch_ms=summary),sort_keys=True))
