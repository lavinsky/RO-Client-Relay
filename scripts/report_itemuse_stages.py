#!/usr/bin/env python3
"""Report the observed stages of 0439 without claiming to inspect the client queue."""
import collections
import datetime
import json
import pathlib
import sys

log = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "relay_log.jsonl")
stages = collections.defaultdict(list)
for line in log.open(encoding="utf-8"):
    try: e = json.loads(line)
    except ValueError: continue
    if e.get("tag") == "ITEMUSE-STAGE":
        stages[e.get("stage")].append(e)
print("0x0439 — etapas observadas (valores agregados, sem identificadores pessoais)")
for name in ("relay-queue", "sendpacket-entry", "sendpacket-return-buffer", "socket-send"):
    rows = stages[name]
    indexes = collections.Counter(e.get("item_index") for e in rows)
    print(f"{name}: {len(rows)} eventos; indices={dict(indexes)}")
    if rows:
        first = datetime.datetime.fromtimestamp(rows[0]["ts"] / 1000).isoformat(timespec="milliseconds")
        last = datetime.datetime.fromtimestamp(rows[-1]["ts"] / 1000).isoformat(timespec="milliseconds")
        print(f"  {first} .. {last}")
print("Limite: relay-queue é a fila do relay; a fila interna do cliente não está instrumentada.")
print("O relatório não pareia individualmente envios concorrentes.")
