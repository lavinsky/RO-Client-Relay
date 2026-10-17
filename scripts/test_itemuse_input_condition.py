#!/usr/bin/env python3
"""Passive comparison of 0439 output before/after a manually performed game input.

Usage:
  python3 scripts/test_itemuse_input_condition.py record
  python3 scripts/test_itemuse_input_condition.py report

No synthetic input, memory manipulation or writes to game/relay.
Press Enter in THIS terminal to mark each phase. Change the game input manually.
"""
import collections
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
MARKS = ROOT / "itemuse_input_marks.json"
LOG = ROOT / "relay_log.jsonl"

def record():
    marks = []
    for phase, instruction in (
        ("idle-start", "Place uaRO in focus, stop using the keyboard/mouse in-game."),
        ("idle-end", "Let the bot attempt to use potions without in-game input."),
        ("input-start", "Perform ONE ordinary keypress or click IN-GAME now."),
        ("input-end", "Let the bot attempt potions again, without other input."),
    ):
        print(instruction)
        input("Press Enter HERE to mark this phase: ")
        marks.append({"phase": phase, "ts": int(time.time() * 1000)})
    MARKS.write_text(json.dumps(marks, indent=2) + "\n", encoding="utf-8")
    print(f"Markers recorded at {MARKS}; run 'report' after relay exits.")

def report():
    marks = {m["phase"]: m["ts"] for m in json.loads(MARKS.read_text(encoding="utf-8"))}
    spans = [("sem input", marks["idle-start"], marks["idle-end"]),
             ("após input", marks["input-start"], marks["input-end"])]
    counts = {name: collections.Counter() for name, _, _ in spans}
    with LOG.open(encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            ts = event.get("ts")
            if not isinstance(ts, (int, float)):
                continue
            for name, start, end in spans:
                if not start <= ts < end:
                    continue
                stat = counts[name]
                tag, pid = event.get("tag"), event.get("id")
                if tag == "SENDCALL" and pid == 0x0439 and event.get("hit") == "sent":
                    stat["pedidos 0439 ao SendPacket"] += 1
                elif tag == "SEND" and pid == "0439":
                    try: payload = bytes.fromhex(event.get("C", ""))
                    except ValueError: continue
                    if len(payload) >= 4 and payload[:2] == b"\x39\x04":
                        index = int.from_bytes(payload[2:4], "little")
                        stat[f"na rede índice {index}"] += 1
                elif tag == "RECV-WIRE" and pid == "01c8":
                    try: payload = bytes.fromhex(event.get("C", "")[:30])
                    except ValueError: continue
                    if len(payload) == 15 and payload[:2] == b"\xc8\x01":
                        index = int.from_bytes(payload[2:4], "little")
                        stat[f"01c8 índice {index}: {'sucesso' if payload[14] == 1 else 'falha'}"] += 1
    for name, _, _ in spans:
        print(f"\n{name.upper()}")
        for key, value in sorted(counts[name].items()):
            print(f"  {key}: {value}")
        if not counts[name]:
            print("  Sem eventos; confira se o relay gravou a sessão durante a janela.")
    print("\nNota: 01c8 conta apenas respostas no início de um chunk TCP; contagens não são pareamentos.")

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("record", "report"):
        print("Usage: python3 scripts/test_itemuse_input_condition.py [record|report]")
        return 2
    (record if sys.argv[1] == "record" else report)()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
