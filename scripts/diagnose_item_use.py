#!/usr/bin/env python3
"""Safe offline 0x0439 diagnostic: inventory slots only; never print account IDs.

Run after starting a new relay session with 0439 SENDCALL metadata enabled:
    python3 scripts/diagnose_item_use.py relay_log.jsonl
"""
import collections
import json
import pathlib
import sys


def slot_from_hex(packet):
    try:
        head = bytes.fromhex(packet[:8])
    except (TypeError, ValueError):
        return None
    if len(head) != 4 or head[:2] != b"\x39\x04":
        return None
    return int.from_bytes(head[2:4], "little")


def summarize(path):
    requested = collections.Counter()
    transmitted = collections.Counter()
    confirmed = collections.Counter()
    rejected = collections.Counter()
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if (m.get("tag") == "SENDCALL" and m.get("hit") == "sent"
                    and m.get("id") == 0x0439 and isinstance(m.get("item_index"), int)):
                requested[m["item_index"]] += 1
            if m.get("tag") == "SEND" and m.get("id") == "0439":
                # sendmsg may include two consecutive 8-byte item packets.
                try:
                    data = bytes.fromhex(m.get("C", ""))
                except ValueError:
                    continue
                for offset in range(0, len(data), 8):
                    chunk = data[offset:offset + 8]
                    if len(chunk) == 8 and chunk[:2] == b"\x39\x04":
                        transmitted[int.from_bytes(chunk[2:4], "little")] += 1
                    else:
                        break
            if m.get("tag") == "RECV-WIRE" and m.get("id") == "01c8":
                # Only count leading response: arbitrary TCP chunks can contain
                # mixed packet types and are not safe to parse in 15-byte slices.
                try:
                    data = bytes.fromhex(m.get("C", "")[:30])
                except ValueError:
                    continue
                if len(data) >= 15 and data[:2] == b"\xc8\x01":
                    slot = int.from_bytes(data[2:4], "little")
                    (confirmed if data[14] == 1 else rejected)[slot] += 1
    return requested, transmitted, confirmed, rejected


def main(argv):
    if len(argv) != 2:
        print("Uso: python3 scripts/diagnose_item_use.py relay_log.jsonl", file=sys.stderr)
        return 2
    requested, transmitted, confirmed, rejected = summarize(argv[1])
    print("Índices do inventário (sem identificadores pessoais)")
    print("índice   solicitado ao SendPacket   enviado na rede   01c8 sucesso   01c8 falha")
    for index in sorted(requested.keys() | transmitted.keys() | confirmed.keys() | rejected.keys()):
        print(f"{index:>6}   {requested[index]:>23}   {transmitted[index]:>15}   "
              f"{confirmed[index]:>12}   {rejected[index]:>10}")
    if not requested:
        print("Nenhum índice pré-SendPacket disponível: reinicie o relay com a instrumentação atual.")
    print("Nota: respostas 01c8 contam só as que iniciam um trecho TCP; "
          "envios manuais também integram a coluna de rede.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
