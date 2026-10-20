#!/usr/bin/env python3
"""Offline stream coverage audit; reads an existing private Frida JSONL capture."""
import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from relay.packets import load_lengths, packet_len

TARGETS = (0x09FD, 0x09FF, 0x0229)


def audit(events, lengths):
    buffers = collections.defaultdict(bytearray)
    summary = collections.Counter()
    found = []
    issues = []
    for n, record in enumerate(events):
        if record.get("kind") != "recv":
            continue
        fd = record.get("fd")
        nbytes = record.get("bytes", 0)
        payload = record.get("payload")
        if not isinstance(payload, str) or len(payload) != 2 * nbytes:
            summary["incomplete_recv_chunks"] += 1
            if buffers[fd]:
                issues.append({"event": n, "fd": fd, "issue": "stream_gap_after_partial"})
                buffers[fd].clear()
            continue
        try:
            raw = bytes.fromhex(payload)
        except ValueError:
            summary["invalid_hex_chunks"] += 1
            buffers[fd].clear()
            continue
        summary["capture_bytes"] += len(raw)
        data = buffers[fd]
        before = len(data)
        data.extend(raw)
        if before:
            summary["chunks_with_carried_bytes"] += 1
        at = 0
        while len(data) - at >= 2:
            pid = data[at] | (data[at+1] << 8)
            size = packet_len(lengths, data, at)
            if size is None:
                summary["unknown_ids"] += 1
                issues.append({"event": n, "fd": fd, "issue": "unknown_id", "id": f"{pid:04X}"})
                # Do not claim correct framing after an unknown packet.
                del data[:]
                break
            if not size:
                break
            if size > 65535:
                issues.append({"event": n, "fd": fd, "issue": "oversize", "id": f"{pid:04X}"})
                del data[:]
                break
            if len(data) - at < size:
                break
            summary["parsed_packets"] += 1
            summary["parsed_bytes"] += size
            if pid in TARGETS:
                summary[f"wire_{pid:04X}"] += 1
                found.append({"id": f"{pid:04X}", "fd": fd, "length": size,
                              "fragmented": before > 0 and at == 0})
            at += size
        if at:
            del data[:at]
        if data:
            summary["chunks_ending_partial"] += 1
    summary["remaining_bytes"] = sum(map(len, buffers.values()))
    matches = collections.Counter()
    seen_ids = set()
    duplicate_ids = 0
    for x in events:
        if x.get("kind") not in ("ring_match", "ring_snapshot_match", "ring_replay_match"):
            continue
        cid = x.get("candidate_id")
        if cid is not None:
            if cid in seen_ids:
                duplicate_ids += 1
                continue
            seen_ids.add(cid)
        pid = int.from_bytes(bytes.fromhex(x["packet_id"]), "little")
        matches[f"plaintext_{pid:04X}"] += 1
        matches[f"{x['kind']}_{pid:04X}"] += 1
    result = dict(summary)
    result.update(matches)
    result["duplicate_candidate_matches"] = duplicate_ids
    result["unresolved_by_type"] = {f"{pid:04X}": summary[f"wire_{pid:04X}"]-matches[f"plaintext_{pid:04X}"]
                                     for pid in TARGETS}
    return {"summary": result, "targets": found, "issues": issues[:30]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("capture", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    records = [json.loads(line) for line in args.capture.read_text().splitlines() if line.strip()]
    report = audit(records, load_lengths(ROOT / "data/uaro_recvpackets.txt"))
    content = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(content + "\n")
    print(content)


if __name__ == "__main__":
    main()
