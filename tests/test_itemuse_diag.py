"""Regression: 0x0439 diagnostics keep only non-sensitive item index metadata."""
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from relay.console import CaptureLog, show


class ItemUseDiagnosticTest(unittest.TestCase):
    def test_pre_send_slot_is_logged_without_account_or_packet_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "relay.jsonl")
            log = CaptureLog(path)
            original = {"tag": "SENDCALL", "hit": "sent", "len": 8,
                        "id": 0x0439, "item_index": 5,
                        "data": "39040500deadbeef"}
            with contextlib.redirect_stdout(io.StringIO()) as output:
                log.write(original)
            log.f.close()
            entry = json.loads(pathlib.Path(path).read_text(encoding="utf8"))
            self.assertEqual(entry["item_index"], 5)
            self.assertEqual(entry["id"], 0x0439)
            self.assertNotIn("data", entry)
            self.assertIn("item_index=5", output.getvalue())
            self.assertNotIn("deadbeef", output.getvalue())

    def test_other_sendcall_format_still_works(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            show({"tag": "SENDCALL", "hit": "sent", "len": 7})
        self.assertIn("SENT len=7", output.getvalue())

    def test_safe_summary_separates_requested_wire_and_ack(self):
        from scripts.diagnose_item_use import summarize
        rows = [
            {"tag": "SENDCALL", "hit": "sent", "id": 0x0439, "item_index": 5},
            {"tag": "SEND", "id": "0439", "C": "3904050011223344"},
            {"tag": "SEND", "id": "0439", "C": "3904650011223344"},
            {"tag": "RECV-WIRE", "id": "01c8", "C": "c80105003902000000000000010001"},
            {"tag": "RECV-WIRE", "id": "01c8", "C": "c80165000000000000000000000000"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "test.jsonl"
            path.write_text(chr(10).join(json.dumps(row) for row in rows) + chr(10), encoding="utf8")
            req, wire, ok, fail = summarize(path)
            self.assertEqual(req, {5: 1})
            self.assertEqual(wire, {5: 1, 101: 1})
            self.assertEqual(ok, {5: 1})
            self.assertEqual(fail, {101: 1})


if __name__ == "__main__":
    unittest.main()
