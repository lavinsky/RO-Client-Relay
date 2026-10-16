"""Standalone offline tests. All byte/state fixtures created here are synthetic."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import shutil
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from research.cipher.core import (Dataset, EvidenceError, analyze, dataset_bytes, header,
    json_bytes, load_dataset, parse_json, private_directory, private_write, validate_record)
from research.cipher.analyze import inspect_file, main, run
from research.cipher.inspect_client import observe, SOURCE
from research.cipher.chain_capture import close_owned, bounded_artifact, cl_source_options, select_pop_candidate, upstream_pop_reference
from research.cipher.candidate_slice import candidate_slice
from research.cipher.debug_inventory import snapshot as debug_snapshot
from research.cipher.chain_audit import audit_chain, audit_cl_origin, audit_cl_transformation, audit_cl_producer, audit_stack_source, audit_source_lineage

FIXTURE = REPO / "research/cipher/fixtures/synthetic_calls.jsonl"


class CipherResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Retain test artifacts privately; cleanup leaves no helper processes or open handles.
        from datetime import datetime, timezone
        cls.root = Path(tempfile.mkdtemp(prefix="ro-cipher-" +
                        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-tests-"))
        os.chmod(cls.root, 0o700)
        cls.original = load_dataset(FIXTURE)

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(dir=self.root))

    def tearDown(self):
        # The permission/symlink/FIFO tests deliberately create unsafe fixtures;
        # normalize only their owned temporary artifacts before returning.
        for path in self.directory.rglob("*"):
            if path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.chmod(0o700)
            else:
                path.chmod(0o600)

    def write(self, content, name="input.jsonl"):
        return private_write(self.directory, name, content)

    def dataset(self, records=None, metadata=None):
        records = copy.deepcopy(self.original.records if records is None else records)
        return Dataset(metadata or self.original.metadata, tuple(records), "synthetic-digest")

    def save_records(self, records, metadata=None):
        return self.write(dataset_bytes(metadata or self.original.metadata, records))

    def test_synthetic_expected_counts_are_deterministic(self):
        result = analyze(self.original)
        self.assertEqual(result, analyze(load_dataset(FIXTURE)))
        self.assertEqual(result["counts"]["paired_bytes"], 5)
        self.assertEqual(result["counts"]["xor_operand_matches"], 2)
        self.assertEqual(result["counts"]["state_link_matches"], 1)
        self.assertEqual(result["counts"]["offset_link_matches"], 1)
        self.assertEqual(result["byte_lengths"], {2: 1, 3: 1})
        self.assertFalse(result["claims"]["cipher_solved"])
        self.assertEqual(result["result"], "C_INSUFFICIENT")

    def test_xor_delta_without_independent_operand_is_not_a_cipher(self):
        records = copy.deepcopy(self.original.records)
        for item in records:
            item["xor_operand_hex"] = None
        result = analyze(self.dataset(records))
        self.assertEqual(result["counts"]["complete_byte_pairs"], 2)
        self.assertNotIn("xor_operand_matches", result["counts"])
        self.assertEqual(result["missing"]["independently_observed_xor_operand"], 2)

    def test_wrong_observed_operand_is_reported(self):
        records = copy.deepcopy(self.original.records)
        records[0]["xor_operand_hex"] = "ffffff"
        self.assertEqual(analyze(self.dataset(records))["counts"]["xor_operand_mismatches"], 1)

    def test_state_is_never_fabricated(self):
        records = copy.deepcopy(self.original.records)
        for item in records:
            item["state_before_hex"] = item["state_after_hex"] = None
        result = analyze(self.dataset(records))
        self.assertEqual(result["missing"]["state_before"], 2)
        self.assertEqual(result["missing"]["state_after"], 2)
        self.assertNotIn("paired_state_snapshots", result["counts"])
        self.assertFalse(result["claims"]["initial_state_fabricated"])

    def test_sessions_directions_units_connections_and_epochs_are_isolated(self):
        for field, other in [("session", "s1"), ("direction", "recv"), ("unit", "sync"),
                             ("connection", "c1"), ("epoch", 1)]:
            with self.subTest(field=field):
                records = copy.deepcopy(self.original.records)
                records[1][field] = other
                result = analyze(self.dataset(records))
                self.assertNotIn("state_link_matches", result["counts"])

    def test_state_mismatch_is_not_repaired(self):
        records = copy.deepcopy(self.original.records)
        records[1]["state_before_hex"] = "000000000000"
        result = analyze(self.dataset(records))
        self.assertEqual(result["counts"]["state_link_mismatches"], 1)

    def test_offset_and_call_discontinuities_are_explicit(self):
        records = copy.deepcopy(self.original.records)
        records[1]["stream_offset"] = 9
        result = analyze(self.dataset(records))
        self.assertEqual(result["counts"]["offset_link_mismatches"], 1)
        self.assertNotIn("state_link_matches", result["counts"])
        records[1]["call_index"] = 4
        result = analyze(self.dataset(records))
        self.assertEqual(result["counts"]["call_index_discontinuities"], 1)
        self.assertNotIn("state_link_matches", result["counts"])

    def test_unattributed_gap_and_truncation_break_all_associations(self):
        records = copy.deepcopy(list(self.original.records))
        gap = {"kind": "gap", "index": 1, "session": "s0", "connection": "cunknown",
               "direction": "unknown", "unit": "unknown", "epoch": 0, "reason": "record_loss"}
        records[1]["index"] = 2
        records.insert(1, gap)
        self.assertNotIn("state_link_matches", analyze(self.dataset(records))["counts"])
        records = copy.deepcopy(list(self.original.records))
        records[0]["complete"] = False
        self.assertNotIn("state_link_matches", analyze(self.dataset(records))["counts"])

    def test_explicit_gap_breaks_state_association(self):
        records = copy.deepcopy(list(self.original.records))
        gap = {"kind": "gap", "index": 1, "session": "s0", "connection": "c0",
               "direction": "send", "unit": "send", "epoch": 0, "reason": "record_loss"}
        records[1]["index"] = 2
        records.insert(1, gap)
        result = analyze(self.dataset(records))
        self.assertEqual(result["counts"]["gap_records"], 1)
        self.assertNotIn("state_link_matches", result["counts"])

    def test_partial_bytes_are_not_marked_complete(self):
        records = copy.deepcopy(self.original.records)
        records[0]["input_hex"] = "01"
        records[0]["complete"] = False
        result = analyze(load_dataset(self.save_records(records)))
        self.assertEqual(result["missing"]["complete_bytes"], 1)
        self.assertEqual(result["counts"]["complete_byte_pairs"], 1)
        records[0]["complete"] = True
        with self.assertRaises(EvidenceError):
            validate_record(records[0])

    def test_packet_boundary_is_not_transformation_boundary(self):
        records = copy.deepcopy(self.original.records)
        for item in records:
            item["kind"] = "packet"
            item["boundary"] = "unknown"
        result = analyze(self.dataset(records))
        self.assertEqual(result["missing"]["transformation_call_boundary"], 2)

    def test_malformed_json_duplicate_keys_and_nonfinite_are_rejected(self):
        for raw in (b"{", b'{"a":1,"a":2}', b'{"x":NaN}', b'\xff', b"[" * 1500):
            with self.subTest(raw_type=len(raw)):
                with self.assertRaises(EvidenceError):
                    parse_json(raw)

    def test_invalid_hex_types_lengths_and_unknown_fields(self):
        for field, value in [("input_hex", "x1"), ("input_hex", "123"),
                             ("output_hex", 3), ("state_after_hex", "00"),
                             ("index", True), ("length", -1), ("length", 65537),
                             ("password", "DO-NOT-STORE")]:
            with self.subTest(field=field):
                record = copy.deepcopy(self.original.records[0])
                record[field] = value
                with self.assertRaises(EvidenceError):
                    validate_record(record)

    def test_missing_input_and_output_fields_produce_diagnosis(self):
        records = copy.deepcopy(self.original.records)
        records[0].pop("input_hex")
        records[1].pop("output_hex")
        report = analyze(load_dataset(self.save_records(records)))
        self.assertEqual(report["missing"]["input_bytes"], 1)
        self.assertEqual(report["missing"]["output_bytes"], 1)

    def test_missing_required_metadata_is_rejected(self):
        record = copy.deepcopy(self.original.records[0])
        del record["session"]
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_empty_input_and_increasing_index_validation(self):
        p = self.write(b"", "empty.jsonl")
        with self.assertRaises(EvidenceError):
            load_dataset(p)
        records = copy.deepcopy(self.original.records)
        records[1]["index"] = 0
        p = self.save_records(records)
        with self.assertRaises(EvidenceError):
            load_dataset(p)

    def test_truncated_jsonl_is_not_silently_accepted(self):
        p = self.write(FIXTURE.read_bytes().rstrip(b"\n"))
        with self.assertRaises(EvidenceError):
            load_dataset(p)
        report = inspect_file(p)
        self.assertIn("error", report)
        self.assertEqual(report["usable_complete_cipher_calls"], 0)

    def test_byte_record_and_nested_event_caps(self):
        with self.assertRaises(EvidenceError):
            load_dataset(FIXTURE, max_bytes=5)
        with self.assertRaises(EvidenceError):
            load_dataset(FIXTURE, max_records=1)
        p = self.write(json_bytes({"events": [{"tag": "DONE"}] * 4}), "events.json")
        self.assertIn("error", inspect_file(p, max_records=3))

    def test_zero_and_negative_limits_are_rejected(self):
        for limit in (0, -1, True, 64 * 1024 * 1024 + 1):
            self.assertIn("error", inspect_file(FIXTURE, max_bytes=limit))

    def test_state_layout_cannot_escape_captured_region(self):
        record = copy.deepcopy(self.original.records[0])
        record["state_layout"]["position_offsets"] = [6]
        with self.assertRaises(EvidenceError):
            validate_record(record)
        record["state_layout"]["position_offsets"] = [4, 4]
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_pattern_match_does_not_identify_state_or_word_operations(self):
        record = copy.deepcopy(self.original.records[0])
        ramp = bytes(((i << 2) | (i >> 6)) & 255 for i in range(256))
        record["state_before_hex"] = (ramp + b"\0\0").hex()
        record["state_after_hex"] = (ramp + b"\x21\x01").hex()
        record["state_layout"] = {"table_offset": 0, "table_length": 256,
                                  "position_offsets": [256, 257]}
        result = analyze(self.dataset([record]))
        self.assertEqual(result["counts"]["rol8_pattern_matches_before"], 256)
        self.assertFalse(result["claims"]["pattern_match_identifies_state"])
        self.assertEqual(result["position_hypotheses"]["257"]["floor_word_step_1_matches"], 1)
        self.assertEqual(result["position_hypotheses"]["257"]["ceil_word_step_1_matches"], 0)

    def test_probe_coordinates_are_not_reconstructed_as_bytes(self):
        p = self.write(json_bytes({"pid": 123, "events": [{"tag": "DONE", "coords": [1, 2],
            "ack0087": {"src": [1, 1], "dst": [1, 2]}}]}), "probe.json")
        report = inspect_file(p)
        self.assertEqual(report["fields_available"]["coordinates"], 1)
        self.assertIn("plaintext", report["fields_absent"])
        self.assertIn("ciphertext", report["fields_absent"])
        self.assertEqual(report["session"], "unknown")

    def test_socket_records_are_not_paired_by_proximity(self):
        records = [{"tag": "HIT", "packet": {"id": "0437", "hex": "37040000000002"}},
                   {"tag": "SEND", "id": "0x0437", "C": "37041122334455"}]
        p = self.write(b"".join(json_bytes(r) for r in records))
        # json_bytes is pretty-printed: use actual JSONL for this transport format.
        p2 = self.write(b"".join((json.dumps(r) + "\n").encode() for r in records), "events.jsonl")
        report = inspect_file(p2)
        self.assertEqual(report["fields_available"]["plaintext"], 1)
        self.assertEqual(report["fields_available"]["ciphertext"], 1)
        self.assertNotIn("same_event_byte_pair", report["fields_available"])
        self.assertEqual(report["usable_complete_cipher_calls"], 0)

    def test_socket_batch_unknown_id_and_secret_fields_are_excluded(self):
        records = [{"tag": "SEND", "id": "0x0064", "C": "SENSITIVE-CREDENTIALS"},
                   {"tag": "SEND", "id": "0x0437", "C": "3704000000000237040000000003"},
                   {"tag": "SEND", "id": "0x0437", "C": "37041122334455",
                    "sock": "PERSONAL-ADDRESS", "token": "NEVER-REPORT"}]
        p = self.write(b"".join((json.dumps(r) + "\n").encode() for r in records))
        report = inspect_file(p)
        encoded = json.dumps(report)
        self.assertNotIn("PERSONAL-ADDRESS", encoded)
        self.assertNotIn("NEVER-REPORT", encoded)
        self.assertNotIn("SENSITIVE-CREDENTIALS", encoded)
        self.assertEqual(report["fields_available"]["ciphertext"], 1)

    def test_unclassified_ebx_window_is_not_promoted_to_state(self):
        p = self.write(json_bytes({"tag": "SCRAMBLE", "hit": "trace", "db": "01",
                                  "ebx": "0x1234", "tbl": "00" * 64}), "trace.json")
        report = inspect_file(p)
        self.assertEqual(report["fields_available"]["unclassified_memory_window"], 1)
        self.assertIn("state_before", report["fields_absent"])

    def test_files_with_same_alias_are_not_merged(self):
        p = self.write(FIXTURE.read_bytes())
        p2 = self.write(FIXTURE.read_bytes(), "second.jsonl")
        out = self.directory / "out"
        report = run([p, p2], out)
        self.assertEqual(len(report["files"]), 2)
        self.assertIn("disabled", report["cross_file_association"])
        self.assertEqual(report["files"][1]["duplicate_content_of_input"], 0)

    def test_conflicting_socket_length_is_not_accepted(self):
        p = self.write(json_bytes({"tag": "SEND", "id": "0437", "C": "37041122334455",
                                  "len": 10}), "length.json")
        report = inspect_file(p)
        self.assertEqual(report["excluded"]["conflicting_socket_length"], 1)
        self.assertIn("ciphertext", report["fields_absent"])

    def test_private_permissions_exclusive_write_and_symlinks(self):
        p = self.write(b"synthetic")
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        with self.assertRaises(FileExistsError):
            self.write(b"replacement")
        link = self.directory / "link"
        link.symlink_to(p)
        with self.assertRaises((OSError, EvidenceError)):
            load_dataset(link)
        other = self.directory / "other"
        other.mkdir(mode=0o755)
        other.chmod(0o755)
        with self.assertRaises(EvidenceError):
            private_directory(other)

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        self.assertIn("error", inspect_file(fifo))

    def test_input_is_preserved_and_stdout_has_no_bytes(self):
        p = self.write(FIXTURE.read_bytes())
        before = hashlib.sha256(p.read_bytes()).hexdigest()
        out = self.directory / "out"
        result = subprocess.run([sys.executable, "research/cipher/analyze.py", "--input", str(p),
                                 "--out", str(out)], cwd=REPO, capture_output=True, text=True,
                                timeout=10, check=True)
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), before)
        self.assertNotIn("010203", result.stdout)
        self.assertNotIn("000102030405", result.stdout)
        self.assertEqual(json.loads(result.stdout)["result"], "C_INSUFFICIENT")

    def test_runs_without_frida_client_or_network(self):
        out = self.directory / "offline"
        with patch.dict(sys.modules, {"frida": None}), \
                patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            report = run([FIXTURE], out)
        self.assertIsNone(report["cipher_candidate"])
        self.assertEqual(len(report["hypotheses"]), 3)

    def test_missing_file_produces_structured_diagnostic(self):
        report = run([self.directory / "absent.json"], self.directory / "out")
        self.assertEqual(report["files"][0]["error"], "FileNotFoundError")
        self.assertTrue((self.directory / "out/missing-data.json").is_file())


class ChainCaptureTests(unittest.TestCase):
    @staticmethod
    def synthetic_stack_source():
        source,destination=0x3000,0x2000
        texts=['push dword ptr [esi]','push dword ptr [edx]','pop dword ptr [esi]','pop dword ptr [edx]']
        raw=dict(context=dict(thread=7,sp=0x4800,frame=0x1fca),source_address=source,destination_address=destination,
            same_address=False,overlap_bytes=0,complete=True,observations=[],
            code_path=[dict(rva=0x100+i*2,next_rva=0x102+i*2,instruction=t) for i,t in enumerate(texts)])
        for i,delta in enumerate([0,-4,-8,-4,0]):
            row=dict(site=i,order=i+1,thread=7,frame=0x1fca,sp=0x4800+delta,esi=source,edx=destination,
                source_word=0x11223344 if i<3 else 0x55667788,destination_word=0x55667788 if i<4 else 0x11223344)
            if 0<i<4:row['stack_top']=0x55667788 if i==2 else 0x11223344
            if i==2:row['older_stack_word']=0x11223344
            raw['observations'].append(row)
        raw['comparisons']={k:True for k in ('first_push','second_push','first_stack_slot_preserved','first_pop',
            'remaining_stack_slot_preserved','second_pop','original_source_reaches_destination')}
        return raw

    def test_stack_transport_is_distinct_from_transformation_and_checks_context(self):
        row=self.synthetic_stack_source();result=audit_stack_source(row)
        self.assertEqual(result['conclusion'],'STACK_MEMORY_TRANSPORT_CONFIRMED')
        self.assertFalse(result['linked_to_cl_load']);self.assertFalse(result['state_identified'])
        self.assertNotIn(str(0x11223344),json.dumps(result))
        for change in ('gap','sp','thread','alias','value','code'):
            raw=copy.deepcopy(row)
            if change=='gap':raw['observations'][2]['site']=3
            if change=='sp':raw['observations'][3]['sp']+=4
            if change=='thread':raw['observations'][3]['thread']+=1
            if change=='alias':raw['overlap_bytes']=4
            if change=='value':raw['observations'][1]['stack_top']^=1
            if change=='code':raw['code_path'][1]['next_rva']+=2
            with self.subTest(change=change),self.assertRaises(EvidenceError):audit_stack_source(raw)
        row['complete']=False;row['observations']=row['observations'][:2]
        self.assertEqual(audit_stack_source(row)['conclusion'],'PARTIAL_STACK_SOURCE')

    def test_stack_pop_and_cl_link_requires_the_same_writer(self):
        stack=self.synthetic_stack_source();cl,path=self.synthetic_cl();cl['context']['frame']=0x1fca
        producer=dict(rva=0x106,next_rva=0x108,instruction='pop dword ptr [edx]',address=0x2000,watched_offset=0,
            before=0x55667788,source_address=0x47fc,source_sample=0x11223344,after=0x11223344,
            before_order=4,after_order=5,write_order=5,load_order=6,
            context=dict(thread=7,sp=0x47fc,frame=0x1fca),post_context=dict(thread=7,sp=0x4800,frame=0x1fca),
            edx_after=0x2000,copy_matches=True,post_context_matches=True,complete=True)
        end=dict(tag='DONE',reason='cl_origin_observed',cleanup=dict(ok=True),thread_id=7,path=path,cl_origin=cl,
            cl_producer=producer,cl_stack_source=stack,occurrence=None,
            counts=dict(visits=13,read_errors=0,discontinuities=0,unselected_chains=0),
            cl_preceding_write=dict(order=5,thread=7,frame=0x1fca,byte_after=0x44,predecessor_execution_proven=True))
        container=dict(configuration=dict(window_ms=500,event_cap=1000,bytes_cap=262144),cleanup_confirmed=True,events=[end])
        self.assertTrue(audit_chain(container)['cl_stack_source']['linked_to_cl_load'])
        end['cl_preceding_write']['order']=7
        self.assertFalse(audit_chain(container)['cl_stack_source']['linked_to_cl_load'])

    def test_debug_register_inventory_never_writes_and_detaches_on_error(self):
        class Backend:
            def __init__(self,flags=0x400,fail=None):self.flags=flags;self.fail=fail;self.calls=[];self.clock=0.
            def now(self):return self.clock
            def sleep(self,n):self.clock+=n
            def seize(self,pid):
                self.calls.append('seize')
                if self.fail=='seize':raise PermissionError(1,'synthetic')
            def interrupt(self,pid):self.calls.append('interrupt')
            def wait(self,pid):return (0,0) if self.fail=='timeout' else (pid,(128<<16)|(5<<8)|0x7f)
            def read(self,pid,index):
                self.calls.append(('read',index))
                if self.fail=='read':raise OSError(5,'synthetic')
                return self.flags if index==7 else 0
            def detach(self,pid,sig):
                self.calls.append(('detach',sig))
                if self.fail=='detach':raise OSError(5,'synthetic')
        for flags,expected in [(0x400,[]),(1,[0]),(2,[0]),(0x44,[1,3])]:
            backend=Backend(flags)
            result=debug_snapshot(7,backend,backend.now,backend.sleep)
            self.assertEqual(result['enabled_slots'],expected);self.assertTrue(result['cleanup_confirmed'])
            self.assertFalse(result['debug_registers_changed']);self.assertEqual(backend.calls[-1],('detach',0))
        for failure in ('seize','read','detach','timeout'):
            backend=Backend(fail=failure);result=debug_snapshot(7,backend,backend.now,backend.sleep)
            self.assertEqual(result['status'],'undetermined')
            self.assertEqual(result['cleanup_confirmed'],failure in ('seize','read'))
            if failure=='read':self.assertEqual(backend.calls[-1],('detach',0))
            self.assertLessEqual(result['elapsed_ms'],202)

    def test_relative_cl_reference_reuses_no_runtime_address_or_state(self):
        source=dict(source_address=0x2036,context=dict(frame=0x2000),source_mapping=dict(private_marker='synthetic'),
                    source_sample=0x11223344,loaded_value=0x11223344)
        original=copy.deepcopy(source)
        with patch.dict(sys.modules,{'frida':None}),patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):
            result=cl_source_options(source,'a'*64,True)
        self.assertNotIn('cl_watch',result)
        self.assertEqual(result['cl_source_relative']['offset'],0x36)
        self.assertFalse(result['cl_source_relative']['source_session_reused'])
        for field in ('source_address','source_sample','source_mapping','loaded_value','frame','private_marker'):
            self.assertNotIn(field,json.dumps(result))
        self.assertEqual(source,original)
        with self.assertRaises(EvidenceError):cl_source_options(dict(source,source_address=0x2037),'a'*64,True)

    def test_pop_copy_preserves_stack_operand_and_checks_esp_change(self):
        row=dict(rva=0x80,next_rva=0x82,address=0x2000,before=0,source_address=0x47fc,source_sample=0x55667788,
            watched_offset=0,instruction='pop dword ptr [edx]',before_order=1,after_order=2,write_order=2,
            context=dict(thread=7,sp=0x47fc,frame=0x3000),post_context=dict(thread=7,sp=0x4800,frame=0x3000),
            after=0x55667788,edx_after=0x2000,copy_matches=True,post_context_matches=True,complete=True)
        self.assertEqual(audit_cl_producer(row)['conclusion'],'POP_COPY_CONFIRMED')
        self.assertFalse(audit_cl_producer(row)['linked_to_cl_load'])
        for key,value in [('source_address',0x47f8),('after',0),('edx_after',0x2004),('after_order',1)]:
            with self.subTest(key=key),self.assertRaises(EvidenceError):audit_cl_producer(dict(row,**{key:value}))
        self.assertEqual(audit_cl_producer(dict(row,complete=False))['conclusion'],'PARTIAL_POP_OBSERVATION')

    def test_earlier_pop_selector_uses_only_unambiguous_code_edges(self):
        row=dict(pc_after='0x1082',candidates=[dict(pc='0x1080',rva=0x80,instruction='pop dword ptr [ebx]')])
        end=dict(cl_writer_observations=[row,copy.deepcopy(row)])
        self.assertEqual(select_pop_candidate(end,0x80),row)
        for bad in (0x81,True,-1):
            with self.subTest(bad=bad),self.assertRaises(EvidenceError):select_pop_candidate(end,bad)
        end['cl_writer_observations'][1]['pc_after']='0x1083'
        with self.assertRaises(EvidenceError):select_pop_candidate(end,0x80)
        with self.assertRaises(EvidenceError):select_pop_candidate(dict(cl_writer_observations=[dict(row,candidates=row['candidates']*2)]),0x80)

    def test_pop_destination_register_must_match_and_remain_stable(self):
        row=dict(rva=0x80,next_rva=0x82,address=0x2000,before=0,source_address=0x47fc,source_sample=0x55667788,
            watched_offset=0,instruction='pop dword ptr [ebx]',destination_register='ebx',before_order=1,after_order=2,write_order=2,
            context=dict(thread=7,sp=0x47fc,frame=0x3000),post_context=dict(thread=7,sp=0x4800,frame=0x3000),
            after=0x55667788,destination_register_after=0x2000,copy_matches=True,post_context_matches=True,complete=True)
        self.assertEqual(audit_cl_producer(row)['conclusion'],'POP_COPY_CONFIRMED')
        for key,value in [('destination_register','esp'),('instruction','pop dword ptr [edi]'),('destination_register_after',0x2004)]:
            with self.subTest(key=key),self.assertRaises(EvidenceError):audit_cl_producer(dict(row,**{key:value}))

    def test_source_lineage_requires_preceding_order_and_matching_byte(self):
        # Synthetic byte provenance; a watchpoint decode remains a candidate.
        watch=dict(address=0x2040,frame=0x2000,offset=0x40,thread=7,start_order=1)
        row=dict(order=2,thread=7,frame=0x2000,byte_after=0x44,
                 candidates=[dict(rva=0x80,instruction='mov byte ptr [eax], cl')],predecessor_execution_proven=False)
        stack=dict(source_address=0x2040,context=dict(thread=7,frame=0x2000),observations=[dict(source_word=0x11223344)],
                   source_lineage=dict(address=0x2040,consumer_order=3,watch_start_order=1,sampled_byte=0x44,preceding_write=row))
        result=audit_source_lineage(stack,watch,[row],1)
        self.assertEqual(result['conclusion'],'BYTE_WRITER_BEFORE_SOURCE_READ_OBSERVED')
        self.assertFalse(result['executed_writer_proven'])
        self.assertEqual(audit_source_lineage(stack,watch,[row],1,False)['conclusion'],'SOURCE_WRITER_UNVERIFIED')
        later=dict(row,order=4,byte_after=0x55)
        self.assertEqual(audit_source_lineage(stack,watch,[row,later],2)['conclusion'],result['conclusion'])
        with self.assertRaises(EvidenceError):audit_source_lineage(stack,watch,[later],1)
        with self.assertRaises(EvidenceError):audit_source_lineage(stack,dict(watch,offset=0x41),[row],1)

    def test_upstream_selector_returns_code_and_offset_without_runtime_state(self):
        row=dict(pc_after='0x1082',candidates=[dict(pc='0x1080',rva=0x80,instruction='pop dword ptr [eax]')],byte_after=0x44)
        reference=dict(events=[dict(tag='DONE',cl_source_writer_observations=[row],cl_source_watch=dict(offset=0x40,address=0x2040))])
        with patch('research.cipher.chain_audit.audit_chain',return_value=dict(source_lineage=dict(conclusion='BYTE_WRITER_BEFORE_SOURCE_READ_OBSERVED'))):
            operation,offset=upstream_pop_reference(reference,0x80)
        self.assertEqual((operation['rva'],operation['next_rva'],operation['destination_register'],offset),(0x80,0x82,'eax',0x40))
        self.assertNotIn('address',operation);self.assertNotIn('byte_after',operation)
        with patch('research.cipher.chain_audit.audit_chain',return_value={}):
            with self.assertRaises(EvidenceError):upstream_pop_reference(reference,0x80)

    def test_hypothetical_slice_stops_at_missing_or_conflicting_edges(self):
        # Synthetic swap: source XOR -> first POP overwrites source -> final POP.
        xor=dict(order=1,byte_after=0x44,candidates=[dict(rva=0x80,instruction='xor byte ptr [eax], cl',effective_address=0x2040)])
        first=dict(order=2,byte_after=0x55,candidates=[dict(rva=0x104,instruction='pop dword ptr [edi]',effective_address=0x2040)])
        final=dict(order=3,byte_after=0x44,candidates=[dict(rva=0x106,instruction='pop dword ptr [eax]',effective_address=0x2000,
            swap_candidate=dict(source_address=0x2040,destination_address=0x2000,first_pop_rva=0x104,executed_path_proven=False))])
        end=dict(tag='DONE',cl_origin=dict(context=dict(frame=0x2000),source_address=0x2000,source_sample=0x44),
            cl_producer=dict(load_order=4),cl_writer_observations=[final],cl_source_watch=dict(address=0x2040),
            cl_source_writer_observations=[xor,first])
        capture=dict(events=[end])
        audit=dict(runtime_health='NO_SCRIPT_ERROR_RECORDED',cl_origin=dict(conclusion='CL_LOAD_AND_STORE_CONFIRMED'),capture_limit_reached=False)
        with patch('research.cipher.candidate_slice.audit_chain',return_value=audit):
            result=candidate_slice(capture)
            self.assertEqual(result['classification'],'HYPOTHESIS');self.assertFalse(result['executed_path_proven'])
            self.assertEqual([s['writer_rva']for s in result['steps']],['0x106','0x80'])
            self.assertEqual(result['stop'],'NO_SWAP_CANDIDATE')
            self.assertEqual(candidate_slice(capture,1)['stop'],'SLICE_LIMIT')
            end['cl_extra_source_watch']=end['cl_source_watch'];end['cl_extra_source_writer_observations']=end['cl_source_writer_observations']
            end['cl_source_watch']=dict(address=0x2070);end['cl_source_writer_observations']=[]
            self.assertEqual([step['writer_rva']for step in candidate_slice(capture)['steps']],['0x106','0x80'])
            end['cl_source_watch']=end.pop('cl_extra_source_watch');end['cl_source_writer_observations']=end.pop('cl_extra_source_writer_observations')
            end['cl_source_writer_observations']=[xor]
            self.assertEqual(candidate_slice(capture)['stop'],'FIRST_POP_NOT_OBSERVED')
            end['cl_source_writer_observations']=[dict(xor,byte_after=0x33),first]
            self.assertEqual(candidate_slice(capture)['stop'],'CANDIDATE_VALUE_MISMATCH')
            final['candidates']*=2
            self.assertEqual(candidate_slice(capture)['stop'],'AMBIGUOUS_WRITER_DECODE')

    def test_local_xor_requires_before_after_order_and_context(self):
        row=dict(rva=0x100,next_rva=0x102,address=0x2000,watched_offset=0,
            instruction='xor dword ptr [ecx], edx',before=0x11223344,operand_edx=0x01020304,
            after=0x10203040,before_order=1,after_order=2,write_order=2,
            context=dict(thread=7,sp=0x4800,frame=0x3000),complete=True,
            xor_matches=True,post_context_matches=True)
        result=audit_cl_transformation(row)
        self.assertEqual(result['conclusion'],'XOR_WRITE_CONFIRMED')
        self.assertFalse(result['linked_to_cl_load']);self.assertFalse(result['state_identified'])
        self.assertNotIn(str(row['before']),json.dumps(result))
        self.assertEqual(audit_cl_transformation(row,False)['conclusion'],'XOR_UNVERIFIED')
        for key,value in [('after',0),('after_order',1),('watched_offset',4),('context',None)]:
            with self.subTest(key=key),self.assertRaises(EvidenceError):audit_cl_transformation(dict(row,**{key:value}))
        self.assertEqual(audit_cl_transformation(dict(row,complete=False))['conclusion'],'PARTIAL_XOR_OBSERVATION')

    def test_xor_to_cl_association_is_separate_and_requires_order_and_context(self):
        cl,path=self.synthetic_cl()
        transform=dict(rva=0x80,next_rva=0x82,address=cl['source_address'],watched_offset=0,
            instruction='xor dword ptr [ecx], edx',before=cl['source_sample']^0x01020304,operand_edx=0x01020304,
            after=cl['source_sample'],before_order=1,after_order=2,write_order=2,load_order=3,
            context=dict(cl['context']),complete=True,xor_matches=True,post_context_matches=True)
        end=dict(tag='DONE',reason='cl_origin_observed',cleanup=dict(ok=True),
            counts=dict(visits=13,discontinuities=0,read_errors=0,unselected_chains=0),
            cl_origin=cl,path=path,thread_id=7,occurrence=None,cl_transformation=transform,
            cl_preceding_write=dict(order=2,thread=7,frame=0x3000,byte_after=0x44,predecessor_execution_proven=True))
        container=dict(configuration=dict(window_ms=500,event_cap=1000,bytes_cap=262144),
            cleanup_confirmed=True,events=[end])
        result=audit_chain(container)
        self.assertTrue(result['cl_transformation']['linked_to_cl_load'])
        self.assertEqual(result['cipher_conclusion'],'NOT_TESTED')
        transform['context']['frame']+=4
        self.assertFalse(audit_chain(container)['cl_transformation']['linked_to_cl_load'])
        transform['context']=dict(cl['context']);transform['load_order']=1
        self.assertFalse(audit_chain(container)['cl_transformation']['linked_to_cl_load'])

    @staticmethod
    def synthetic_cl():
        path=[dict(rva=0x100+i,next_rva=0x101+i,instruction='synthetic neutral') for i in range(13)]
        path[0]['instruction']='mov ecx, dword ptr [ecx]';path[11]['instruction']='mov byte ptr [esi], cl'
        row=dict(context=dict(thread=7,sp=0x4800,frame=0x3000),source_address=0x2000,
            source_sample=0x11223344,loaded_value=0x11223344,sites=list(range(13)),
            ecx_values=[0x2000]+[0x11223344]*12,complete=True,pointer_slot=0x3100,
            pointer_sample=0x4002,pointer_loaded=0x4002,destination=0x4002,
            store_byte=0x44,destination_before=0x66,destination_after=0x44)
        for key in ('context_matches','load_matches','ecx_stable','pointer_load_matches',
                    'destination_matches','store_matches','post_destination_matches'):row[key]=True
        return row,path

    def test_cl_load_and_low_byte_store_are_not_a_cipher_vector(self):
        row,path=self.synthetic_cl();result=audit_cl_origin(row,path)
        self.assertEqual(result['conclusion'],'CL_LOAD_AND_STORE_CONFIRMED')
        self.assertEqual(result['cipher_role'],'UNKNOWN')
        self.assertFalse(result['state_identified'])
        self.assertNotIn(str(0x11223344),json.dumps(result))
        row['complete']=False;row['sites']=row['sites'][:2];row['ecx_values']=row['ecx_values'][:2]
        self.assertEqual(audit_cl_origin(row,path)['conclusion'],'PARTIAL_CL_PATH')

    def test_cl_missing_changed_context_order_and_claims_are_rejected(self):
        for change in ('original_address','order','sample','byte','code_gap','context'):
            row,path=self.synthetic_cl()
            if change=='original_address':row['source_address']+=4
            if change=='order':row['sites'][2]=4
            if change=='sample':row['source_sample']^=1
            if change=='byte':row['destination_after']^=1
            if change=='code_gap':path[1]['next_rva']+=3
            if change=='context':row['context']=None
            with self.subTest(change=change),self.assertRaises(EvidenceError):audit_cl_origin(row,path)

    @staticmethod
    def synthetic_chain():
        # Exclusively synthetic: no addresses, values or states from the client.
        row = dict(stage=4, context=dict(thread=7, sp=0x4800, frame=0x3000),
                   source_address=0x2000, source_sample=0x11223344, loaded_value=0x11223344,
                   base_ecx=0x100, expected_slot=0x3100, pointer_slot=0x3100,
                   expected_destination=0x4002, destination=0x4002, store_byte=0x44,
                   destination_before=0x66, destination_after=0x44, order=[1,2,3,4,5], sites=[0,1,2,3,4],
                   source_shares_sp_mapping=False)
        for key in ('load_matches_sample', 'pre_add_ecx_matches', 'add_matches', 'destination_matches',
                    'loaded_value_reaches_store', 'post_context_matches', 'write_matches'):
            row[key] = True
        return dict(configuration=dict(window_ms=500, event_cap=1000, bytes_cap=262144),
                    build={'uaRO.exe': 'a'*64, 'gepard.dll': 'b'*64}, cleanup_confirmed=True,
                    events=[dict(tag='DONE', reason='matched', cleanup=dict(ok=True), thread_id=7,
                                 counts=dict(visits=5, discontinuities=0, unselected_chains=0, read_errors=0),
                                 occurrence=row)])

    def test_chain_inventory_preserves_inputs_and_exports_no_values(self):
        with tempfile.TemporaryDirectory(prefix='ro-cipher-synthetic-audit-') as directory:
            raw = json_bytes(self.synthetic_chain())
            path = private_write(Path(directory), 'synthetic.json', raw)
            report = inspect_file(path)
            self.assertEqual(path.read_bytes(), raw)
        self.assertNotIn('error', report)
        self.assertEqual(report['chain_observation']['chain_conclusion'], 'COPY_CHAIN_CONFIRMED')
        self.assertEqual(report['chain_observation']['session'], 'unknown')
        self.assertEqual(report['chain_observation']['direction'], 'unknown')
        self.assertEqual(report['usable_complete_cipher_calls'], 0)
        self.assertEqual(report['result'], 'C_INSUFFICIENT')
        self.assertNotIn(str(0x11223344), json.dumps(report))
        self.assertNotIn('source_address', json.dumps(report))

    def test_script_error_phase_is_not_hidden_by_local_read_counters(self):
        after=self.synthetic_chain();after['events'].append(dict(tag='SCRIPT_ERROR',description='synthetic failure'))
        result=audit_chain(after)
        self.assertEqual(result['script_errors_after_done'],1)
        self.assertEqual(result['runtime_health'],'UNVERIFIED')
        self.assertEqual(result['chain_conclusion'],'COPY_CHAIN_CONFIRMED')
        before=self.synthetic_chain();before['events'].insert(0,dict(tag='SCRIPT_ERROR',description='synthetic failure'))
        result=audit_chain(before)
        self.assertEqual(result['script_errors_before_done'],1)
        self.assertNotEqual(result['chain_conclusion'],'COPY_CHAIN_CONFIRMED')

    def test_chain_missing_malformed_or_ambiguous_fields_are_rejected(self):
        for mutate in (
            lambda v: v.update(configuration=None),
            lambda v: v['events'][0].update(cleanup=[]),
            lambda v: v['events'].append(copy.deepcopy(v['events'][0])),
            lambda v: v['events'][0]['occurrence'].update(context=None),
            lambda v: v['events'][0]['occurrence'].update(source_address='synthetic-invalid'),
            lambda v: v['events'][0]['occurrence'].update(order=[1,2,4,5,6]),
            lambda v: v['events'][0]['occurrence'].update(sites=[0,True,2,3,4]),
            lambda v: v['events'][0]['occurrence'].update(write_matches=False),
        ):
            with self.subTest(mutation=mutate):
                value = self.synthetic_chain(); mutate(value)
                with self.assertRaises(EvidenceError):
                    audit_chain(value)

    def test_cleanup_failure_and_capture_limit_invalidate_chain_completeness(self):
        for mode in ('cleanup', 'event_limit', 'write_limit', 'byte_limit'):
            value = self.synthetic_chain()
            if mode == 'cleanup':
                value['cleanup_confirmed'] = False
            else:
                value['events'][0]['reason'] = mode
            result = audit_chain(value)
            self.assertEqual(result['chain_conclusion'], 'INCOMPLETE_OR_MISMATCHED_CHAIN')

    def test_independent_writer_is_never_paired_with_a_different_capture(self):
        value = self.synthetic_chain(); end = value['events'][0]; end['occurrence'] = None
        end['partial_observations'] = {'byte_producer': dict(destination=0x6000, ecx_before=0x11223344,
            sp=0x4800, frame=0x3000, thread=7, rva=0x1234, before=0x66, after=0x44,
            write_order=2, copy_matches=True, context_matches=True)}
        result = audit_chain(value)
        self.assertTrue(result['independent_byte_writer']['independent_copy_confirmed'])
        self.assertFalse(result['independent_byte_writer']['paired_with_later_load'])
        self.assertEqual(result['cipher_conclusion'], 'NOT_TESTED')
        del end['partial_observations']['byte_producer']['after']
        self.assertIn('after', audit_chain(value)['independent_byte_writer']['missing'])

    def test_optional_copy_and_byte_load_stages_are_recomputed(self):
        value = self.synthetic_chain(); row = value['events'][0]['occurrence']
        row.update(source_sample=0x44, loaded_value=0x44)
        row['producer'] = dict(before=0x99, after=0x44, input_register_value=0x44, destination=0x2000,
            thread=7, frame=0x3000, sp=0x4800, rva=0x1234, write_order=2, copy_matches=True, context_matches=True)
        row['operand'] = dict(eax_before=0x6044, low_byte_before=0x44, rva=0x1231, zero_extension_matches=True)
        row['value_load'] = dict(source_address=0x6000, eax_before=0x6000, eax_after=0x6044,
            sample_byte=0x44, load_matches=True, context_matches=True, eax_stable_after_load=True)
        result = audit_chain(value)
        self.assertTrue(result['intermediate_writer']['written_dword_is_loaded_dword'])
        self.assertTrue(result['zero_extension']['matches_writer_input'])
        self.assertTrue(result['value_load']['reaches_operand'])
        self.assertTrue(result['value_load']['source_byte_equals_final_store'])

    def test_entire_artifact_budget_invalidates_instead_of_truncating_a_pair(self):
        value = self.synthetic_chain(); value['padding'] = 'x' * 5000
        before = copy.deepcopy(value)
        result = bounded_artifact(value, 2048)
        self.assertLessEqual(len(json_bytes(result)), 2048)
        self.assertEqual(result['capture_invalid_reason'], 'byte_limit')
        self.assertEqual(value, before)
        self.assertFalse(audit_chain(result)['retained_chain'])

    @unittest.skipUnless(shutil.which('node'), 'Node required only for new JS collector doubles')
    def test_chain_machine_with_synthetic_data(self):
        result = subprocess.run(['node', 'research/cipher/chain_probe_test.js'], cwd=REPO,
                                capture_output=True, text=True, timeout=10, check=True)
        self.assertIn('CHAIN SYNTHETIC PASS', result.stdout)

    def test_cleanup_retries_are_bounded_and_refuse_unsafe_unload(self):
        class Exports:
            count = 0
            def stop(self):
                self.count += 1
                return {'ok': False}
        class Script:
            exports_sync = Exports()
            def unload(self):
                raise AssertionError('unsafe unload')
        class Session:
            def detach(self):
                raise AssertionError('unsafe detach')
        script = Script()
        self.assertFalse(close_owned(script, Session(), lambda operation: operation()))
        self.assertEqual(script.exports_sync.count, 3)

    def test_pre_start_failure_does_not_require_rpc_stop(self):
        class Script:
            unloaded = False
            def unload(self):
                self.unloaded = True
        class Session:
            detached = False
            def detach(self):
                self.detached = True
        script, session = Script(), Session()
        self.assertTrue(close_owned(script, session, lambda operation: operation(), needs_stop=False))
        self.assertTrue(script.unloaded and session.detached)


class InspectionLifecycleTests(unittest.TestCase):
    """Code-only inspection doubles; no claim about safety on a real client."""
    class Script:
        def __init__(self, messages=(), failure=None):
            self.messages = messages
            self.failure = failure
            self.unloaded = False

        def on(self, tag, callback):
            self.callback = callback

        def load(self):
            for value in self.messages:
                self.callback({"type": "send", "payload": value}, None)
            if self.failure == "load":
                raise RuntimeError("synthetic error")
            if self.failure == "interrupt":
                raise KeyboardInterrupt()

        def unload(self):
            if self.failure == "unload":
                raise RuntimeError("synthetic cleanup error")
            self.unloaded = True

    def test_code_source_contains_no_hooks_or_payload_state_reads(self):
        for token in ("Interceptor", "Stalker", "setHardware", "readU", "readByteArray", "NativeFunction"):
            self.assertNotIn(token, SOURCE)
        self.assertIn("depth<8", SOURCE)
        self.assertIn("},200)", SOURCE)

    class Session:
        def __init__(self, script, failure=None):
            self.script = script
            self.failure = failure
            self.detached = False

        def create_script(self, source):
            if self.failure == "create":
                raise RuntimeError("synthetic create error")
            return self.script

        def detach(self):
            self.detached = True

    class Device:
        def __init__(self, session):
            self.session = session

        def attach(self, name):
            return self.session

    def run_double(self, messages=(), failure=None):
        script = self.Script(messages, failure)
        session = self.Session(script, failure)
        result = observe(self.Device(session), "synthetic code", timeout=0.001, cap=2)
        return result, script, session

    def test_success_cleans_only_owned_script_and_session(self):
        result, script, session = self.run_double([{"tag": "CODE_PREFLIGHT"}, {"tag": "DONE"}])
        self.assertEqual(result["reason"], "done")
        self.assertTrue(result["cleanup_confirmed"] and script.unloaded and session.detached)
        self.assertEqual(result["breakpoints"], 0)

    def test_timeout_unloads_and_detaches(self):
        result, script, session = self.run_double()
        self.assertEqual(result["reason"], "timeout")
        self.assertTrue(script.unloaded and session.detached)

    def test_error_and_interrupt_both_cleanup(self):
        for failure in ("load", "interrupt"):
            result, script, session = self.run_double(failure=failure)
            self.assertIn(result["reason"], ("error", "interrupted"))
            self.assertTrue(script.unloaded and session.detached)

    def test_event_cap_stops_without_claiming_completeness(self):
        result, script, session = self.run_double([{"tag": "one"}] * 4)
        self.assertEqual(result["reason"], "event_limit")
        self.assertEqual(len(result["events"]), 2)
        self.assertTrue(script.unloaded and session.detached)

    def test_failed_cleanup_is_reported_and_not_hidden(self):
        result, script, session = self.run_double(failure="unload")
        self.assertFalse(result["cleanup_confirmed"])
        self.assertTrue(session.detached)
        self.assertFalse(script.unloaded)

    def test_partial_setup_detaches_session(self):
        result, script, session = self.run_double(failure="create")
        self.assertEqual(result["reason"], "error")
        self.assertTrue(session.detached)
        self.assertFalse(script.unloaded)


if __name__ == "__main__":
    unittest.main(verbosity=1)
