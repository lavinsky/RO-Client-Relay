"""Offline tests for ro_ops. Doubles only: no live client, Frida, network or process memory."""
import io
import json
import os
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from ro_ops import cli, contract as C
from ro_ops.discover import discover, main_tid
from ro_ops.env import env_check
from ro_ops.sample import sample

GOOD = {"python": (3, 12, 0), "ss": True, "git_head": "a" * 40, "proc_readable": True,
        "frida_module": False, "ptrace_scope": "1"}


def run_cli(argv, deps=None):
    out = io.StringIO()
    code = cli.main(argv, stdout=out, deps=deps)
    return code, json.loads(out.getvalue())


def fake_proc(root, pid, tids, start=777):
    d = Path(root, str(pid)); (d / "task").mkdir(parents=True)
    for t in tids:
        (d / "task" / str(t)).mkdir()
    (d / "stat").write_text(f"{pid} (uaRO.exe) S " + " ".join(["0"] * 18 + [str(start)]) + " 0\n")


class FakeSampler:
    def __init__(self, series, label):
        self.series, self.label = series, label
    def sample_series(self, *a): return self.series
    def classify(self, s): return self.label


def S(state="S", wchan="x", nr=7, ut=5, user=False):
    return {"present": True, "state": state, "wchan": wchan, "syscall_nr": nr, "utime": ut, "in_userspace": user}


class ContractTests(unittest.TestCase):
    def test_four_statuses_and_exit_codes(self):
        self.assertEqual(C.EXIT_CODES, {"verified": 0, "unverified": 10, "undetermined": 20, "error": 1})
        for st, code in C.EXIT_CODES.items():
            r = C.make("env-check", st, {}, ["c"])
            self.assertEqual(set(r), {"cmd", "status", "data", "caveats"})
            self.assertEqual(C.emit(r, io.StringIO()), code)

    def test_negative_and_undetermined_need_caveats(self):
        for st in ("unverified", "undetermined"):
            with self.assertRaises(ValueError):
                C.make("discover", st, {}, [])
        with self.assertRaises(ValueError):
            C.make("discover", "ok")

    def test_undetermined_never_positive(self):
        self.assertEqual(C.worst("verified", "undetermined", "unverified"), "undetermined")
        self.assertEqual(C.worst("verified", "unverified"), "unverified")

    def test_credentials_and_traffic_rejected(self):
        for k in ("password", "auth_token", "packet_body", "payload"):
            with self.assertRaises(ValueError):
                C.make("discover", "verified", {"x": {k: 1}})

    def test_classes_are_disjoint(self):
        self.assertEqual({c for c in C.COMMAND_CLASS.values()}, {"read-only", "private-write"})
        self.assertEqual(len(C.COMMAND_CLASS), 5)


class DiscoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        fake_proc(self.tmp.name, 100, [100, 101]); fake_proc(self.tmp.name, 200, [200])

    def run_d(self, ports, pid_of=None, **kw):
        return discover(ports_fn=lambda: ports, pid_of_port_fn=pid_of or (lambda port: dict((p, i) for p, i, _ in ports).get(port)),
                        proc_root=self.tmp.name, **kw)

    def test_single_gadget_verified(self):
        r = self.run_d([(27052, 100, "Z:\\g\\uaRO.exe")])
        self.assertEqual((r["status"], r["data"]["pid"], r["data"]["main_tid"], r["data"]["starttime_ticks"]),
                         ("verified", 100, 100, 777))
        self.assertTrue(any("exclusividade" in c for c in r["caveats"]))

    def test_multiple_gadgets_undetermined(self):
        r = self.run_d([(27052, 100, "/x/uaRO.exe"), (27053, 200, "/y/uaRO.exe")])
        self.assertEqual(r["status"], "undetermined"); self.assertNotIn("pid", r["data"])

    def test_no_match_unverified(self):
        r = self.run_d([(27052, 100, "/x/other.exe")])
        self.assertEqual((r["status"], r["data"]["gadgets_listening"]), ("unverified", 1))

    def test_ss_missing_undetermined(self):
        def boom(): raise FileNotFoundError("ss")
        self.assertEqual(discover(ports_fn=boom)["status"], "undetermined")

    def test_port_race_undetermined(self):
        r = self.run_d([(27052, 100, "/x/uaRO.exe")], pid_of=lambda p: 999)
        self.assertEqual(r["status"], "undetermined")

    def test_missing_task_dir_undetermined(self):
        r = self.run_d([(27052, 300, "/x/uaRO.exe")], pid_of=lambda p: 300)
        self.assertEqual(r["status"], "undetermined"); self.assertIsNone(r["data"]["main_tid"])
        self.assertEqual(main_tid(300, self.tmp.name), (None, None))

    def test_not_cached_between_runs(self):
        a = self.run_d([(27052, 100, "/x/uaRO.exe")])
        b = self.run_d([(27052, 200, "/x/uaRO.exe")])
        self.assertEqual((a["data"]["pid"], b["data"]["pid"]), (100, 200))


class SampleTests(unittest.TestCase):
    def test_label_mapping(self):
        cases = {"progressing": "verified", "waiting/blocked(waiting_cpu_flat,wchan=x,syscall_nr=7)": "verified",
                 "spinning_userspace(utime+; confirmar_responsividade_UI)": "verified",
                 "terminated_or_exception": "verified", "absent": "unverified",
                 "mixed/indeterminate": "undetermined", "running_userspace_stalled(utime_flat; needs_pc)": "undetermined",
                 "no_samples": "undetermined"}
        for label, want in cases.items():
            r = sample(1, 1, 10, 30, sampler=FakeSampler([S(), S(ut=9)], label))
            self.assertEqual(r["status"], want, label); self.assertTrue(r["caveats"])

    def test_summary_without_raw_series(self):
        r = sample(1, 1, 10, 30, sampler=FakeSampler([S(ut=5), S(ut=9)], "progressing"))
        self.assertEqual((r["data"]["utime_delta_ticks"], r["data"]["states"], r["data"]["syscall_nrs"]), (4, {"S": 2}, [7]))
        self.assertNotIn("series", r["data"])

    def test_real_sampler_on_self_is_read_only_and_classified(self):
        r = sample(os.getpid(), os.getpid(), 10, 30)
        self.assertIn(r["status"], C.STATUSES[:3]); self.assertGreater(r["data"]["present_samples"], 0)
        self.assertEqual(sample(os.getpid(), 2 ** 22 + 12345, 10, 30)["status"], "unverified")

    def test_bounds(self):
        for a in ((0, 1), (1, 0)):
            with self.assertRaises(C.UsageError):
                sample(*a)
        with self.assertRaises(C.UsageError):
            sample(1, 1, 5, 100)
        with self.assertRaises(C.UsageError):
            sample(1, 1, 10, 600000)


class EnvTests(unittest.TestCase):
    def test_exclusivity_never_concluded(self):
        for probes in (GOOD, dict(GOOD, ss=False), dict(GOOD, git_head=None)):
            r = env_check(probes)
            self.assertEqual(r["data"]["exclusivity"], "not_determined")
            self.assertTrue(any("exclusividade" in c and "NAO" in c for c in r["caveats"]))
            self.assertNotIn("exclusive", json.dumps(r["data"]).replace("exclusivity", ""))

    def test_statuses(self):
        self.assertEqual(env_check(GOOD)["status"], "verified")
        self.assertEqual(env_check(dict(GOOD, ss=False))["status"], "unverified")
        self.assertEqual(env_check(dict(GOOD, git_head=None))["status"], "undetermined")
        self.assertEqual(env_check(dict(GOOD, python=(3, 9, 0)))["status"], "unverified")
        self.assertEqual(env_check(dict(GOOD, frida_module=False))["status"], "verified")  # informativo


class WriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_new_artifact_private_with_provenance(self):
        probe = REPO / "ro_ops/templates/STATE.md"
        code, r = run_cli(["new-artifact", "--dir", str(self.base / "art"), "--probe", str(probe)])
        d = self.base / "art"
        self.assertIn(code, (0, 20))
        self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
        prov = (d / "PROVENANCE.txt").read_text()
        self.assertIn("repository_head:", prov); self.assertIn("created_utc:", prov)
        self.assertIn("tools_sha256: ", prov); self.assertTrue((d / "STATE.md").is_file())
        self.assertEqual(stat.S_IMODE((d / "PROVENANCE.txt").stat().st_mode), 0o600)
        self.assertEqual(r["data"]["class"], "private-write")

    def test_pid_unobserved_is_unverified_exit_10(self):
        code, r = run_cli(["new-artifact", "--dir", str(self.base / "a2"), "--pid", "999999999"])
        self.assertEqual(code, 10 if r["data"]["repository_head"] else 20)
        self.assertIn("not_observed", (self.base / "a2/PROVENANCE.txt").read_text())

    def test_new_artifact_refuses_repo_scopes_and_existing(self):
        for bad in ("docs/x", "relay/x", "agent/x", "scripts/x", ".codex/x", "research"):
            code, r = run_cli(["new-artifact", "--dir", str(REPO / bad)])
            self.assertEqual((code, r["status"]), (1, "error"), bad)
            self.assertFalse((REPO / bad).exists() and bad.endswith("/x"))
        self.base.joinpath("e").mkdir()
        self.assertEqual(run_cli(["new-artifact", "--dir", str(self.base / "e")])[0], 1)
        link = self.base / "ln"; link.symlink_to(self.base)
        self.assertEqual(run_cli(["new-artifact", "--dir", str(link)])[0], 1)

    def test_new_artifact_refuses_foreign_probe(self):
        outside = self.base / "p.py"; outside.write_text("x")
        self.assertEqual(run_cli(["new-artifact", "--dir", str(self.base / "a3"), "--probe", str(outside)])[0], 1)
        self.assertFalse((self.base / "a3").exists())

    def test_scaffold_creates_and_never_overwrites(self):
        code, r = run_cli(["scaffold-state", "--dir", str(self.base), "--role", "MOVER", "--id", "MOVER-1"])
        self.assertEqual((code, r["data"]["created"]), (0, ["STATE.md", "HANDOFF.md"]))
        self.assertIn("MOVER-1", (self.base / "HANDOFF.md").read_text())
        self.assertNotIn("{{", (self.base / "STATE.md").read_text())
        (self.base / "STATE.md").write_text("mine")
        code, r = run_cli(["scaffold-state", "--dir", str(self.base)])
        self.assertEqual((code, r["data"]["skipped"]), (10, ["STATE.md", "HANDOFF.md"]))
        self.assertEqual((self.base / "STATE.md").read_text(), "mine")

    def test_scaffold_refuses_shared_dirs(self):
        for bad in ("docs", "relay", "agent", "tests", ".codex"):
            self.assertEqual(run_cli(["scaffold-state", "--dir", str(REPO / bad)])[0], 1, bad)
        self.assertEqual(run_cli(["scaffold-state", "--dir", str(self.base), "--id", "x;rm"])[0], 1)

    def test_templates_follow_coordination(self):
        st = (REPO / "ro_ops/templates/STATE.md").read_text(); ho = (REPO / "ro_ops/templates/HANDOFF.md").read_text()
        for k in ("600 palavras", "Inventario minimo de sondas", "Autorizacoes", "Limpeza", "NAO CONFIRMADA"):
            self.assertIn(k, st)
        for k in ("400 palavras", "ID unico", "Rival", "Cobertura/perdas", "Evidencias", "Limpeza"):
            self.assertIn(k, ho)


class CliTests(unittest.TestCase):
    def test_exit_codes_0_10_20_1(self):
        pr = lambda ports: {"discover": {"ports_fn": lambda: ports, "pid_of_port_fn": lambda p: ports[0][1],
                                         "proc_root": self.proc}}
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.proc = self.tmp.name
        fake_proc(self.proc, 100, [100])
        one = [(27052, 100, "/x/uaRO.exe")]
        self.assertEqual(run_cli(["discover"], pr(one))[0], 0)
        self.assertEqual(run_cli(["discover"], pr([(27052, 100, "/x/o.exe")]))[0], 10)
        self.assertEqual(run_cli(["discover"], pr(one + [(27053, 100, "/y/uaRO.exe")]))[0], 20)
        self.assertEqual(run_cli(["discover", "--bogus"])[0], 1)

    def test_usage_errors_are_contract_json(self):
        for argv in ([], ["nope"], ["sample-thread"], ["sample-thread", "--pid", "x", "--tid", "1"],
                     ["sample-thread", "--pid", "1", "--tid", "1", "--ms", "1"]):
            code, r = run_cli(argv)
            self.assertEqual((code, r["status"], set(r)), (1, "error", {"cmd", "status", "data", "caveats"}), argv)

    def test_unexpected_exception_is_error(self):
        def boom(): raise RuntimeError("x")
        code, r = run_cli(["discover"], {"discover": {"ports_fn": boom}})
        self.assertEqual((code, r["status"]), (1, "error"))

    def test_real_process_emits_contract(self):
        p = subprocess.run([sys.executable, "-B", "-m", "ro_ops.cli", "env-check"], cwd=REPO,
                           capture_output=True, text=True)
        r = json.loads(p.stdout)
        self.assertEqual(p.returncode, C.EXIT_CODES[r["status"]]); self.assertEqual(r["data"]["exclusivity"], "not_determined")

    def test_skill_and_codex_discovery(self):
        skill = REPO / ".agents/skills/ro-ops/SKILL.md"
        text = skill.read_text()
        self.assertTrue(text.startswith("---\n") and "\nname: ro-ops\n" in text and "\ndescription:" in text)
        link = REPO / ".claude/skills/ro-ops"
        self.assertTrue(link.is_symlink() and link.resolve() == skill.parent.resolve())

    def test_phase2_commands_absent(self):
        for c in ("verify-build", "validate"):
            self.assertEqual(run_cli([c])[0], 1)


if __name__ == "__main__":
    unittest.main()
