#!/usr/bin/env python3
"""Valida sintaxe/esquema mínimo; não substitui executar a versão local do Codex."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[1]
config = tomllib.loads((root / ".codex/config.toml").read_text(encoding="utf-8"))
assert config["agents"]["max_concurrent_threads_per_session"] == 2
assert config["sandbox_mode"] == "workspace-write"
assert not config["sandbox_workspace_write"]["network_access"]
agents = sorted((root / ".codex/agents").glob("*.toml"))
assert len(agents) == 3
for path in agents:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    assert all(data.get(k) for k in ("name", "description", "model", "developer_instructions")), path
for path in (root / ".agents/skills").glob("*/SKILL.md"):
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n") and "\nname:" in text and "\ndescription:" in text, path
print(f"CODEX CONFIG PASS ({len(agents)} agents; sintaxe, não integração runtime)")
