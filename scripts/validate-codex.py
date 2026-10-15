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

# Paridade Claude Code: mesmos agentes e skills, mesmas instruções.
for path in agents:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    mirror = root / ".claude/agents" / f"{data['name']}.md"
    assert mirror.is_file(), mirror
    _, front, body = mirror.read_text(encoding="utf-8").split("---\n", 2)
    assert f"\nname: {data['name']}\n" in f"\n{front}", mirror
    assert body.strip() == data["developer_instructions"].strip(), f"{mirror} diverge de {path}"
for path in (root / ".agents/skills").iterdir():
    link = root / ".claude/skills" / path.name
    assert link.is_symlink() and link.resolve() == path.resolve(), link
print(f"CODEX CONFIG PASS ({len(agents)} agents + espelho Claude; sintaxe, não integração runtime)")
