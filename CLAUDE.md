# Claude Code — complemento a AGENTS.md

`AGENTS.md` é a fonte única de regras (Claude Code e Codex leem ambos). Este arquivo só mapeia o que é específico do Claude.

| Codex | Claude Code |
|---|---|
| `.agents/skills/<nome>/` | `.claude/skills/<nome>` (symlink para `.agents/skills/<nome>`) |
| `.codex/agents/<nome>.toml` | `.claude/agents/<nome>.md` (mesmas instruções) |
| Sol (orquestrador / `implementer`) | sessão principal; `implementer` = `sonnet` |
| Luna (`explorer`, `verifier`) | `explorer` = `haiku`, `verifier` = `sonnet` |
| `codex -m gpt-6-astra` (decisões complexas) | sessão principal com Opus |

- Ao alterar um agente ou skill, mantenha os dois lados iguais; `python3 scripts/validate-codex.py` verifica a paridade.
- Skill nova: crie em `.agents/skills/<nome>/SKILL.md` e rode `ln -s ../../.agents/skills/<nome> .claude/skills/<nome>`.
- `.mcp.json` e `.claude/settings.local.json` são locais (caminhos absolutos da máquina); não versione.
