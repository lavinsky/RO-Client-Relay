# HANDOFF — ro_ops — RO-OPS-20261015-01

Revisao: base `4354615` + working tree (nao commitado). Pergunta: kit operacional fase 1 offline.

**Entregues (5):** discover, sample-thread, env-check (read-only); new-artifact, scaffold-state
(private-write). `verify-build`/`validate` NAO implementados (Fase 2; teste exige exit 1).
Contrato `{cmd,status,data,caveats}`, exit 0/10/20/1: `ro_ops/contract.py:6-14`, `make`/`emit`.
Extra fora da lista: `ro_ops/common.py` (git, sha256, starttime) e `ro_ops/HANDOFF.md`.

**Reuso:** `relay/agent.py:13` gadget_ports e `:41` pid_of_port (sem reparse de `ss`; `ro_ops/discover.py:9-16,54`);
main_tid em /proc/<pid>/task (`discover.py:27`). `research/movement_035f/sample_thread.py:25,60,73`
(read_state/sample_series/classify) carregado por importlib, sem copia (`ro_ops/sample.py:11-16`).
Espirito de `tools_sha256` (`research/cipher/chain_capture.py:389`) e `_hash_copy`
(`research/movement_035f/dispatcher_trial_onleave.py:278`) em `ro_ops/artifact.py` (copia + sha256 + PROVENANCE.txt 0600, dir 0700).

**Garantias medidas por teste:** exclusividade sempre `not_determined`; multiplos gadgets,
ss ausente, corrida pid_of_port ou /proc/task ilegivel -> undetermined; `worst()` nunca promove
undetermined; chaves de credencial/trafego rejeitadas; escrita no repo so em `research/<trilha>/`
(docs/, relay/, agent/, scripts/, .codex, tests recusados), sem overwrite nem symlink.

**Cobertura:** `python3 tests/test_ro_ops.py` 31 testes PASS com doubles (4 status, exit 0/10/20/1).
`validate-research.py`, `validate-codex.py`, `scripts/test-offline.sh` (11 scripts) e `git diff --check`: PASS.

**NOT RUN (prova viva):** `sample-thread` contra a thread do cliente real; validacao do classificador
no cliente ocioso (pendencia de STATE MOVER); `discover` com gadget uaRO real so foi consultado de forma
read-only de passagem, sem teste automatizado; Win32 main thread != tid lider nao verificado.

**Codex:** descobre skills em `.agents/skills/*/SKILL.md` (validate-codex.py:16); `ro-ops` la, com
espelho `.claude/skills/ro-ops` (symlink exigido por validate-codex.py:28-30). `.codex/config.toml`
nao lista skills (so `[skills] max_context_tokens`), logo nada alterado. Execucao pelo Codex
(sandbox workspace-write, sem rede) nao testada. Documentador: citar o kit em docs/CODEX_WORKFLOW.md.

Limpeza: nenhum processo/recurso ativo; nada fora destes caminhos foi escrito.
