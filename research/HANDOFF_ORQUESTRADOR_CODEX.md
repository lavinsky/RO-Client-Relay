# HANDOFF — OrquestradorCLAUDE → Orquestrador Codex — ORCH-20261016-01

_2026-10-16. Entrega por arquivo (sessões Codex sem tokens/inalcançáveis por mensagem).
Segue `research/COORDINATION.md` (Entrega ao documentador / Relatórios). Sem dados crus nem
credenciais. Preservar este handoff até incorporação/decisão do orquestrador._

## Resumo de decisão (≤200 palavras)

Executei o plano aprovado `/.claude/plans/abundant-frolicking-aho.md`: **PoC de movimento integrado
ao relay/agent de produção, dirigido pelo OpenKore**. Um `035F` (CZ_REQUEST_MOVE) do consumidor passa
a acionar o **dispatcher nativo do cliente** (método do MOVER, §13.10), que monta/cifra/envia o
próprio `035F`; o servidor responde `0087` e o cliente fica vivo. O relay **não** fabrica corpo
cifrado nem reencaminha o `035F` original (dropado). **FUNCIONOU LIVE (2026-10-16), uma vez**,
dirigido por OpenKore. Como efeito colateral do mesmo caminho de inject-call, corrigi uma divergência
de pacotes de controle: o `0368` pré-select que o relay injetava antes de ações com alvo impedia
ataque `0437`/perícia `0438` (sentar `0437` com GID=0 sempre funcionou); agora é opt-in
(`--target-select`, default OFF).

**Autorizações usadas:** edição de `agent/` + `relay/` (decisão humana no plano); teste live no
servidor próprio do responsável. **Nada commitado** — mudanças em working tree. Push/commit continuam
bloqueados pelo classificador de auto-mode para o assistente; o responsável roda manualmente.
Documentação canônica já integrada por mim (abaixo).

## Rodada 09 — PoC relay `035F` → dispatcher nativo

- **ID:** ORCH-20261016-01a
- **Revisão executada:** working tree sobre `6c20733` (HEAD); `.py`/`.js` não commitados.
- **Pergunta:** o relay consegue produzir o `035F` do cliente via dispatcher nativo, dirigido pelo
  OpenKore, sem conhecer a cifra?
- **Condições:** build MATCH (`uaRO.exe f2f2…9569`, `gepard` base `0x76920000`); cliente PID 3520569
  porta 27053 (Wine); OpenKore XKore 1 porta 2350; servidor próprio.
- **Resultado observado:** `035F` do consumidor → `unpack_move` → dispatcher `0xd473b0` (fire-site
  `0x4dcba0`) → `035F` original dropado → `recv_0087 dst=destino` → cliente VIVO. 4 critérios = SIM.
- **Interpretação:** **OBSERVADO** (uma vez, live). A cifra **não** está compreendida — o relay só
  decide o destino; geração de keystream antes do XOR segue **DESCONHECIDA** (§13.8).
- **Rival:** nenhum resultado concorrente; falta reprodução multi-sessão (determinismo).
- **Cobertura/perdas:** `store_035f` do scrambler não observado (DRs ocupados por outros slots);
  origem+cifra+envio provados **funcionalmente** por `sendmsg`+`recv_0087`.
- **Evidências:** roteamento `relay/writeback.py:243,249`; `_arm` soma move_dispatch+inject_call
  `relay/writeback.py:101-107`; `relay/packets.py:119` `unpack_move`; `relay/protocol.py:106`
  `move_dispatch_msg`; agent `agent/relay_hook_linux.js:435,647-752` (`MD_RECIPES['walk-035f']`);
  flags `relay/cli.py:85,89,90`. Docs: `docs/MOVEMENT_035F_PRECONDITIONS.md` §13.11;
  `docs/RESEARCH_EVIDENCE_INDEX.md` M-12; `docs/RESEARCH_STATUS.md` M-12.
- **Orçamento DR (4/4):** DR0 scramble · DR1 SendPacket · DR2 captura `this` · DR3 fire-site →
  `--no-send-watch` obrigatório.
- **Invocação (rodada pelo responsável):**
  `./run.sh --inject --inject-call --move-dispatch --no-send-watch --out <dir>/relay_log.jsonl`
  (`--out` = arquivo; criar o dir antes).
- **Testes:** `bash scripts/test-offline.sh` PASS (11 scripts; inclui `move-dispatch routing ok`);
  `node --check agent/relay_hook_linux.js` PASS; `python3 scripts/validate-research.py` PASS.
- **Limpeza:** detach/unload ao Ctrl-C; DRs desarmados em `doFire`/dispose. `this` recapturado por
  sessão (relogin invalida PID/base/heap).

## Rodada 09b — pacotes de controle `0437`/`0438` × `0368` pré-select

- **ID:** ORCH-20261016-01b
- **Pergunta:** por que ataque `0437`/perícia `0438` não disparavam, enquanto sentar `0437` sim?
- **Resultado observado:** a única divergência era o `0368` (CZ_REQNAME_BYGID, pedido de nome por
  GID) que o relay injetava antes de ações com alvo. Responsável confirmou live: *sem* o `0368`, o
  `sendmsg` da ação sai. Sentar (GID=0) nunca emitia `0368`.
- **Interpretação:** envio sem `0368` = **OBSERVADO**; **execução completa** (dano/efeito) =
  **NÃO VERIFICADO** (re-teste live pendente).
- **Rival:** H-CIPHER-01 (falha por cobertura de cifra do `0438`) — **não refutada**, mas deixa de
  ser a única hipótese; a divergência OBSERVADA era a injeção do `0368`.
- **Evidências:** `relay/writeback.py:266,283` (gate `target_select`), `:31` (`0368` em `SKIP_IDS`);
  flag `relay/cli.py:80`; `tests/test_writeback.py` (default sem `0368`; caso `target_select=True`).
  Docs: `docs/GEPARD_CONTROL_PACKETS.md` (seção "Achado — `0368` pré-select…").
- **Testes:** cobertos pelo `test-offline.sh` PASS acima.
- **Limpeza:** n/a (mudança de código; sem sonda viva adicional).

## Arquivos alterados (working tree, NÃO commitados)

`agent/relay_hook_linux.js`, `relay/cli.py`, `relay/console.py`, `relay/packets.py`,
`relay/protocol.py`, `relay/writeback.py`, `tests/test_writeback.py`. Docs editados por mim
(autorizados pela tarefa de documentação): `docs/MOVEMENT_035F_PRECONDITIONS.md`,
`docs/RESEARCH_STATUS.md`, `docs/RESEARCH_EVIDENCE_INDEX.md`, `docs/GEPARD_CONTROL_PACKETS.md`,
`docs/OPERATIONS.md`. Sonda externa não versionável: `research/action_0437_0438/` (gerada).

## Próxima decisão para o orquestrador

1. **Re-teste live** de ataque `0437`/perícia `0438` (Ctrl-C + mesma invocação) para mover a execução
   completa de NÃO VERIFICADO → OBSERVADO. Owner sugerido: MOVER ou implementer, servidor próprio.
2. **Reprodução** de 06b/09 para avaliar determinismo (prioridade F.1 do RESEARCH_STATUS).
3. **Comparar** PoC do dispatcher nativo vs. via de relay (merge pré-XOR `gepard+0x18eff2`) e decidir
   a entrega realista rumo a xKore 0.
4. **Commit local** de movimento + controle (código) quando o responsável autorizar; push manual
   pelo responsável (classificador bloqueia o assistente). Caminhos explícitos acima.
5. Novos pacotes = +1 entrada em `MD_RECIPES` (costura de extensão mínima já existe) conforme o MOVER
   mapear dispatcher+frame de cada ação.
