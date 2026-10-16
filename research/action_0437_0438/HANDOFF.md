# HANDOFF — ação/perícia 0x0437/0x0438 → Documentador

## ID: ACT-20261016-01 (método MOVER aplicado a 0437/0438 + testes de injeção nativa da perícia)
**Revisão base:** commit `6c20733` + sondas novas em `research/action_0437_0438/`.
**Autorização:** direta do responsável, ao vivo, para cada rodada (servidor próprio). Build uaRO+gepard = MATCH.
**Estado completo:** `research/action_0437_0438/STATE.md`. Artefatos privados (não versionar):
`/tmp/claude-act-20261016-031147-sendpkt/observe.json`, `/tmp/claude-act-20261016-110249-soulstrike2/inject.json`,
`/tmp/claude-act-20261016-111154-callers/callers.json`, `/tmp/claude-act-20261016-112037-ebp2/ebp.json`.

### OBSERVADO (ao vivo, read-only salvo §injeção)
- Mapa dispatcher `0xd473b0` → pacote: `0x11`→035f (andar; X,Y no frame); `0x1f`→0437 (sentar/levantar, GID
  próprio); **`0x28`→0437 (ataque, `3704 <GID> 07`)**; **`0x2a`→0438 (perícia, `3804 0a00 0d00 <GID>` =
  nível10/skill13 Soul Strike)**; `0x0a`→seleção de alvo. Fronteira em claro = `SendPacket` em
  uaRO+0x816640 (VA `0xC16640`); scrambler em `gb+0x18eff2`.
- `0x28`/`0x2a` **não levam args no frame** (leem alvo/perícia de estado global). Cadeia de cast observada:
  **`0x29`(skill13+GID) → `0x5a`(nível10) → `0x2a`(dispara)**.
- Caller imediato do dispatcher é SEMPRE o shim do Gepard **`gepard+0xb2c251`** (`[esp]`, todos os codes).

### INFERIDO (sequência + cross-check)
- `0x29` = seta skill id(13)+GID; `0x5a` = seta nível(10); `0x0a` = seleciona alvo. Cadeias: ataque = `0x0a→0x28`;
  perícia = `0x0a?→0x29→0x5a→0x2a`. O corpo do 0438 (nível10/skill13) casa com `0x29`+`0x5a`.

### TESTE DE INJEÇÃO (ao vivo, autorizado) — NEGATIVO
- Replay da cadeia de perícia (`0x29→0x5a→0x2a`) via mecanismo do PoC 035f (captura `this` + chamada thiscall do
  fire-site de main-loop `0x4dcba0`): `0x2a` retorna **0**, **nenhum `0x0438` sai na rede** (perícia NÃO conjurada)
  e o cliente **crasha** (rodada 1 por bug meu com movimento no replay; rodada 2, cadeia mínima limpa, crash
  deferido). CONCLUSÃO: a via nativa disparada de `0x4dcba0` é **inócua e instável** para a perícia — o commit
  depende de estado/contexto do handler de input que esse disparo não tem.

### REFUTADO
- "O `0368` pré-ação era o bloqueio da SendPacket de 0437/0438" — **FALSO** (responsável): o SendPacket sempre
  ocorria com/sem `0368`; o problema (ação sem efeito) é anterior ao `0368`. Rotear 0437/0438 pela SendPacket crua
  **não executa** a ação. → Corrigir qualquer doc que credite o `0368`/`--target-select` como solução de ataque/perícia
  (ver memória `movement-035f-poc-live-works` §ataque/perícia, já marcada como refutada).

### RETIRADO (não publicar como fato)
- Cadeias de chamadores do dispatcher obtidas por `Backtracer.FUZZY` e por EBP-walk: ao validar no objdump,
  os endereços não são retornos de `call` genuínos (frames SEH/FPO + trampolim do Gepard quebram a pilha). Só o
  shim imediato `gepard+0xb2c251` é confiável. O split "prepare vs commit" NÃO está provado.

### EM ABERTO / próxima decisão
- Achar o sítio real de disparo do `0x2a` e a pré-condição que ele lê, via **validated stack scan** (read-only;
  manter só dwords da pilha que são retorno de `call` comprovado no disassembly). Responsável mantém janela ao
  vivo disponível (estabilidade não é problema; pode reabrir o cliente e reconjurar à vontade).

### Sugestão de integração em `docs/` (decisão do Documentador)
- `docs/GEPARD_CONTROL_PACKETS.md`: registrar codes `0x28`/`0x2a`/`0x1f`/`0x0a` e a cadeia de cast.
- `docs/MOVEMENT_035F_PRECONDITIONS.md`: nota de que a via nativa (fire-site `0x4dcba0`) **não** transfere para a
  perícia (OBSERVADO), distinta do movimento.
- Corrigir no índice/‘status’ a REFUTAÇÃO do `0368` como solução.

**Verificações:** `py_compile` de todas as sondas OK; `tests/test_movement_preconditions.py` PASS;
`scripts/validate-research.py` PASS. **Limpeza:** nenhuma sonda ativa; `docs/`/`relay/`/`agent/` não editados;
nenhum commit.
