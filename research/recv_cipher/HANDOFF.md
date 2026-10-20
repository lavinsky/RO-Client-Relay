# HANDOFF — recv_cipher: extração de pacotes já decifrados

**Atualização documental 2026-10-20 (sem nova sonda):** o bloqueio de fixture mencionado na seção histórica `Blocker / next step` foi resolvido na atualização de 03:18; resultados posteriores de 2026-10-19 constam no `STATE.md`. A sonda reutiliza descoberta assíncrona de ring do `ActorDecrypt`, teve 7/7 recuperados em amostra limitada com hardware BP e resultados divergentes sob carga; não concluiu captura perfeita. Testes offline específicos de correlacionador e atribuição de escritas **PASS** nesta revisão. Próxima dependência técnica: medir proveniência e backlog sob rajadas de `09FF` com critérios comparáveis e sem misturar bases/PCs de sessões diferentes. Nenhuma autorização live decorre desta nota.

## Goal
Capturar **do próprio cliente uaRO** o plaintext de todos os pacotes recebidos que tenham corpo cifrado, preservando ordem, limites e integridade. **Não** recuperar algoritmo, chave ou keystream (pesquisa CIFRA independente).

## Current state / evidence
- `20261018-021919`: `__recvmsg64` recebe wire com ID+length em claro e `09FD` cifrado; pacotes `0086` plausíveis perto de (155,184).
- `20261018-024630`: sete recuperações `09FD` no ring; correlacionador exige header, contexto claro posterior e corpo validado. Ring observado nessa sessão: `0x21020000` (não hardcodar).
- `20261018-025120`: PC de escrita in-place `Gepard+0x18EFF2`; **investigação de cifra encerrada nesta trilha**.
- `20261018-025841`: 5/5 `09FD`, 2/26 `09FF`, 0/5 `0229` recuperados; captura limitada era incompleta.
- **Último live** `artifacts/20261018-030335/recv_callsites.jsonl`: 120 receives, 12.923 bytes, 475 frames, 8 `09FD`, 46 `09FF`, **15 ring_match / 39 ring_miss**, sem erro de Frida, cleanup ok. Não demonstra 100% de cobertura.

## Decisions / constraints
Não alterar relay de produção, nem executar ptrace, CEserver debugger/debug trace (congelam o jogo). Frida Gadget in-process, uma instância instrumentada; dumps em `artifacts/` gitignored. Watchpoint e disassembly de `ring_watch.js` pertencem ao histórico, **não estão ativos na sonda padrão**.

## Changes pending verification — recorte inicial de 2026-10-18
`recv_probe.py`: captura TCP completa via iovec; patch recente coleta snapshot de 16 KiB do ring em `onEnter` de recv, **antes da próxima sobrescrita**, após primeiro `ring_match` informar a base por RPC. `ring_correlator.py`: enquadramento por FD, fragmentos, tipos `09FD/09FF/0229`, `ring_coverage`, `ring_snapshot_match` e deduplicação. `audit_coverage.py`: auditoria retrospectiva. **Nenhuma rodada live nessa versão.**

## Blocker / next step — recorte inicial de 2026-10-18 (resolvido posteriormente)
O teste `test_stream_detects_interior_and_fragmented` ainda falha: fixture feita com `RingCorrelator.__new__` não inicializa `snapshot_lock`, `awaiting`, `resolved`. Correções remotas tentadas foram bloqueadas. **Primeiro corrigir teste e exercitar snapshots/deduplicação offline; depois validar sintaxe Python/JS, diff e executar `./research/recv_cipher/run_probe.sh`.** Verificar se `ring_snapshot_match` reduz misses sem duplicar pacotes e se `0229` recebe validação suficiente. Não extrapolar para 100%.

## Context files (ordem)
`research/recv_cipher/STATE.md` → `README.md` → `recv_probe.py` → `ring_correlator.py` → `test_ring_correlator.py` → `audit_coverage.py` → `artifacts/20261018-030335/recv_callsites.jsonl`.

## Update 2026-10-18 03:18
Fixture corrigida e testes sintéticos de snapshot/deduplicação PASS. Sonda de 12 s concluída: 3/3 `09FD`, 0/1 `0229`; nenhum `09FF` e nenhum `ring_snapshot_match`. Coleta privada `artifacts/20261018-031820/recv_callsites.jsonl`. Auditoria ampliada para snapshots/deduplicação; eventos de match/miss agora possuem `candidate_id`. **Próxima etapa:** provar ganho de cobertura da captura de snapshots em janela com tráfego `09FF`, validar `0229` e ordenação antes de qualquer integração no relay.

## Adaptação ActorDecrypt — 2026-10-18 04:02
- Criado `actor_adapter.py`: usa `relay.actors.ActorDecrypt.note_chunk`, `note_enc` e `_best` via subclass investigativa, sem alterar produção nem ler/gravar cache de ring da produção. Guarda contiguidade por FD, cabeçalho `0229` de 2 bytes e seleção por pontuação/slot esperado.
- `ring_correlator.py`: buscas diretas, snapshots e replay consultam o mesmo motor de candidatos se a sonda está ativa. `test_ring_correlator.py`: testes sintéticos para `09FD` e `0229` pela interface do motor real, PASS.
- Coleta live 12s `artifacts/20261018-040036`: 9/10 `09FD` recuperados, nenhum erro Frida.
- Coleta live 60s `artifacts/20261018-040159`: 1072 pacotes enquadrados; 37/37 `09FD`, 3/3 `0229`, 0 `09FF` observados; 36 `ring_match`, 4 `ring_snapshot_match`; nenhuma duplicação, sem erros Frida. 4 `ring_miss` intermediários, resolvidos posteriormente por snapshot.
- Limitação: recuperação de `09FF` e fragmentação com novo motor ainda não foram demonstradas nesta rodada; capturas não simultâneas com baseline, portanto não concluir ganho percentual causal. Próximo passo: obter coleta rica em `09FF` e testar forte identidade de conexão e slots de chunks fragmentados.
