# recv_cipher — extração de plaintext de pacotes recebidos

**Estado atualizado em 2026-10-20:** os bloqueios antigos da fixture e da primeira prova de snapshot relatados abaixo foram resolvidos nas atualizações cronológicas de 2026-10-18/19. Testes locais `test_ring_correlator.py` e `test_audit_write_trace.py` passam nesta auditoria **offline**. Houve rodadas live registradas em `STATE.md` com recuperação parcial, quase total e zero sob carga; **não** há prova de 100% nem autorização nova para sondagem. O código da sonda usa instrumentação isolada (Frida Gadget, snapshots e opcionalmente hooks de escrita); não altera automaticamente o relay em produção. Consulte [STATE](STATE.md) e [HANDOFF](HANDOFF.md). Trechos de 2026-10-18 abaixo são históricos e não definem a condição mais recente.

## Escopo
Esta trilha **não investiga o algoritmo de cifragem**. O objetivo é obter, diretamente do cliente uaRO após sua própria decifragem, pacotes `0x09FD`, `0x09FF`, `0x0229` e quaisquer outros que exijam recuperação, na ordem original, com validação e cobertura mensurável. A pesquisa da cifra é independente. Não alterar o relay de produção.

## Fatos verificados
- O TCP recebido pelo cliente usa `__recvmsg64`; cabeçalho de `09FD` (ID e comprimento) permanece em claro e seu corpo chega cifrado.
- O cliente cria cópias em plaintext no ring de recepção. `ring_match` exige mesmo cabeçalho, corpo diferente e válido, mais contexto posterior idêntico; em `0229`, a validação é específica e ainda exige mais cobertura.
- O ring encontrado numa sessão foi `0x21020000`, **endereço não estável**. A posição real pode variar.
- O watchpoint histórico localizou uma escrita de decifragem em `Gepard+0x18EFF2`, mas não é necessário investigar a cifra nem manter o watchpoint ativo.
- Na última rodada validada (`artifacts/20261018-030335/recv_callsites.jsonl`): **8 `09FD` + 46 `09FF` vistos; somente 15 de 54 recuperados e 39 misses**. Portanto ainda não existe captura 100% funcional. Nenhum `0229` apareceu nessa rodada; outra coleta anterior encontrou cinco sem plaintext recuperado.

## Sonda e execução
```bash
./research/recv_cipher/run_probe.sh
```
Executar somente com cliente uaRO aberto e relay parado, **após corrigir o bloqueio de teste abaixo**. O launcher descobre PID/porta do Frida Gadget e verifica identidade do processo; duração padrão 12 segundos. Gera `artifacts/<timestamp>/recv_callsites.jsonl` privado e ignorado pelo Git.

- `recv_probe.py`: Frida Gadget in-process em `recvmsg/__recvmsg64/recv/recvfrom`, FD TCP classificado via `/proc`, payloads inclusive iovecs múltiplos até 4096 bytes por recepção. Patch **ainda não validado live**: captura snapshot binário de 16 KiB do ring no `onEnter` da **próxima** recepção, antes de sobrescrever o conteúdo anterior. A base só fica disponível depois do primeiro `ring_match`.
- `ring_correlator.py`: framing contínuo por FD, pacote cifrado em qualquer offset do stream, fragmentação, comparação wire/clear, `ring_match`, `ring_miss`, `ring_snapshot_match`, `ring_coverage` e controle de duplicações. Lê ring via `/proc/PID/mem` como alternativa; não escreve na memória.
- `audit_coverage.py`: audita contagens de pacotes, truncamentos e diferenças entre vistos/recuperados.
- `test_ring_correlator.py`: testes sintéticos, **PASS em 2026-10-20**. A falha antiga de fixture sem `snapshot_lock`, `awaiting`, `resolved` foi corrigida em 2026-10-18; mantida no registro histórico abaixo.
- `ring_watch.js`: sonda histórica de escrita, **desativada** na configuração padrão.

## Bloqueio histórico de 2026-10-18 (resolvido; ver estado atualizado acima)
**Não executar live ainda.** Corrigir a fixture mencionada, criar teste para snapshot antes da sobrescrita e deduplicação, validar `python3 -m py_compile research/recv_cipher/*.py`, `python3 research/recv_cipher/test_ring_correlator.py`, `bash -n research/recv_cipher/run_probe.sh`, sintaxe do JS injetado e `git diff --check`. Em seguida executar a sonda e comparar `ring_snapshot_match` com `ring_miss` e `ring_coverage`. Priorizar perdas por overwrite/timing, ordenação e validação de `0229` — **não algoritmos de cifra**.

Não usar `ptrace`, `cecli debug trace` ou attach do debugger CEserver, que congelam o processo Wine. Não versionar dumps/payloads nem presumir que um endereço de sessão seja constante. Alterações locais de pesquisa ainda não commitadas; nenhum push realizado.

## Diagnóstico contínuo de 09FF / EF63 no relay (2026-10-19)

O relay registra passivamente eventos `RECV-BOUNDARY` em `relay_log.jsonl`
(apenas stream do map server `:5121`). Cada `09FF` e o pacote seguinte incluem
`conn`, `offset`, `length`, `end`, `previous`, `tail` (últimos 8 bytes),
`next_prefix` (até 16 bytes posteriores) e `next_available`. Em um switch
inexistente, `event=unknown` registra também `prefix`, `preceding` e o último
ID reconhecido. Isso **não** altera o fluxo, não adiciona IDs à tabela e
não anexa outro debugger. Os bytes são amostras do **fluxo TCP observado pelo
relay**, não do cursor interno do Gepard. Ausência de `RECV-BOUNDARY` com
`EF63` não descarta erro local no cliente.

Para inspecionar após uma falha: `grep '"tag": "RECV-BOUNDARY"' relay_log.jsonl | tail -80`.
Não publicar trechos hex de sessões reais sem revisão.


## Inventário dos instrumentos ainda não publicados — revisão estática 2026-10-20

| Arquivo | Papel atual | Limite / cuidado |
|---|---|---|
| `recv_probe.py`, `run_probe.sh` | Hook de leitura via Frida Gadget, verificação de PID, disparo e finalização da sonda | Uso live só após autorização e exclusividade; não anexar à mesma sessão instrumentada por outra sonda |
| `ring_correlator.py`, `actor_adapter.py` | Reconstrução por FD, fragmentos, matching de ring e reuso de `ActorDecrypt` | Cópia candidata sem proveniência única não deve virar plaintext entregue a consumidor |
| `ring_watch.js` | Observação histórica por HW watchpoint de transições no ring | Modo opcional e intrusivo; PC e base de uma sessão não são constantes |
| `write_trace.js`, `audit_write_trace.py` | Trace explícito de escritas + auditoria offline de consistência com plaintext final | Escritas compatíveis não provam autoria causal única; testes sintéticos `test_audit_write_trace.py` PASS |
| `audit_coverage.py` | Audita integridade do fluxo, chunks truncados, candidatos e duplicações | Alvos contados são **09FD, 09FF, 0229**; não mede automaticamente 043F/0983 |
| `validate_0229.py` | Verifica estrutura de 15 bytes e flags opt1/opt2/option/stance em log privado | Valores de referência **não são allowlist de protocolo**; exige contexto + slot fresco e não substitui a decisão do relay |
| `sample_telemetry.py` | Polling de memória somente leitura, intervalo inicial de 1 ms e buffer limitado a 512 frames | **ALERTA:** apesar do docstring “never stores buffer contents”, `RingSampleTelemetry._run` armazena cópias completas de até 16 KiB do ring **em memória RAM** em `frames`. Não exportar nem versionar frames; o limite é de retenção, não de privacidade, e polling de 1 ms não garante 1 ms efetivo |
| `test_ring_correlator.py`, `test_audit_write_trace.py` | Contratos reproduzíveis de correlação e escrita | **PASS offline** na auditoria 2026-10-20, sem leitura da sessão real |

O conjunto é **misto**: `recv_probe.py` e `run_probe.sh` já são rastreados com mudanças locais; diversos auxiliares (`ring_correlator.py`, `actor_adapter.py`, rastreadores e testes) ainda não são rastreados por Git. A existência local ou o estado rastreado não equivalem a um PR publicado. `research/recv_cipher/STATE.md` é o registro cronológico das sessões efetivamente capturadas. A auditoria documental não modifica código nem executa a sonda.
