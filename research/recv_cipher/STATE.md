# STATE — extração de pacotes recebidos em plaintext (2026-10-18)

## Objetivo e limite
Extrair do cliente uaRO **os pacotes já decifrados**, com enquadramento, ordem e cobertura verificáveis. **Não** investigar algoritmo, chaves ou keystream: isso pertence à trilha CIFRA. Não modificar o relay de produção. Não usar ptrace, CEserver debugger ou debug trace (congelam o cliente). Uma sonda por instância; sem escrita na memória do jogo.

## Evidência observada
- `artifacts/20261018-021919/recv_callsites.jsonl`: TCP via `__recvmsg64`; headers `09FD` com ID+length em claro e corpo incompatível com ator; pacotes `0086` com coordenadas compatíveis com (155,184).
- `artifacts/20261018-024630/recv_callsites.jsonl`: sete correlações de `09FD` cifrado com plaintext na memória; ring `0x21020000`, slots variáveis, cópias com mesmo cabeçalho/contexto e corpo de ator válido.
- `artifacts/20261018-025120/recv_callsites.jsonl`: escrita por `Gepard+0x18EFF2` (`mov byte ptr [ecx], bl`), observada por watchpoint. Descoberta histórica útil para localizar a fronteira, **não é objetivo continuar reverse engineering da cifra**.
- `artifacts/20261018-025841/recv_callsites.jsonl`: análise offline de fluxo identificou 5 `09FD`, 26 `09FF` e 5 `0229`; a sonda antiga recuperou 5, 2 e 0, respectivamente; existiam chunks incompletos por limite de payload.
- `artifacts/20261018-030335/recv_callsites.jsonl`: 120 chamadas, 12.923 bytes, 475 pacotes enquadrados, 8 `09FD` + 46 `09FF` detectados, 15 `ring_match`, 39 `ring_miss`, cleanup ok. **Não há 100% de recuperação.** `0229` não apareceu nessa janela.

## Estado inicial de instrumentação — 2026-10-18 (histórico; ver atualizações abaixo)
- `run_probe.sh`: descobre e verifica identidade de uaRO, aciona `recv_probe.py` (12 s), artefatos privados.
- `recv_probe.py`: intercepta `recvmsg/__recvmsg64/recv/recvfrom` via Frida Gadget; classifica TCP e captura até 4096 bytes por chamada. Mudança mais recente adicionou **snapshot do ring no onEnter da próxima recepção**, antes da sobrescrita, com envio binário `ring_snapshot`.
- `ring_correlator.py`: tokeniza por FD, mantém fragmentos, seleciona `09FD/09FF/0229` em qualquer offset, valida corpo e contexto, lê ring via /proc como alternativa; recebeu método `snapshot` e estado para evitar duplicações. O snapshot só inicia **após descoberta do ring por correlação inicial**; perdas anteriores continuam possíveis.
- `audit_coverage.py`: contagem retrospectiva por pacote e lacunas; `test_ring_correlator.py`: fixtures sintéticas.
- `ring_watch.js`: artefato de investigação anterior, **desativado** na sonda padrão; não retomar investigação da cifra.

## Bloqueio inicial e próximo passo de 2026-10-18 (superados na sequência cronológica)
A integração dos snapshots ainda **não passou nos testes offline**: `test_stream_detects_interior_and_fragmented` cria `RingCorrelator.__new__` sem `snapshot_lock`, `awaiting` e `resolved`, gerando `AttributeError`. Tentativas de corrigir no computador foram bloqueadas pela ferramenta remota. **Corrigir fixture, validar Python/JS e casos de snapshot/duplicação antes de qualquer teste live.** Só então executar `./research/recv_cipher/run_probe.sh`, avaliar `ring_snapshot_match`, `ring_match`, `ring_miss` e `ring_coverage`, e testar diferenças com intervenções na ordem e timing.

## Estado de execução
Última rodada live validada: `20261018-030335`, antes da alteração de snapshots. Nenhum teste live da versão atual; não afirmar sucesso. Alterações locais ainda não commitadas; não houve push. A limpeza da rodada anterior confirmou `cleanup ok`; não há instrumentação permanente planejada.

## Rodada de validação 2026-10-18 03:18
- Corrigida fixture offline que não inicializava o correlacionador; testes de snapshot/contexto errado/FD errado/deduplicação PASS. Sintaxe Python, JS e bash; `git diff --check`: PASS.
- Live `artifacts/20261018-031820/recv_callsites.jsonl`: 98 `recv`, 6.643 bytes, 658 pacotes enquadrados, 3 `09FD` recuperados por `ring_match`, 1 `0229` com `ring_miss`, 0 `ring_snapshot_match`. Sem erros de Frida, `cleanup` presente. Amostra sem `09FF`; não há evidência de ganho por snapshot.
- `audit_coverage.py` agora conta `ring_snapshot_match` e detecta duplicações por `candidate_id`; `ring_correlator.py` inclui esse ID em `ring_match` e `ring_miss` nas próximas capturas.
- **Pendente:** capturar amostras com `09FF` e `0229`, investigar timing da habilitação de snapshots e qualidade da validação `0229` antes de integrar ao relay. Nenhuma mudança no relay de produção.

## Adaptação ActorDecrypt — 2026-10-18 04:02
- Criado `actor_adapter.py`: usa `relay.actors.ActorDecrypt.note_chunk`, `note_enc` e `_best` via subclass investigativa, sem alterar produção nem ler/gravar cache de ring da produção. Guarda contiguidade por FD, cabeçalho `0229` de 2 bytes e seleção por pontuação/slot esperado.
- `ring_correlator.py`: buscas diretas, snapshots e replay consultam o mesmo motor de candidatos se a sonda está ativa. `test_ring_correlator.py`: testes sintéticos para `09FD` e `0229` pela interface do motor real, PASS.
- Coleta live 12s `artifacts/20261018-040036`: 9/10 `09FD` recuperados, nenhum erro Frida.
- Coleta live 60s `artifacts/20261018-040159`: 1072 pacotes enquadrados; 37/37 `09FD`, 3/3 `0229`, 0 `09FF` observados; 36 `ring_match`, 4 `ring_snapshot_match`; nenhuma duplicação, sem erros Frida. 4 `ring_miss` intermediários, resolvidos posteriormente por snapshot.
- Limitação: recuperação de `09FF` e fragmentação com novo motor ainda não foram demonstradas nesta rodada; capturas não simultâneas com baseline, portanto não concluir ganho percentual causal. Próximo passo: obter coleta rica em `09FF` e testar forte identidade de conexão e slots de chunks fragmentados.

## 2026-10-19 — sonda isolada, descoberta interna e snapshots (sem integração ao relay)

- Observado `artifacts/20261019-182530`: 30 s, 10 pacotes 09FD, 0 recuperados, 10 `ring_miss`.
- Ajuste apenas em `ring_correlator.py`: reutilizar `ActorDecrypt.quick_discover` para localizar ring **dentro** dos mapeamentos, verificando corpo de ator decifrado e bytes claros adjacentes; a busca antiga limitava-se principalmente ao início das regiões.
- Observado `artifacts/20261019-182859`: 35 s, 16/16 09FD e 2/2 0229 recuperados; descoberta inicial `production_masked_discovery` e 17 leituras `known_ring`, sem duplicações.
- Observado `artifacts/20261019-182943`: 60 s, 70 09FF + 4 09FD + 2 0229 detectados, **nenhum recuperado**; descoberta inicial levou 90–235 ms por tentativa e causou fila crescente. Não extrapolar a taxa positiva para tráfego intenso.
- Introduzido `RECV_PROBE_RING_HINT` opcional, endereço somente como pista de uma captura validada **na mesma vida do processo uaRO**. Cada cópia precisa passar pela validação completa; se a pista falhar, ela é descartada e inicia-se redescoberta. Não hardcodar endereço em produção.
- Observado `artifacts/20261019-183115`: 60 s, 14/14 09FD recuperados (4 `ring_match`, 10 `ring_snapshot_match`), 0 duplicações, usando endereço de ring confirmado em captura anterior da mesma sessão. Houve 1 `ring_miss` intermediário posteriormente resolvido por snapshot. Nenhum 09FF ou 0229 nessa janela.
- **Próximo passo:** validar o caminho de hint + snapshot com 09FF em tráfego denso, medir backlog e impedir correlação indevida; só então considerar integração no relay. Nenhuma garantia de 100% em geral, não alterada produção.

## 2026-10-19 — slot diagnostics for unresolved candidates

Read-only `ring_slot_live_diagnostic` / `ring_slot_snapshot_diagnostic` records
for unmatched candidates include the predicted offset, a truncated SHA-256
fingerprint, whether bytes equal wire, and the breakdown of the existing relay
`copy_validation()` checks. No decrypted name, GID or payload is logged by
these new diagnostic events. Up to three snapshot diagnostics per unresolved
candidate. Observed `artifacts/20261019-184839`: 60-second sample with 224
09FF and 16 09FD; respectively 221 and 14 recovered. Five unresolved
candidates (09FF: 41/67/96; 09FD: 211/219) consistently had an invalid
header at the predicted slot. Their fingerprints sometimes changed between
snapshots; this cannot yet distinguish overwrite from incorrect slot mapping.
Production relay not modified.

## 2026-10-19 — diagnóstico de deslocamentos alternativos

A sonda registra agora, apenas em falhas de correspondência durante snapshots,
quantos cabeçalhos e cópias **estruturalmente válidas** aparecem em outros
offsets da região capturada, sem liberar plaintext nem aceitar esses candidatos.
`artifacts/20261019-185105`: 14/14 recuperados; `artifacts/20261019-185142`:
23/23 recuperados. No segundo teste o candidato 29 apresentou candidato válido
no offset 419 durante snapshots 244–246, mas sua recuperação confirmada ocorreu
posteriormente no offset esperado 64 (snapshot 259). Portanto o offset 419 não
pode ser atribuído ao pacote 29 apenas pela estrutura; correlação temporal segue
necessária. Não houve perdas definitivas nessas duas amostras, então a causa dos
cinco misses da coleta anterior permanece indeterminada. Produção inalterada.

## 2026-10-19 — transição de escrita capturada com watchpoint

Sonda isolada `RECV_WATCH_BP=1` usa o mecanismo histórico de watchpoint de
hardware no offset `ring+0x44`, armando na saída de recv e desarmando após
125 ms. Alteração apenas no arquivo de pesquisa `ring_watch.js`: os eventos
registram `initial_word`, `final_word` e `duration_ms`, além dos eventos de
escrita já existentes. Não alterou a produção nem escreve memória do cliente.

Observado `artifacts/20261019-190226` (12 s): 31 janelas e 91 traps de escrita;
uma sequência incluiu o PC posterior à instrução nativa `mov byte ptr [ecx], bl`.
Observado `artifacts/20261019-190327` (30 s): 92 armaram, 92 janelas fechadas,
288 traps, alteração entre valor inicial/final nas 92, sem erros de sonda.
23/23 pacotes 09FD e 2/2 0229 recuperados, sem 09FF nessa amostra.
A captura **prova escrita nesse endereço**, mas não prova que todo evento
corresponde ao plaintext de um pacote específico nem resolve a causa dos
misses de 09FF. Próxima etapa é sincronizar armamento e associação temporal
por pacote/slot e coletar sob rajadas de 09FF, conservando validação de
proveniência.

## 2026-10-19 — hook direto na instrução de escrita (sonda isolada)

Foi criado `write_trace.js`, habilitado exclusivamente por `RECV_WRITE_PC` e
instalado após base do ring validada, somente se a instrução no endereço indicado
é exatamente `mov byte ptr [ecx], bl` em mapeamento executável. Para cada escrita
no intervalo `ring+0x40 .. ring+0x4000`, registra sequência da escrita, offset,
byte, thread e última recepção observada nessa thread. Buffer de até 64 eventos
por lote e limite máximo de 30.000 escritas; cleanup desinstala hook e despeja
lote restante. O endereço do PC não é constante após reiniciar cliente.

`ring_correlator.py` emite `ring_candidate` (sem corpo) com `candidate_id`,
`recv_seq`, FD, thread, instante, ID, slot e tamanho. `audit_write_trace.py`
compara writes no slot e recepção correspondentes com plaintext efetivamente
recuperado; nunca classifica essa coincidência isolada como prova inequívoca de
proveniência. Testes sintéticos em `test_audit_write_trace.py`.

Coleta `artifacts/20261019-191224` (8 s): 11.537 escritas capturadas, nenhuma
perdida pelo limite, sem erros do hook. Coleta
`artifacts/20261019-191350` (20 s): 984 escritas, 11 pacotes recuperados,
9 com todas as escritas observadas no intervalo do slot compatíveis com os
bytes do plaintext final, e 2 sem escrita na janela correspondente; 0 escrita
incompatível nos 9. **Classificação: correspondência consistente, ainda não
associação de origem demonstrada univocamente.** Nenhum 09FF nessa amostra.

Tentativa seguinte de coleta em `artifacts/20261019-191503` não iniciou:
`ro_ops discover` retornou `unverified` com zero candidatos uaRO.exe/Gadget;
portanto não houve teste de alta carga nessa rodada. Nenhum endereço da sessão
antiga pode ser reutilizado após reinício do cliente. Produção não modificada,
sem commits.

## 2026-10-19 — sonda reutiliza descoberta assíncrona de ring do relay

`ring_correlator.py` agora reutiliza diretamente `ActorDecrypt.start_quick_discover`
com o chunk TCP **completo** de cada `recv`, offsets absolutos e itens cifrados
marcados `E`, em lugar de descobrir a partir de um único pacote isolado ou
varrer todas as regiões de memória no worker de correlação. O callback `on_ring`
da implementação de produção atualiza a base da sonda e arma a coleta de
snapshots/hardware breakpoint, sempre após verificação de plaintext.
Não houve alteração em `relay/actors.py`, nem persistência de endereço.

Teste ao vivo sem endereço fixo de ring, no mesmo processo `uaRO.exe`
PID 1417583: `artifacts/20261019-193122` confirmou descoberta via
`ActorDecrypt.start_quick_discover` em 0x23410000. Sonda com watchpoint
`artifacts/20261019-193202` confirmou a instrução de escrita observada nessa
sessão (`0x76aaeff2`), também com descoberta automática. Sonda com hardware
execution breakpoint `artifacts/20261019-193230`: 528 escritas, 0 descartes
por limite do hook, 7/7 candidatos recuperados, 5 com escritas e bytes
consistentes na janela/slot e 2 sem escritas observadas nessa janela. Isso
**não prova** proveniência única e não valida recuperação sob rajadas de 09FF.
Teste offline `test_production_quick_discovery_receives_full_chunk` exercita
passagem integral do chunk, itens, callback e ausência de varredura síncrona.

Produção inalterada. Nenhum commit ou push.


## Auditoria documental 2026-10-20 — estado do checkout, sem novas sondas

**Procedência:** revisão dos arquivos locais ainda não commitados de `research/recv_cipher/` contra `origin/main@9ee7ef5`, e dos registros históricos acima. `test_ring_correlator.py` e `test_audit_write_trace.py` **PASS offline**, `bash -n run_probe.sh` e `node --check ring_watch.js/write_trace.js` **PASS**. `validate_0229.py` aceita caminho de log como entrada; não foi executado sobre uma captura privada. A suíte principal `bash scripts/test-offline.sh` passou **37 scripts**. Não houve cliente instrumentado nesta auditoria.

**Estado científico/operacional:** o correlacionador com `ActorDecrypt.start_quick_discover`, snippets de contexto, snapshots, hashes de diagnóstico e coleta explícita de escritas é um instrumento **isolado**, não um produto que extraia todos os plaintexts garantidamente. Coletas anteriores positivas (ex.: `20261019-184839`: 221/224 `09FF` e 14/16 `09FD`) convivem com perdas completas sob carga (`20261019-182943`: 0 recuperados para 70 `09FF`, 4 `09FD` e 2 `0229`). Hooks de escrita mostraram compatibilidade com bytes recuperados em janelas delimitadas, mas não provaram atribuição unívoca do escritor a todo candidato. Falta comparação sob carga controlada, sem misturar process lifetime, offsets, ring hints e tempos.

**Próximo discriminador, somente após autorização live separada:** isolar falhas por sobrescrita e correlação temporal de `09FF`, confrontar recebidos/recuperados, falsos positivos e duplicações no mesmo cenário; testar `0229` sem pressupor plaintext de GID igual ao cifrado. Endereços de sessão não são constantes. **CIFRA** (seed/gerador/estado) continua outra pesquisa, em `research/cipher/`.
