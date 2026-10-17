# Índice de evidências técnicas — RO-Client-Relay

**Atualização 2026-10-17:** movimento e ações encerrados funcionalmente; somente cifra é pesquisa aberta. A evidência de código para o defeito do byte zero está em `agent/relay_hook_linux.js:481-534`. Ver [A-02/A-03 abaixo](#a-02a-03--fechamento-de-movimento-e-ações-2026-10-17).

> **Integração 2026-10-16:** [entregas conferidas e limites](#c-08--integração-cifra-20261016-pop-03) atualizam os checkpoints anteriores; relatos, consistência de artefatos e prova independente permanecem distintos.

**Revisão:** 2026-10-15. **Referência:** revisão local `524b0f05fa61872e140f98ace9e503d12356641e`. Os resultados abaixo são **documentados em fontes primárias do repositório**, não verificados de novo em cliente real por esta auditoria. Os artefatos privados citados nos estudos **não acompanham** este índice.

| ID | Estado | Evidência / método original | Build e condições | Documento canônico / código | Limitação principal |
|---|---|---|---|---|---|
| M-01 | **OBSERVADO** | S1/S2: 6/6 capturas positivas, sequência `0x11→0x0D→0x5B→0x8A` até store de `0x035F` | Duas instâncias do mesmo build documentado, sessões distintas | [Investigação §§S1/S2](MOVEMENT_035F_INVESTIGATION.md); `research/movement_035f/` | Capturas até primeiro hit, não cobertura total de movimentos |
| M-02 | **OBSERVADO/INFERIDO** | ABI natural `(0x8A,x,y,0,0)`; ECX manager; ESP compatível com cinco argumentos; resposta `0x0087` correspondente | Mesmo build, cliques alternados e controles | [Investigação §ABI](MOVEMENT_035F_INVESTIGATION.md); `relay/packets.py` | ABI semântica inferida; ACK não prova conclusão do percurso |
| M-03 | **OBSERVADO** | Observadores independentes dispatcher/receptor/store/`sendmsg`/`recv_0087`, ordenação por evento | Run read-only de 10 s na janela controlada | [Pré-condições §5](MOVEMENT_035F_PRECONDITIONS.md); `research/movement_035f/observe_path.py` | `sendmsg` temporalmente correlacionado, bytes não identificados naquele run |
| M-04 | **REFUTADO no recorte** | Ensaio 6.4: `0x8A` isolado entra e retorna, sem store/`sendmsg` atribuível; controles naturais funcionam antes/depois | Mesmo build, objeto/args/thread conferidos, observadores independentes | [Pré-condições §§4–5](MOVEMENT_035F_PRECONDITIONS.md); `research/movement_035f/native_trial.py` | Refuta M-H1 (falha apenas de observabilidade), não distingue M-H2/M-H3; não ausência global |
| M-05 | **OBSERVADO/INFERIDO** | Disassembly dos casos `0x11/0x0D/0x5B`, campos +0x500/+0x50c/+0x510/+0x520/+0x534/+0x538 | Código identificado; distinção dos objetos dispatcher/receptor | [Pré-condições §3](MOVEMENT_035F_PRECONDITIONS.md); [Investigação §Casos internos](MOVEMENT_035F_INVESTIGATION.md) | Consumidor dos campos e unidade de `0x15E` não observados |
| M-06 | **REFUTADO no recorte** | Wrapper `+0x875400` observado em controles de repouso e de movimento; `0xc7650e` faltou em uma amostra positiva | S1 e uma amostra de callsite | [Investigação §§S1/Origem](MOVEMENT_035F_INVESTIGATION.md) | Não elimina esses caminhos de todos os ramos ou funções |
| C-01 | **OBSERVADO** | Breakpoints com operandos preservados verificaram `+0x1B223C → +0x1B2255 → +0x18EFEC..+0x18EFF2` em recortes delimitados | Arquivos de módulos identificados e revalidados em 2026-10-15 | [Cifra §Continuação dinâmica](CIPHER_INVESTIGATION.md); `research/cipher/chain_capture.py` | Não identifica entrada/saída de função criptográfica |
| C-02 | **OBSERVADO independente** | Watchpoint do byte consumido + escritor `+0x1C752B mov [esi],cl` confirmado em rodada isolada | Mesmo build; recortes não fundidos indevidamente | [Cifra §Evidências e limites](CIPHER_INVESTIGATION.md) | Última definição de CL e conexão com recorte consumidor não concluídas numa só rodada |
| C-03 | **OBSERVADO** | 26 rodadas, contagem de matches/timeouts/exceções e limpeza | Capturas reportadas em 2026-10-15, observação por thread | [Cifra §Rodadas](CIPHER_INVESTIGATION.md); `research/cipher/chain_audit.py` | Timeout ≠ ausência global de escrita; alguns observadores incompletos |
| C-04 | **NÃO VERIFICADO** | Auditoria de onze fontes: nenhuma chamada P/C/estado completa; ferramenta retorna `C_INSUFFICIENT` | Escopos variados, não unir sessões por nome/tempo | [Cifra §§Auditoria/Ferramenta](CIPHER_INVESTIGATION.md); `research/cipher/analyze.py` | Sem identidade de F, estado, inicialização, pacote ou cifragem independente |
| C-05 | **OBSERVADO** | Origem de CL: carga de dword em `+0x1C7502`, ECX estável até store `+0x1C752B`; 13 pontos/9 ms e byte posterior conferido | Mesmo build, nova instância descoberta e janela exclusiva; origem `EBP+0x36` nessa ocorrência | [Cifra — retomada](CIPHER_INVESTIGATION.md#retomada-após-consolidação--origem-executada-de-cl); `cl-round-1/chain-capture.json:161` em `/tmp/ro-cipher-20261015T174618Z/` | Não demonstra escritor da origem, operação da cifra ou continuidade com sessões anteriores |
| C-06 | **OBSERVADO** | XOR de dword `+0x2689FB`, operandos e resultado antes/depois conferidos; 17 escritas seguintes | Nova instância, mesma build, janela exclusiva | [Cifra — nova instância](CIPHER_INVESTIGATION.md#nova-instância-e-primeiro-escritor-aritmético-observado); `session2-cl-transform-round-1/chain-capture.json`, evento `DONE.cl_transformation`, na mesma raiz privada de C-05 | Não associado ao consumidor de CL; papel criptográfico desconhecido |
| C-07 | **OBSERVADO / INFERIDO** | 129 escritas, depois 13 pontos de carga→CL→store; última escrita com candidata única `+0x1C70DC pop [edx]`, byte correspondente | Mesma instância de C-06; teto de 256 autorizado; observação em uma thread | [Cifra — nova instância](CIPHER_INVESTIGATION.md#nova-instância-e-primeiro-escritor-aritmético-observado); `session2-cl-writer256-round-1/chain-capture.json`, `DONE.cl_preceding_write` | POP ainda sem prova antes/depois; sem origem do operando, cifra, inicialização ou identidade de pacote |
| G-01 | **OBSERVADO apenas na tabela** | IDs `8280 128`, `4754 -1`, `5395 -1`, `C392 -1` | Tabela do repositório, não captura de sessão | [Controle](GEPARD_CONTROL_PACKETS.md); `data/uaro_recvpackets.txt` | Tamanho tabelado não determina direção, função ou handshake |
| G-02 | **DOCUMENTADO apenas para 2016** | `SC_GEPARD_INIT`, `CS_GEPARD_INIT_ACK`, `CS_GEPARD_SYNC`, estados históricos | Fonte Gepard 2016, não equivalência do uaRO atual | [Controle](GEPARD_CONTROL_PACKETS.md); [investigação histórica](HISTORY/GEPARD_LEGACY.md) | Necessário revalidar IDs/algoritmo/direção no build atual |
| R-01 | **OBSERVADO no código/configuração** | `inject = true`, `inject-call = true`; separar merge stack do `SendPacket` fila; frames XKore | Revisão de código publicada em 2026-10-15 | `relay_capture.conf`; `relay/writeback.py`; [arquitetura](ARCHITECTURE.md) | Verificação estática não prova cliente/servidor funcionando agora |

## Notas de procedência e auditoria

- **Identidade de módulos do estudo:** `uaRO.exe` SHA-256 `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569`; `gepard.dll` SHA-256 `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b`. Hashes citados em [CIPHER_INVESTIGATION §Build](CIPHER_INVESTIGATION.md); não provam identidade do estado criptográfico entre sessões.
- **Bases de endereços:** código anônimo uaRO referenciado em `0x401000`, base PE em `0x400000`, bases Gepard variáveis por relog. Offsets de sessão só podem ser interpretados junto às bases e hashes; não são assinatura universal. [MOVEMENT_035F_INVESTIGATION §Convenções](MOVEMENT_035F_INVESTIGATION.md).
- **Artefatos externos:** caminhos em `/tmp/` citados nos estudos apontam para material de execução original; este índice não afirma que continuam disponíveis. Para reproduzir, exigir autorização separada, revalidar build e limites e não copiar dados privados.
- **Independência epistemológica:** códigos `M-H1` e `C-H1` são linhas de pesquisa diferentes; não fundi-los. Ausência de hit não é ausência de evento fora da cobertura observada.

## Evidência incorporada após o pacote inicial

| ID | Status e origem | Recorte e resultado | Limite / refutação |
|---|---|---|---|
| M-07 | OBSERVADO no registro; commits `2645fad`, `87245d6`; `MOVEMENT_035F_PRECONDITIONS.md` §12 | Argumentos iguais; sem ponteiro nos 1024 B bidirecionais + 128 B do registro global, 8+ eventos; contexto de retorno difere | Refuta passagem de campo por argumento nesse callsite e restringe ligação por ponteiro; não exclui valor global/TLS/indireções |
| D-01 | OBSERVADO offline nesta consolidação; `DOCUMENTATION_AUDIT.md` | Manifesto/CRC conferidos; aplicador recusou HEAD divergente sem escrita; reconciliação manual | Não valida resultados vivos nem integridade atual de capturas externas |

Reprodução offline dos contratos: `python3 tests/test_movement_preconditions.py` e
`python3 tests/test_cipher_research.py`. Não reproduzem os experimentos históricos vivos.

## M-08 — ensaio do dispatcher, corrigido após integração

**Origem:** `524b0f0`, corrigido em `888764a`; [pré-condições §13](MOVEMENT_035F_PRECONDITIONS.md).
**OBSERVADO no registro:** buffer compatível no trap pré-store em `disp2`, sem confirmação
de escrita final, pacote completo, retorno normal, envio ou resposta. `disp5` sem HW BPs
é outra condição; não fornece confirmação daquele trap. **OBSERVADO por disassembly:**
`ret 0x34` = 52 bytes; chamada com 44 bytes. **HIPÓTESE então levantada:** desequilíbrio de 8 bytes como causa da falha;
explicação exclusiva superada pelo ensaio M-09 abaixo. Necessidade individual H2/H3 não demonstrada; reentrância segue aberta.
Nova coleta requer proposta própria. Capturas privadas não foram abertas nesta integração.

## P-01 — identificação de proteções recebida na main

**Origem:** `77954b2`, integrado em `origin/main@0a29193`;
[PROTECTION_FINGERPRINT_DIE.md](PROTECTION_FINGERPRINT_DIE.md).
**OBSERVADO e confirmado pelo responsável no DiE:** Themida/WinLicense 3.XX em `uaRO.exe`,
VMProtect em `gepard.dll`, arquivos da mesma build. **NÃO VERIFICADO:** quais funções estão
virtualizadas; não atribuir automaticamente uma região anônima a um protetor.

## M-09 — ABI de 13 dwords também trava

**Origem:** `7a64581`, [pré-condições §13.5](MOVEMENT_035F_PRECONDITIONS.md).
**OBSERVADO no registro:** replay com 13 dwords/52 bytes do frame natural, alterando x/y;
conteúdo de movimento no trap pré-store, sem retorno, exceção reportada ou envio/resposta
observados durante a chamada; cliente congelou. **REFUTADO no recorte:** discrepância de
8 bytes como explicação exclusiva da falha. **HIPÓTESE:** reentrância em `poll/select` ou
outra dependência de contexto/estado. Trap de execução não prova escrita concluída;
ausência de exceção reportada não exclui toda falha fora da cobertura. H2/H3 não isoladas.
A publicação não executou a sonda. Arquivo-fonte incluído no commit `7a64581`.

## M-10 — dependência de fase (rodadas 04/05), âncora `read` do wineserver

**Origem:** HANDOFFs MOVER-20261015-04 e -05 (`research/movement_035f/HANDOFF.md`);
[pré-condições §13.9](MOVEMENT_035F_PRECONDITIONS.md). **Correção associada (§13.8):** o `035F` é
cifrado e o `store_035f` em `gepard+0x18eff2` é o byte-store do scrambler
(`relay_capture.conf:99-111`); leituras de `035F` como "texto claro" estão REFUTADAS.
**OBSERVADO:** cliente Wine, main thread drena o wineserver por `read`/`writev` (poll quase ausente
na main); âncora corrigida para `read` onLeave. Rodada 04 (delay 700 ms) **retornou** e o scrambler
cifrou o corpo injetado, mas o cliente **congelou após o retorno**, sem `sendmsg`/`recv_0087`.
Rodada 05 (delay 2 s) **abortou durante a chamada** (SIGABRT, `pc=vdso`), também após cifrar o corpo.
Dependência de fase/contexto = OBSERVADA; manifestações distintas (freeze × abort). **HIPÓTESE
LÍDER (não provada):** reentrância Wine. **Artefatos privados (caminhos, não conteúdo; não
versionados):** rodada 04 `/tmp/claude-035f-20261015-160152-read-anchor/` (trial.json + manifesto
de 3 sondas); rodada 05 diretório `…-resume04/` na mesma convenção `/tmp/claude-035f-*`.
**Limite:** disparo no `onLeave` de um `read` é contexto não-natural; mecanismo do crash não
demonstrado; `sendmsg` lado-UNIX da fronteira Wine não observável por hook de export libc.

## M-11 — rodada 06b: origem autônoma ponta-a-ponta (MARCO, cliente vivo)

**Origem:** HANDOFF MOVER-20261015-06 (`research/movement_035f/HANDOFF.md`);
[pré-condições §13.10](MOVEMENT_035F_PRECONDITIONS.md). Sonda `dispatcher_trial_pesite.py`
(`--fire-site 0x4dcba0 --construct-frame --dest-x 273 --dest-y 313 --delay-ms 700`). PID 3338296,
build MATCH por hash. **OBSERVADO (uma única vez):** dispatcher 0x11 disparado de um sítio de
main-loop do `uaRO.exe` (HW exec BP `0x4dcba0`, base `0x400000`), fora do contexto do `read` do
wineserver → `emit_call` dest `[273,313]` → `sendmsg` fd195 5 B during_call → `emit_return`
retval=215959 (sem exceção) → `recv_0087` src `[273,314]` dst `[273,313]` (= destino injetado) →
cliente state S, vivo/estável. **4 critérios:** retorno/envio/resposta dst=destino/responsivo = SIM
→ PASSOU. **Diagnóstico da 06 (não disparou):** bug de guard (`capFrame` null de propósito em
`--construct-frame`); corrigido — não era slot/threading de HW BP. **Artefato privado (caminho, não
conteúdo; não versionado):** `/tmp/claude-035f-20261015-170143-round06b/trial.json`.
**Limite:** disparo via callback de HW-BP é contexto não-natural; sustenta que o contexto
read/wineserver causava os crashes 04/05, **não** "reentrância resolvida em geral". Os 4 HW BP foram
desarmados em `doFire`, então o `store_035f` do scrambler **não** foi observado during_call;
origem+cifra+envio provados **funcionalmente** por `sendmsg` 5 B + `recv_0087` dst=injetado.
**Não reproduzida**; comparação com a via de relay (merge pré-XOR em `gepard+0x18eff2`) pendente.

## M-12 — rodada 09: PoC do relay, `035F` do OpenKore → dispatcher nativo (OBSERVADO live, cliente vivo)

**Origem:** sessão OrquestradorCLAUDE, 2026-10-16; plano
`/home/bazzite/.claude/plans/abundant-frolicking-aho.md`. Integração da primitiva de M-11/§13.10 ao
relay/agent de produção, dirigida pelo OpenKore. **Build MATCH por hash:** `uaRO.exe` `f2f2…9569`,
`gepard.dll` base `0x76920000`. PID cliente 3520569 porta 27053 (Wine); OpenKore XKore 1 porta 2350
em container podman. Servidor **próprio do responsável** (escopo autorizado). **Mudanças em working
tree, não commitadas** no registro.
**OBSERVADO (uma única vez, live):** `035F` do consumidor (XKore `S`) decodificado
(`relay/packets.py:119` `unpack_move`), roteado em `relay/writeback.py:243` para o dispatcher nativo
`0xd473b0` (fire-site `0x4dcba0`, `agent/relay_hook_linux.js:647-752` `MD_RECIPES['walk-035f']`), com
o `035F` original **dropado** (`:249`, nada reenviado) → cliente monta/cifra o próprio `035F` →
`recv_0087 dst = destino pedido` → **cliente VIVO**. Os 4 critérios de M-11 = SIM.
**Orçamento de DR (4/4):** DR0 scramble · DR1 SendPacket · DR2 captura passiva do `this` · DR3
fire-site. `send-watch` OFF obrigatório. **Gotcha corrigido:** `move_dispatch` soma ao `inject-call`
(`relay/writeback.py:101-107`); eram exclusivos no `_arm` original → sem `--inject-call` o relay
dropava todo pacote não-`035F` e o OpenKore travava em "Aguardando".
**Invocação (rodada manualmente pelo responsável; classificador de auto-mode bloqueia o assistente):**
`./run.sh --inject --inject-call --move-dispatch --no-send-watch --out <ARQUIVO>`.
**Verificações offline:** `bash scripts/test-offline.sh` ALL PASS (11 scripts); `node --check
agent/relay_hook_linux.js` PASS; `python3 scripts/validate-research.py` PASS; `py_compile` dos `.py`
alterados OK. **Limites:** OBSERVADO uma vez; não reproduzido em várias sessões; `this` recapturado a
cada sessão (relogin invalida PID/base/heap); a cifra **não** é compreendida (o relay só decide o
destino; geração de keystream anterior ao XOR segue DESCONHECIDA, §13.8). Comparação de custo/robustez
com a via de relay (merge pré-XOR em `gepard+0x18eff2`) pendente. [Pré-condições §13.11](MOVEMENT_035F_PRECONDITIONS.md).

## C-08 — integração CIFRA-20261016-POP-03

**Origem:** [HANDOFF CIFRA](../research/cipher/HANDOFF.md), POP-03;
`/tmp/ro-cipher-20261016T061947Z/pop-click-1/capture/chain-capture.json`,
`DONE.cl_producer/cl_origin/cl_preceding_write`. **OBSERVADO NO ARTEFATO:** cópia
POP antes/depois, ESP+4, EDX estável e associação até pós-store de CL na mesma
ocorrência; recálculo local `POP_COPY_CONFIRMED`, `linked_to_cl_load=true`.
15 traps/uma escrita/13 pontos, 43 ms totais/12 ms sequência. Não é uma coleta
independente; nenhuma captura privada foi publicada. `SCRIPT_ERROR` posterior ao
DONE registrado e perguntado ao autor; contadores limpos não significam ausência
global de erros. Limpeza própria em `stimulus-summary.json` (dois flags verdadeiros),
sem prova de saúde global. [Integração completa](CIPHER_INVESTIGATION.md#integração-documental--cifra-20261016-pop-03).
C-07 conserva a etapa de candidato; C-08 demonstra a cópia apenas na nova ocorrência.
Origem anterior, cifra/estado/pacote permanecem desconhecidos.

## M-13 — MOVER-20261016-08: reprodução da sonda 06b

**Fontes:** [HANDOFF MOVER](../research/movement_035f/HANDOFF.md), IDs06/08;
`/tmp/claude-035f-20261015-170143-round06b/trial.json` e
`/tmp/claude-035f-20261016-014857-repro06b/trial.json`, `DONE.events` e flags
externos de limpeza. Conferidos dois pares chamada/retorno e envio 5/5 bytes,
resposta com destino correspondente; zero stores observados durante a chamada.
**OBSERVADO NO ARTEFATO**, não nova execução pelo documentador. UI responsiva é relato
MOVER; mecanismos da cifra e reentrância não demonstrados. Atualiza o estado “não
reproduzida” de M-11; não reproduz automaticamente a integração relay M-12.
[Limites e lições](RESEARCH_STATUS.md#m-13--reprodução-08-e-lições-do-contexto-de-disparo).

## Limites de procedência que mudam decisões

1. **MOVER-01/02, §13.7:** o autor confirmou que nenhum evento identifica o byte
   verificado ou a colisão; alerta/encerramento são relato. A indetectabilidade geral
   de Stalker/HW BP não foi demonstrada por esses recortes. Pergunta de evidência
   encaminhada ao pesquisador via orquestrador; não autoriza nova instrumentação.
2. **§13.8 / ORCH-20261016-01a:** os trechos citados documentam o caminho de merge e
   uma implementação; não medem operandos XOR do cliente ou gerador criptográfico.
   Solicitados artefato/eventos do PoC e evidência da operação, sem rebaixar o relato
   funcional nem promovê-lo a prova independente.
3. **WRITER-02 / POP-03:** erro tardio após DONE comunicado a CIFRA. Cópias e XOR
   local conferidos são preservados com cobertura; causa/impacto tardio e saúde global
   não preenchidos por inferência. Próxima entrega do autor poderá resolver a lacuna.

## C-09 — informação confirmada: valores enviados ao cliente no login

**Fonte:** declaração direta do responsável nesta rodada, 2026-10-16; no login
valores relacionados à cifra são enviados ao cliente. **Confirmação informada**, sem
captura/reprodução independente pelo documentador. Não identifica automaticamente
seed, chave completa, pacote, estado ou derivação. [Registro e limites](CIPHER_INVESTIGATION.md#valores-de-cifra-recebidos-no-login--confirmação-do-responsável).

## C-10 — CIFRA STACK-04 … SLICE-12 (linhagem por transportes)

**Fonte:** [HANDOFF CIFRA](../research/cipher/HANDOFF.md), IDs STACK-04 a SLICE-12; raiz privada
`/tmp/ro-cipher-resume-20261016/` (`prefix-manual-1`, `earlier-pop-manual-256`,
`earlier-prefix-sixth-manual-1`, `repeat-prefix-manual-1`, `lineage-passive-and-1`,
`upstream-eax-manual-1`, `session2-upstream-prefix-manual-1`, `session4-slice-late4-1`).
**OBSERVADO por ocorrência:** trocas PUSH/POP `+0x1C70D6`, `+0x13A194..A`, `+0x256883..9`;
igualdade do byte através das escritas cobertas até CL. **HIPÓTESE:** plano até `EBP+0x09`.
SLICE-11 inválida (exclusividade perdida). Relato do autor, não reexecutado pelo documentador.
[Integração](CIPHER_INVESTIGATION.md#integração-documental--cifra-stack-04--slice-12).

## A-01 — ACT-20261016-01: dispatcher × ataque/perícia

**Fonte:** `research/action_0437_0438/STATE.md`, `HANDOFF.md`; artefatos privados
`/tmp/claude-act-20261016-031147-sendpkt/observe.json`,
`/tmp/claude-act-20261016-110249-soulstrike2/inject.json`. **OBSERVADO:** codes `0x11/0x1f/0x28/0x2a/0x0a`
→ `035F/0437/0437/0438/(0368)`; cadeia de cast `0x29→0x5a→0x2a`; caller imediato `gepard+0xb2c251`.
**OBSERVADO (injeção):** replay da cadeia pelo fire-site `0x4dcba0` → `0x2a`=0, sem egress, crash
deferido. **REFUTADO:** `0368` pré-select como bloqueio. **RETIRADO:** cadeias de caller por
Backtracer/EBP-walk. [Controle](GEPARD_CONTROL_PACKETS.md#mapa-dispatcher--pacote-de-ação-act-20261016-01).
Supera a leitura da rodada 09b citada em M-12.

## A-02/A-03 — fechamento de movimento e ações (2026-10-17)

**CONFIRMADO PELO RESPONSÁVEL:** `0x035F` (movimento), `0x0437` (ataque automático), `0x0438` (skill automática em alvo) e `0x0AF4` (skill automática no chão) funcionam no ambiente pesquisado. Trilhas MOVER e ACT encerradas; cifra permanece a única pesquisa aberta. Registro novo por declaração do responsável, **não por coleta repetida nesta auditoria**.

**OBSERVADO NO CÓDIGO:** `agent/relay_hook_linux.js:481-534` demonstra `_fix0`. `bodyp.writeByteArray(body)` não bastava no primeiro byte quando `bl` já tinha o valor derivado do corpo original: o store `mov [ecx],bl` o sobregravava. No hit seguinte, `c0 ^ orig0 ^ our0` restaura a contribuição do consumidor. Comentário do agente relaciona erro anterior a GID de ataque e nível de skill. Base `main@0bddf0d77a5f81dc92c6fa5f5d6d45f1aa237d95`.

**REFUTADO/SUPERADO como causa do bloqueio automático:** seleção/lock de alvo e diagnóstico de alcance/estado de movimento em ACT-03. **REFUTADO como correção suficiente:** `0368` pré-select, fila FIFO e disparo isolado da perícia pelo fire-site de movimento. Esses últimos continuam resultados negativos válidos **das vias testadas**, não falha das funções finais.

**Fontes:** [estudo de ações](ACTION_0437_0438_INVESTIGATION.md), `research/action_0437_0438/HANDOFF.md` ACT-01/02/03, `research/action_0437_0438/MERGE_SYNTH_STATE.md` (histórico), `research/movement_035f/HANDOFF.md` MOVER-06b/08, [Pré-condições `13](MOVEMENT_035F_PRECONDITIONS.md). **Limite:** sem ensaio live pós-fix pelo documentador; não comprova algoritmo/estado criptográfico nem generaliza a builds distintos.
