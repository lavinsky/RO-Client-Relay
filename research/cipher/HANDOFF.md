# CIFRA — entregas ao Documentador

Protocolo: `research/COORDINATION.md`. Sem capturas cruas ou estado criptográfico.

## CIFRA-20261015-CL-01 — origem de CL

Pergunta: última definição executada de CL antes de `+0x1C752B`.
Revisão: alterações locais; hashes de instrumentos/script em cada artefato,
HEAD individual não registrado. Build: hashes canônicos uaRO/gepard revalidados.
Condição: janela exclusiva, movimentos naturais, breakpoint rotativo.
**OBSERVADO:** `+0x1C7502 mov ecx,[ecx]`, ECX estável até pós-store; dword anterior
coincide com ECX e byte escrito com CL; 13 pontos/9 ms, sem perdas/erros.
Origem `EBP+0x36`. Reinício posterior exigiu nova instância e captura independente.
Evidências: raiz privada `/tmp/ro-cipher-20261015T174618Z/`,
`cl-round-1/chain-capture.json:DONE.cl_origin` e
`session2-cl-round-1/chain-capture.json:DONE.cl_origin`.
Limite: cópia demonstrada, sem cifra/estado/pacote. Limpeza confirmada.

## CIFRA-20261015-WRITER-02 — XOR e último escritor candidato

Pergunta: quem escreve o operando de CL antes da carga?
Revisão exata: `tools_sha256`/`loaded_script_sha256` nos artefatos; HEAD de
transferência `435461546a1ef7d3cdcba863ea5bbb0ace81b7dd`, sem commit CIFRA.
Mesma build, nova instância exclusiva; não unir estados entre instâncias.

**OBSERVADO:** `session2-cl-transform-round-1/chain-capture.json:DONE.cl_transformation`
na raiz acima demonstrou `+0x2689FB xor dword ptr [ecx],edx` antes/depois, operando
em EBP+0x36, contexto preservado e igualdade XOR não trivial. Depois houve 17
escritas; 36 traps/33 escritas totais, sem carga consumidora retida. A coleta parou
em candidata ADD; nenhuma atribuição desse XOR ao byte final é permitida.

`session2-cl-writer-round-1/:DONE` atingiu 64 escritas antes do consumidor, invalidando
a completude. Após autorização explícita para 256,
`session2-cl-writer256-round-1/chain-capture.json:DONE` registrou 129 escritas,
142 traps, 13 pontos/10 ms, 349 ms totais, zero perdas/erros e 72.449 bytes.
**OBSERVADO:** byte da última escrita = byte carregado/armazenado por CL, mesma
thread/EBP. **INFERIDO:** única candidata reversa `+0x1C70DC pop dword ptr [edx]`.
Rival/limite: decode não prova POP; origem do valor na pilha e papel criptográfico
desconhecidos; observador de um byte/uma thread não exclui outras threads.

Próximo: `cl-producer`, antes/depois POP + carga/CL/store, somente uma dword da
pilha, sem watchpoint de stack. Preflight 200 ms armou/desarmou sem acertos;
grafo reverso contém alternativas, sem caminho inferido. MOVER liberou via responsável.
53 testes offline PASS, suíte 10 scripts PASS, validador documental/diff PASS.
Nenhum recurso próprio ativo; todas as limpezas confirmadas. Cifra segue sem vetor.

## Transferência de docs — liberada

Documentador pode assumir imediatamente `docs/CIPHER_INVESTIGATION.md`,
`docs/CIPHER_TOOLS.md`, `docs/RESEARCH_STATUS.md`, `docs/RESEARCH_EVIDENCE_INDEX.md`.
Esses diffs estão completos até WRITER-02 e não estão mais em edição por CIFRA.
Snapshot privado: `docs-transfer.diff` e `docs-transfer.json` na raiz acima.
Interfaces novas: `cl-origin`, `cl-writer`, `cl-transform`, `cl-producer`,
`--cl-code-input`, `--cl-source-capture`, `--cl-writer-capture`, `--cl-write-cap`.
Material posterior será entregue abaixo com outro ID, sem sobrepor docs.

## CIFRA-20261016-POP-03 — POP associado ao consumidor na mesma ocorrência

Pergunta: confirmar o POP candidato e seu consumidor, sem reutilizar heap antigo.
Revisão: HEAD/digest do diff em `repository_revision`, hashes de fonte/script nos
artefatos; preparação a partir de `6c20733ef0af42d8a618bba39a16322f316207db`.
Raiz privada nova: `/tmp/ro-cipher-20261016T061947Z/` (0700/0600).

Condição: nova instância, mesmos hashes de build, exclusividade atual confirmada
pelo responsável via orquestrador. DR0–3 livres por leitura ptrace sem escrita
(0,056 ms, detach confirmado), zero conexões Gadget anteriores. Essa leitura não
inspeciona handlers; sua propriedade é confirmação cooperativa, não introspecção.
Preflight 200 ms e passiva 10 s sem hits, limpos. Não repetir ocioso.

`--cl-relocate-source` usa histórico só para código/RVA/offset; EDX e mapeamento
são resolvidos no hit atual, EDX=EBP+0x36, fora dos mapas de ESP enumerados. Nenhum
estado/endereço antigo foi usado como entrada atual. Um clique uinput em chão
visualmente verificado na captura exclusiva da janela, com PID/vida/geometria/foco
conferidos. Não confundir pixels com tile ou esse estímulo com identidade de pacote.

**OBSERVADO:** `pop-click-1/capture/chain-capture.json:DONE.cl_producer` mostra
`+0x1C70DC pop dword ptr [edx]` antes/depois: uma dword de ESP coincide com destino,
EDX estável, ESP+4, thread/EBP preservados. `DONE.cl_origin` confirma os 13 pontos
até pós-store. `audit_chain` retorna `POP_COPY_CONFIRMED` e `linked_to_cl_load=true`.
Cobertura: 15 traps, uma escrita, 43 ms totais/12 ms sequência, zero perdas/erros;
14.946 bytes. Watchpoint cobre um byte/uma thread, sem excluir outras threads.

Rival/limite: cópia de valor já existente; não identifica cifra/estado/pacote,
direção ou origem anterior do operando. Grafo reverso contém candidata de dois
PUSH/dois POP; precisa prova executada. Próximo recorte: quatro instruções/8 bytes,
preservando endereços/valores de memória e ESP, sem watchpoint de stack.

Limpeza: `stimulus-summary.json` confirma sonda e daemon/socket próprios liberados;
nenhuma chamada nativa ou hook inline, nenhuma interferência em terceiros.
Testes: 55 próprios PASS antes da rodada; revisão final e validadores ainda serão
reexecutados. Docs continuam sob propriedade do Documentador.

## CIFRA-20261016-STACK-04 — transporte executado com operandos coincidentes

Pergunta: os dois PUSH/dois POP candidatos fornecem o operando consumido por CL?
Origem: nova coleta nesta conversa, exclusividade e escopo confirmados diretamente
pelo usuário; clique manual solicitado após ARMED. Novo runtime; hashes dos dois
módulos conferidos contra referência, sem reutilizar estado/heap histórico.
Revisão: HEAD 6c20733ef0af42d8a618bba39a16322f316207db com diffs locais;
`repository_revision`, `tools_sha256`, `loaded_script_sha256` identificam execução.
Evidência privada: `/tmp/ro-cipher-resume-20261016/prefix-manual-1/chain-capture.json`
(`DONE.cl_stack_source`, `DONE.cl_producer`, `DONE.cl_origin`) e `audit.json`.

**OBSERVADO:** cinco pontos provam `+1c70d6 push [esi]; push [edx]; pop [esi];
pop [edx]`; sete relações de operandos/ESP confirmadas. ESI==EDX, sobreposição
integral: o valor retorna ao mesmo endereço. POP ligado à carga e pós-store CL.
18 traps, duas escritas, 13 pontos CL, sequência 22 ms, espera total 6086 ms,
20.029 bytes; zero erros de leitura/discontinuidades registrados, sem teto.
**INFERIDO:** transporte redundante nesta ocorrência; nenhuma transformação
criptográfica demonstrada. Rival: outras ocorrências podem ter operandos distintos;
origem anterior do valor e escritores de outras threads permanecem desconhecidos.

Saúde: um `SCRIPT_ERROR TypeError: not a function` posterior a DONE, sem linha/stack;
exit 1 e `runtime_health=UNVERIFIED`, preservados. Não atribuir causa nem declarar
rodada globalmente limpa. RPC desarme, unload/detach confirmados pelo coletor;
nenhum daemon/socket/input próprio criado. Não houve segunda tentativa.
Verificações: `python3 tests/test_cipher_research.py` PASS (58);
`python3 scripts/validate-research.py`, `python3 scripts/validate-codex.py` e
`git diff --check -- research/cipher/STATE.md research/cipher/HANDOFF.md` PASS.
Próximo: diagnóstico offline do erro
e candidato anterior ao primeiro PUSH. Sem commit; docs pertencem ao Documentador.

## CIFRA-20261016-EARLIER-05 — POP anterior e cobertura até CL

Mandato: usuário autorizou continuidade autônoma nesta conversa, perguntando apenas
prontidão para input. Exclusividade CIFRA mantida; sem publicação/commit.
Pergunta: candidato `+0x13A19A pop [ebx]`, historicamente última mudança do byte,
fornece o valor consumido? Revisão efetiva e hashes nos respectivos artefatos.
Raiz privada `/tmp/ro-cipher-resume-20261016/`:
`earlier-pop-code/chain-capture.json` é somente código; `earlier-pop-manual-1/`
atingiu 64 escritas sem consumidor, cobertura incompleta. `earlier-pop-manual-256/`
chegou a CL: 146 traps, 130 escritas, 186 ms, 13 pontos CL, sem teto nem erros de
leitura/discontinuidades registrados. POP antes/depois confirmado localmente, mas
129 escritas intermediárias impedem atribuição do primeiro POP ao consumidor.
Mesmo código apareceu seis vezes na lista desta ocorrência. Não tornar essa
contagem uma regra. Capturas por thread/um byte não excluem outras threads.

Erro posterior a DONE persiste com handler callable em vez de null; mitigação
REFUTADA nesta tentativa. `javascript_stack` não forneceu linha útil.
`cleanup-auto-stop-preflight/` também registrou hits, sem estímulo automatizado:
atingiu teto 64; não chamá-lo de prova ociosa nem de movimento. Evitar RPC stop
redundante não suprimiu TypeError (fase script_unload). Não atribuir causa ao
cliente ou à proteção. Saúde global UNVERIFIED; limpeza do coletor confirmada.
Testes 60 próprios PASS; novos validadores ainda serão registrados ao fechar a
preparação. Nenhum input sintético/daemon próprio, nenhuma alteração em produção.

## CIFRA-20261016-SOURCE-06 — troca de operandos distintos

Pergunta: preservar origem de memória dos PUSH/POP em +0x13A194–+0x13A19A.
Seleção experimental: sexto hit compatível do primeiro PUSH, não sexto POP;
essa diferença ficou explícita pelo número de escritas intermediárias.
Evidência: `earlier-prefix-sixth-manual-1/chain-capture.json:DONE` e `audit.json`
na raiz privada acima; revisão/diff/hashes anexados pelo driver.
**OBSERVADO:** cinco pontos, sete relações verdadeiras, operandos distintos e sem
sobreposição; fonte EBP+0x68, destino EBP+0x36, fonte em mapa sem arquivo.
Cópia da dword para destino via pilha comprovada; consumidor CL observado depois,
mas 102 escritas impedem ligação causal automática ao byte final.
143 traps, 19 hits ignorados, sequência 165 ms, 13 pontos CL, sem perdas/erros de
leitura/discontinuidades registrados. Uma dword da pilha por operando delimitado;
nenhum watchpoint de stack. SCRIPT_ERROR depois de DONE na fase stop_rpc; sem
stack útil, saúde UNVERIFIED, desarme/unload/detach confirmados pelo coletor.

INFERIDO: operador de transporte; papel criptográfico desconhecido. Próximo
método: breakpoint independente para CL e observação repetida dos pares PUSH/POP,
selecionando a última troca pela execução, com no máximo 32 ocorrências e limites
500 ms/256 escritas/1000 traps/256 KiB. Ferramenta com 60 testes PASS, incluindo
registro EBX, prefixo EDI/EBX, seletor limitado e duas ocorrências sintéticas.

## CIFRA-20261016-REPEAT-07 — última troca selecionada pela execução

Raiz privada `/tmp/ro-cipher-resume-20261016/repeat-prefix-manual-1/`;
`chain-capture.json` e `audit.json`, revisão/diff/hashes anexados. Exclusividade e
clique manual confirmado nesta conversa. Três DRs próprios (prefixo, byte destino,
CL independente); até 32 ocorrências, sem watchpoint de stack.
OBSERVADO: cinco trocas EDI/EBX preservadas; a última leu EBP+0x57 e copiou para
EBP+0x36. Todas as escritas cobertas depois dessa cópia preservaram o byte até CL.
151 traps, 102 escritas no destino, 230 ms, 13 pontos CL, sem teto/leitura perdida.
Isso comprova igualdade através da cobertura, não ligação causal ao último escritor
direto nem papel criptográfico. Outras threads/bytes não cobertos.
TypeError posterior a DONE na fase script_unload; saúde UNVERIFIED; limpeza do
coletor confirmada. Não transferir a afirmação de saúde da rodada seguinte.

## CIFRA-20261016-LINEAGE-08 — escritor da fonte da última troca

Pergunta: quem escreve EBP+0x57 antes de sua leitura pelo primeiro PUSH da última
troca? Referência fornece somente offset estrutural; endereço deriva do EBP atual.
Quarto DR próprio observa um byte fora dos mapas ESP enumerados, sem scan/dump.
Revisão efetiva em repository_revision/tools_sha256/loaded_script_sha256.

Raiz privada `/tmp/ro-cipher-resume-20261016/`. `lineage-manual-1/` terminou antes
do aviso de clique: 27 escritas de fonte/25 destino, 81 ms, unattributed_exception,
decode candidato `+0x2c042f and byte ptr [edi], dl`. Nenhum SCRIPT_ERROR,
limpeza confirmada. Não houve clique solicitado nessa rodada.

Após reconhecer AND e antecipar desarme dos watchpoints ao callback adiado,
`lineage-passive-and-1/{chain-capture,audit}.json` registrou seis trocas,
306 traps, 130 escritas destino/120 fonte, 414 ms, 13 pontos CL; nenhum teto,
erro de leitura/discontinuidade ou SCRIPT_ERROR. Desarme/unload/detach confirmados.
Coleta passiva, sem input solicitado/automatizado; mecanismo any-chain não prova
movimento, pacote, direção ou envio. Não afirmar segurança global do cliente.

OBSERVADO: última escrita de fonte antes da leitura tem byte igual ao operando do
primeiro PUSH; sete relações da troca e igualdade através das escritas destino até
CL confirmadas. INFERIDO: decode único `+0x256889 pop dword ptr [eax]` é escritor
candidato. Falta pré/pós executado e origem da pilha; cifra/estado desconhecidos.

Testes 61 próprios PASS, incluindo separação de dois watchpoints, prefixos repetidos,
associação temporal de fonte e desarme antes de callback adiado. Trocar handler
por callable e evitar RPC redundante não suprimiu TypeError; antecipar desarme foi
seguido por uma coleta completa sem erro, mas causalidade permanece NÃO VERIFICADA.
Nenhum recurso próprio ativo, sem commit/produção/docs. Próximo: POP/EAX pré/pós.

## CIFRA-20261016-UPSTREAM-09 — POP/EAX pré/pós

Pergunta: confirmar a candidata da escrita de EBP+0x57 observada por LINEAGE-08.
Referência de seleção: `lineage-passive-and-1/`; fornece RVA e offset estrutural,
sem reutilizar heap/estado antigo. Nova observação local independente, não fundir
com a ocorrência de LINEAGE-08 para alegar associação ponta a ponta.

Raiz privada `/tmp/ro-cipher-resume-20261016/`. `upstream-eax-code/` inspecionou
código sem armar; grafo reverso mostra candidata PUSH/POP e XOR imediato próximo,
sem prova de execução ou relevância criptográfica. `upstream-eax-passive-1/`
encerrou em 10 s sem hit compatível, sem erros e com limpeza confirmada; não
repetido ocioso. Usuário confirmou prontidão; após ARMED foi solicitado clique.

`upstream-eax-manual-1/{chain-capture,audit}.json`: OBSERVADO `+0x256889 pop [eax]`
antes/depois, dword em ESP preservada antes de execução, EAX estável, ESP+4 e
cópia coincidente para EBP+0x57. Quatro traps, dois hits ignorados, uma escrita,
2 ms, sem teto/leitura perdida/SCRIPT_ERROR. Nenhum consumidor CL retido por
desenho (`upstream_pop_observed`); não usar linked_to_cl_load=false como prova
negativa de fluxo nem promover proximidade do XOR a transformação observada.

Revisão/diff/hashes em cada captura; instrumentos atualizados com seleção upstream
baseada em referência auditada e limite de offset. 62 testes próprios PASS;
preflight `upstream-prefix-code/` PASS sem instrumentação. Próximo: quatro
instruções/operandos da troca que precede POP/EAX; preparo validado com registros
EDI/EAX sintéticos e callback adiado. Nenhum instrumento próprio ativo, sem
input sintético, sem commit/docs/produção. Validadores finais pendentes após
novas alterações. Papel criptográfico e inicialização continuam desconhecidos.

## CIFRA-20261016-SWAP-10 — nova instância, origem do POP/EAX

Usuário confirmou prontidão e informou reinício/PID diferente. Runtime descoberto
novamente, inventário `inventory-session2.json` separado do anterior, mapas e hashes
dos dois módulos revalidados. Autorização exclusiva CIFRA continuada pelo usuário;
nenhuma continuidade de heap/estado. Referências anteriores usadas só como código
e offset estrutural; EAX/EDI/endereço vêm dos hits atuais.

Evidência `/tmp/ro-cipher-resume-20261016/session2-upstream-prefix-manual-1/`
(`chain-capture.json:DONE.cl_stack_source`, `DONE.cl_producer`, `audit.json`).
Preflight anterior `session2-upstream-prefix-code/`: código validado sem armar.
OBSERVADO: +0x256883 PUSH [EDI], PUSH [EAX], POP [EDI], POP [EAX], cinco pontos,
sete relações de operandos/ESP verdadeiras; fonte EBP+0x36, destino EBP+0x57,
operandos distintos. POP/EAX e transporte comprovados localmente, não cifra.
Sete traps, uma escrita, dois hits ignorados, sequência 13 ms, sem teto,
erros de leitura/discontinuidades/SCRIPT_ERROR. Desarme/unload/detach confirmados;
nenhum recurso próprio de input. Usuário informou clique: relação temporal com
captura NÃO VERIFICADA; não rotular passiva por ter terminado antes do aviso.

Rival/limite: não provar retorno circular 36→57→36 fundindo capturas ou instâncias.
CL não retido neste recorte. XOR imediato próximo continua mero candidato estático.
Próxima preparação SLICE-11: registrar padrões de troca como candidatos durante
observação dos dois bytes e calcular retrospectivamente plano de até 32 arestas.
`candidate_slice.py` para em decode ambíguo, falta de primeiro POP, fonte não
observada ou byte divergente; sempre HIPÓTESE, sem estado/valores na saída.
63 testes próprios PASS, incluindo casos sintéticos de lacuna/conflito e fonte
anterior ao primeiro POP. validate-research/validate-codex/diff PASS. Sem commit,
sem produção/docs; nenhum instrumento ativo. Aguardando prontidão já perguntada
para coleta dos novos metadados; nenhuma execução SLICE-11 ainda.

## CIFRA-20261016-SLICE-11 — perda de janela exclusiva e limpeza pendente

Pergunta: obter dependências candidatas do byte sob dois watchpoints, prefixo
repetido e CL independente. Usuário disse «Siga adiante»; descoberta identificou
outra instância, inventário privado `inventory-session3.json`, hashes atuais
conferidos, sem reutilizar heap. Propriedade permaneceu research/cipher e teste
próprio, nenhuma produção/docs/configuração/terceiro alterado.

Raiz privada `/tmp/ro-cipher-resume-20261016/`. `session3-slice-manual-1/` parou
em 502 ms, 218 traps, 96 escritas destino/90 fonte, sem CL; TypeError depois de
DONE. `session3-slice-cached-1/` também parou em 502 ms, 221 traps, 97 escritas
 destino/92 fonte, sem CL, sem SCRIPT_ERROR. Desarme/unload/detach confirmados
pelo coletor nessas duas tentativas; cobertura científica incompleta.
O cache reduziu decodes repetidos com validação de oito bytes de código e valores
de registradores atuais; testes de invalidação/fonte dinâmica PASS. Não afirmar
que isso resolveu custo ou saúde no cliente.

Preparou-se gate experimental no quarto hit compatível, preservando timeout e
limites; usuário confirmou prontidão e clique foi solicitado após ARMED.
`session3-slice-late4-1/chain-capture.json` reteve somente READY, nenhum DONE,
cleanup_confirmed=false; revisão/diff/script/hashes preservados. Usuário informou
que o jogo travou e exclusividade foi comprometida por outro agente. Origem é
RELATO DO RESPONSÁVEL; instrumentação concorrente/momento/causa não verificados
independentemente. Nenhuma conclusão sobre cifra ou causa do travamento é válida.
Também não usar tentativas da sessão 3 como reprodução exclusiva sem reconciliar
quando houve a interferência. /proc: líder Z, 36 threads S; não prova término
integral do cliente. Nenhuma leitura ptrace/DR ou ação no instrumento alheio.

Limpeza: SIGTERM enviado somente ao driver próprio com argv/artefato conferidos;
driver e wrapper encerrados, sem SIGKILL necessário. `controller-stop.json`
registra ações. **PENDENTE:** desarme/handler/unload/detach do script CIFRA no
cliente da sessão 3; DRs solicitados 0–3. Interrompidas novas tentativas vivas.
Nova rodada requer resolução desse recurso e janela exclusiva explícita.

63 testes próprios PASS; validate-research, validate-codex e diff-check PASS.
Validação offline não refuta conflito vivo. Sem commit. Após três tentativas sem nova prova completa, próximo é mudar método offline e
reduzir custo/cobertura simultânea, não ampliar limites ou repetir a coleta.

## CIFRA-20261016-SLICE-12 — nova exclusividade e dependência candidata +0x09

Responsável confirmou explicitamente cliente reiniciado e exclusivo, pronto para
input. Descoberta e `inventory-session4.json` identificam runtime novo; dois hashes
revalidados. /proc do alvo anterior ausente: pendência restrita à instância antiga
não se transfere ao novo processo. Nenhum recurso/instrumento de terceiro alterado.
Pergunta: plano retrospectivo do byte com descrições candidatas de trocas,
iniciando no quarto hit compatível para reduzir cobertura simultânea no tempo.
Seletor quatro é experimental, não invariante nem continuidade entre sessões.

Raiz privada `/tmp/ro-cipher-resume-20261016/session4-slice-late4-1/`.
`chain-capture.json:DONE` grava revisão/diff/hashes do instrumento e script;
`audit.json`, `candidate-slice.json`, `analysis-provenance.json` identificam análise.
Input: usuário confirmou prontidão; clique solicitado após ARMED. Relação exata do
estímulo com o hit não medida. OBSERVADO: 73 traps, 20 escritas em +0x36, 14 em
+0x57, duas trocas capturadas, 151 ms de sequência, 13 pontos CL, sem teto,
discontinuidades/erros de leitura/SCRIPT_ERROR. Desarme/unload/detach confirmados.
Cobertura limitada a uma thread/dois bytes a partir do gate; não provar pacote,
direção, envio ou cifra. Byte da última troca preservado nas escritas cobertas.

HIPÓTESE: plano de cinco escritores segue +1C70DC→+28E0A7→+13A19A→+256889→
+256809, chegando a fonte EBP+0x09. Quatro arestas condicionais atravessadas;
última interrompida em FIRST_POP_NOT_OBSERVED porque +0x09 não estava sob watch.
Só o prefixo +13A194..+13A19A tem prova executada dentro desta coleta; demais
padrões e ponteiros pós-store são candidatos. Não converter o plano em cadeia
executada ou fundir com SWAP-10 de outra instância.

63 testes próprios PASS antes da coleta. Nenhum instrumento próprio ativo;
sem input sintético, sem commit/docs/produção. Próxima decisão: observar +0x09
sem exceder quatro DRs e manter ligação ao consumidor, reduzindo escopo simultâneo
se necessário. Verificações documentais serão registradas ao fechar a rodada.
