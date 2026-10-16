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
