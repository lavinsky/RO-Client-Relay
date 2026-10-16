# CIFRA — estado operacional

Reconciliação pontual em 2026-10-15; protocolo: `research/COORDINATION.md`.
Este arquivo não substitui os documentos científicos nem uma confirmação de janela.

## Objetivo e próxima rodada

Demonstrar o escritor do byte efetivamente consumido, distinguindo transporte,
transformação e estado. Próximo experimento único: confirmar antes/depois de
`gepard+0x1C70DC pop dword ptr [edx]`, preservando destino EDX e a única dword
de ESP usada como operando; associar à carga `+0x1C7502` e ao store `+0x1C752B`.
Modo `cl-producer` preparado; aguarda estímulo coordenado do responsável.

## Revisão e evidência executada

HEAD na transferência: `435461546a1ef7d3cdcba863ea5bbb0ace81b7dd`;
há alterações locais, sem commit CIFRA. As capturas anteriores não gravaram HEAD
individual: não atribuir retroativamente essa revisão a elas. Identidade exata
executada está em `tools_sha256` e `loaded_script_sha256` de cada captura.
Novas capturas também gravam HEAD/digest do diff dos instrumentos.

Raiz privada: `/tmp/ro-cipher-20261015T174618Z/` (0700/0600).
Última rodada principal: `session2-cl-writer256-round-1/chain-capture.json`,
evento `DONE`: 129 escritas, 142 traps, 13 pontos, 349 ms totais/10 ms de sequência;
sem perdas/erros; último escritor candidato POP, byte associado a CL, mesma
thread/EBP. Script executado SHA-256:
`a208b68623a6e2130e8a1ea682b21a66983a6b0e93386cf732d78505ad38ab5c`.
Último preflight: `session2-cl-producer-preflight/`, timeout 200 ms, sem acertos,
limpeza confirmada; revisões de campos/diagnóstico seguintes só testadas offline.

## Fatos estabelecidos

- Carga em `+0x1C7502` define CL; 13 pontos até pós-store, ECX estável;
  origem `EBP+0x36` nas ocorrências observadas, fora dos mapas de ESP enumerados.
- XOR local em `+0x2689FB` demonstrado por operandos antes/depois; houve 17
  escritas posteriores, sem consumidor associado naquela rodada.
- Teto de 64 cortou a coleta antes do consumidor; ampliação autorizada para uma
  rodada de 256 permitiu identificar a última escrita candidata POP.
- Reinício entre instâncias: nenhuma continuidade de heap/sessão criptográfica.

## Hipóteses e limites

- POP ainda candidato por decode reverso; a prova antes/depois está pendente.
- Operando da pilha ainda sem produtor demonstrado; grafo reverso tem alternativas.
- XOR não identificado como cifra. Direção, pacote, fronteira F, estado,
  inicialização e vetores independentes continuam desconhecidos.
- Observação por thread/um byte não exclui escritores em outras threads.
- Retirada qualquer atribuição automática do XOR observado ao byte final.

## Sondas e autorização

`chain_capture.py`: coleta limitada; `chain_probe.js`: agentes/doubles;
`chain_audit.py`/`analyze.py`: auditoria offline, sem Frida/rede.
`cl-producer` usa capturas explícitas da mesma instância; não depende das âncoras
antigas. Sem ação nativa, reinício, login, mudança de relay ou watchpoint de stack.
Padrão: 10 s de espera, 500 ms de sequência, 64 escritas, 1.000 eventos, 256 KiB.
Ampliação anterior a 256 foi expressamente autorizada para a rodada indicada.
Exclusividade atual liberada por MOVER via confirmação do responsável; válida
para a rodada POP preparada, até liberação/reinício/novo conflito. Não inferir de locks.

## Limpeza, testes e propriedade

Nenhum instrumento próprio ativo; todas as rodadas terminaram com limpeza confirmada.
53 testes próprios PASS; suíte offline PASS (10 scripts); validador documental e
`git diff --check` PASS no checkpoint. Isso não valida execução do POP no cliente.
Docs liberados ao Documentador; snapshot privado `docs-transfer.diff/.json`.
Próximas evidências entram no HANDOFF, sem escrita concorrente em docs.
