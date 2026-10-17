# CIFRA — handoff operacional atual

> Linha de pesquisa **ativa**, não encerrada. Handoff cumulativo original (2026-10-15/16) preservado **integralmente** em [PROJECT_HANDOFFS.md](../../docs/HISTORY/PROJECT_HANDOFFS.md#source-research-cipher-handoff-md). Esta versão curta evita que o histórico de múltiplas rodadas seja confundido com uma tarefa já executada nesta sessão.

## Última fronteira documentada

- Última rodada registrada: **CIFRA-20261016-SLICE-12**, com linhagem/transportes rastreados até candidata `EBP+0x09`; os dados não identificam a operação geradora do keystream.
- `research/cipher/STATE.md` continua sendo o estado de execução, limpeza e próxima dependência; sua informação mais recente prevalece sobre esta sinopse quando houver handoff posterior.
- **OBSERVADO** na implementação, separadamente: o XOR final `gepard+0x18eff2` e o fix de primeiro byte `_fix0` do merge em `agent/relay_hook_linux.js`. **NÃO VERIFICADO:** inicialização, evolução de estado, fronteiras de cifra completas e reconstrução independente.

## Ao entregar nova rodada

Acrescente um bloco com ID, commit/build/sessão sanitizada, método, `arquivo:linha`, resultados OBSERVADO/INFERIDO/HIPÓTESE/NÃO VERIFICADO/REFUTADO, limitações, artefatos privados por caminho, testes, limpeza e pergunta seguinte. O Documentador integra a prova em [CIPHER_INVESTIGATION.md](../../docs/CIPHER_INVESTIGATION.md) e atualiza [RESEARCH_STATUS.md](../../docs/RESEARCH_STATUS.md).

**Não** publique logs crus, credenciais, GIDs ou dados de sessão. Nenhuma instrução arquivada autoriza instrumentação live.
