# CIFRA — handoff operacional atual


<!-- CIPHER-SPECIALIST-REFERENCES-2026-10-17 -->

## Tarefa prioritária de continuidade — identificação da variante Gepard (2026-10-17)

**Objetivo único:** vincular a família matemática **real** ilustrada por duas variantes atuais de servidores distintos às operações e ao estado do uaRO, antes de tentar implementar a cifra sem cliente. Fonte especializada de **alta confiança**; aplicação exata ao build uaRO ainda **PENDENTE DE IDENTIFICAÇÃO**. [Referências completas A/B e comparação](../../docs/CIPHER_INVESTIGATION.md#cipher-specialist-20261017).

**Próxima etapa offline, não executada:** definir **vetores sintéticos reprodutíveis** A/B para sementes e corpos de tamanhos variados, explicitando máscara `uint32`, truncamentos de posições e o tipo real desconhecido de `unit->pos_*` em B. Não alterar nem normalizar o código transcrito; hash A=`None`, hash B com constante inicial ambígua. Documentar critérios objetivos para diferenciar índices (`pos3` vs `pos2`), somas/subtrações, fonte do termo de comprimento, shift `>>7`/`>>10` e estados antes/depois.

**Ligação com observação viva já disponível:** SLICE-12 acompanhou transportes até candidata `EBP+0x09`, **não** isolou gerador de keystream. Valores da cifra no login foram confirmados pelo responsável, mas os campos/semântica ainda não foram identificados. O estudo seguinte deve distinguir seed de estado derivado, unidades de envio/recepção/sincronização, continuidade de estado e resets. Não transportar heap, endereços ou seeds entre sessões.

**Método descrito pela fonte:** VMProtect; captura por hypervisor de entradas/saídas de rotinas virtualizadas e confronto com templates de `+`, `-`, `*`, `/`, `%` e `^`, ferramenta especializada reportada em ~2 min. Isso sugere identificação orientada à estrutura; **não** representa ferramenta disponível ou testada neste projeto, nem demonstra quais calls no uaRO já correspondem às variantes.

**Entrega ao Documentador:** tabela A/B/uaRO com OBSERVADO, INFERIDO, HIPÓTESE, NÃO VERIFICADO e REFUTADO, vetor/seed sintéticos, build, direção, ID, fronteiras de estado, evidências sanitizadas, controles de falsificação, resultados negativos e pergunta seguinte. `0x8280` permanece dependência de protocolo futuro xKore 0. Sem novas sondas live autorizadas por este handoff.

**Questões pendentes:** seeds por unidade? valores no login? continuidade e reinicialização? hash/autenticação? constantes/variantização do build? reconstrutor de funções completas ou matcher de templates? Falta da struct B/semântica de largura? O histórico de handoff anterior permanece abaixo.
> Linha de pesquisa **ativa**, não encerrada. Handoff cumulativo original (2026-10-15/16) preservado **integralmente** em [PROJECT_HANDOFFS.md](../../docs/HISTORY/PROJECT_HANDOFFS.md#source-research-cipher-handoff-md). Esta versão curta evita que o histórico de múltiplas rodadas seja confundido com uma tarefa já executada nesta sessão.

## Última fronteira documentada

- Última rodada registrada: **CIFRA-20261016-SLICE-12**, com linhagem/transportes rastreados até candidata `EBP+0x09`; os dados não identificam a operação geradora do keystream.
- `research/cipher/STATE.md` continua sendo o estado de execução, limpeza e próxima dependência; sua informação mais recente prevalece sobre esta sinopse quando houver handoff posterior.
- **OBSERVADO** na implementação, separadamente: o XOR final `gepard+0x18eff2` e o fix de primeiro byte `_fix0` do merge em `agent/relay_hook_linux.js`. **NÃO VERIFICADO:** inicialização, evolução de estado, fronteiras de cifra completas e reconstrução independente.

## Ao entregar nova rodada

Acrescente um bloco com ID, commit/build/sessão sanitizada, método, `arquivo:linha`, resultados OBSERVADO/INFERIDO/HIPÓTESE/NÃO VERIFICADO/REFUTADO, limitações, artefatos privados por caminho, testes, limpeza e pergunta seguinte. O Documentador integra a prova em [CIPHER_INVESTIGATION.md](../../docs/CIPHER_INVESTIGATION.md) e atualiza [RESEARCH_STATUS.md](../../docs/RESEARCH_STATUS.md).

**Não** publique logs crus, credenciais, GIDs ou dados de sessão. Nenhuma instrução arquivada autoriza instrumentação live.
