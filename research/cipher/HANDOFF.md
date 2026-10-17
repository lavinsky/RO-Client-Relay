# CIFRA — handoff operacional atual

## GEPARD-SESSION-20261017-01 — inventário de login e mapa

**Pergunta/mandato:** pedido direto do responsável nesta conversa para observar
login até dez segundos no mapa, investigar desconhecidos e documentar controles.
Revisão `d3baabe` mais instrumentos locais; hashes de uaRO/Gepard e evidências
integrados em [GEPARD_CONTROL_PACKETS](../../docs/GEPARD_CONTROL_PACKETS.md).

**Resultado:** A/B/D totalizam 314 mensagens, 69 pares direção/ID, 65 mapeados ao
parser e quatro controles. A cumpre login/10 s com ações; D cumpre 10 s sem ações.
B saiu do mapa em 3,078 s e não valida estadia contínua; C expirou antes de nova
entrada e foi excluída. Não há bytes pendentes, comprimento desconhecido ou lacuna
de sequência nos recortes registrados. Cobertura dos hooks não equivale a PCAP.

**Níveis:** OBSERVADO `4754` R/40, `C392` S/72 pareados no login/mapa; negociação/ACK
INFERIDOS. `5395` R/12 tem 1/1 compatível com LGP histórico; R/16 tem código 4 e dois
campos variáveis: @12 acompanha milissegundos em seis amostras (até 10 ms de erro
adjacente em 2.451.850 ms); relógio INFERIDO, origem/eco não verificados. @8 permanece
sem significado identificado. `8280` S/128 ocorre também sem
ações no recorte. Conteúdo criptográfico e associação de campos a seeds permanecem
NÃO VERIFICADOS. 72 hipóteses de decifragem literal A/B/2016 foram negativas somente
para constantes, offsets, fronteira e estado assumidos; não refutam a família.

**Rival/discriminador:** @8 do tipo 4 pode ser nonce/checksum/configuração em vez
de seed; localizar consumidor, separando-o do relógio candidato @12. Não promover nomes e
offsets 2016 ao uaRO. Referências de código e catálogo completo estão no documento;
`catalog.json`, sequências e scripts privados em `/tmp/gepard-session-20261017/`.

**Limpeza:** unload/detach confirmados nas quatro tentativas, nenhum HW BP/input;
nenhum coletor desta rodada mantido ativo. Repetição manual pendente após timeout.
**Testes focados:** `tests/test_session_packets.py` PASS; `tests/test_packet_semantics.py`
PASS (8 testes). **Verificações finais:** `bash scripts/test-offline.sh` PASS (14 scripts);
`python3 scripts/validate-research.py` PASS; `python3 scripts/validate-codex.py` PASS;
`git diff --check` PASS.
Sem commit, push ou alteração em produção/configuração nesta tarefa.


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
