# Coordenação da pesquisa

Protocolo de trabalho solicitado pelo responsável. Complementa o AGENTS.md da raiz;
não concede autorização para experimentos, commits ou publicação. Cada agente deve
ler este arquivo explicitamente ao receber sua tarefa. Não é carregado automaticamente
como instrução por todos os clientes de IA.

## Papéis e propriedade

| Papel | Responsabilidade | Arquivos de escrita |
|---|---|---|
| Orquestrador | Prioridades, contratos de tarefa, decisões entre trilhas e critérios de aceitação | Este protocolo e instruções específicas, quando necessário |
| MOVER | Diagnóstico e experimentos do movimento; implementar e testar suas sondas | `research/movement_035f/`, `tests/test_movement_preconditions.py` |
| CIFRA | Produtor do byte, transformação, estado e sessão; implementar e testar suas sondas | `research/cipher/`, `tests/test_cipher_research.py` |
| Documentador | Integrar evidências e corrigir contradições, links e estado científico | `docs/`, seguindo suas instruções locais |

Cada pesquisador mantém `STATE.md` e `HANDOFF.md` em seu diretório. São registros
operacionais, não substitutos dos documentos científicos. Documentador é o único
escritor habitual dos documentos compartilhados. Antes da transferência, quem já
estiver editando docs termina ou entrega seu diff: não sobrepor edições em curso.
Ninguém reverte mudanças alheias. Alterar produção, configuração ou outro escopo
exige uma tarefa explícita; não é consequência automática de um experimento.

## Contrato de tarefa

O orquestrador entrega: objetivo único, proprietário, arquivos, evidências iniciais,
teste discriminante, critérios de conclusão e limites. Pesquisador escolhe detalhes
de implementação dentro desse contrato sem pedir aprovação para cada ajuste local.
Só escala decisão de escopo, conflito científico, recurso compartilhado ou bloqueio.

Cada rodada termina com conclusão delimitada ou diagnóstico da lacuna. Após três
rodadas sem evidência nova, o pesquisador propõe mudança de método, não repete o
mesmo teste nem inicia uma expansão indefinida por conta própria.

## Estado curto e retomada

`STATE.md`: alvo de até 600 palavras, atualizado após cada rodada e antes de trocar
de contexto. Deve conter:

- Objetivo ativo e próximo experimento único.
- Última revisão de código executada (commit e hash/diff quando houver mudanças locais).
- Última rodada, resultado, evidência privada referenciada e cobertura.
- Fatos estabelecidos, hipóteses abertas e conclusões retiradas, em itens separados.
- Inventário mínimo de sondas: finalidade e ponto de entrada; sem copiar código.
- Autorizações: ações cobertas, restrições, confirmação de exclusividade e sua validade.
- Limpeza confirmada ou pendente; recursos próprios ainda ativos.
- Testes realizados e bloqueios.

Na retomada: ler instruções aplicáveis, STATE, status/diff dos próprios arquivos e
somente as seções canônicas referenciadas. Abrir funções específicas quando precisar
alterá-las, conferir segurança da execução ou resolver divergência. Não reler todo
o código para recuperar o histórico. Se STATE estiver ausente/desatualizado, fazer
uma reconciliação pontual e marcá-la; não preencher lacunas por memória presumida.
Um hash ou resumo não substitui revisão das mudanças antes de executar uma sonda.

## Entrega ao documentador

`HANDOFF.md`: até 400 palavras por rodada, com ID único, revisão executada, pergunta,
condições, resultado observado, interpretação, rival, cobertura/perdas, evidências
`arquivo:linha` ou caminho privado + evento, testes e limpeza. Não incluir dados crus
ou credenciais. Preservar rodadas anteriores nos documentos/evidências antes de
substituir um handoff ainda não incorporado.

O documentador verifica as afirmações novas contra os trechos citados, classifica
OBSERVADO/INFERIDO/HIPÓTESE/NÃO VERIFICADO/REFUTADO e integra a rodada. Pode ler código
pontualmente para conferir semântica de um observador; não precisa auditar todo o
repositório por entrega. Não transforma relato em prova independente. Se a evidência
estiver inacessível, registra a limitação e devolve uma pergunta específica ao autor.

O documentador devolve ID incorporado, links e no máximo três divergências pendentes.
O orquestrador recebe apenas o resumo de decisão; revisa código só em escalonamento
justificado. Pesquisadores continuam responsáveis pela correção de seus instrumentos.

## Cliente compartilhado

CIFRA e MOVER podem preparar/analisar offline simultaneamente. Só um instrumenta a
mesma instância por vez. Antes da coleta, obter confirmação explícita de liberação,
instância e escopo; ausência de processo/arquivo de lock não é autorização.
Reutilizar autorização vigente para ações cobertas, sem perguntar repetidamente.
Reinício/relogin invalida identidades de runtime e continuidade presumida de sessão.
Liberar a janela comunicando limpeza; nunca remover instrumentação de terceiros.
Não executar sonda viva enquanto houver limpeza própria não confirmada.

## Relatórios e controle de custo

Retorno ao orquestrador: até 200 palavras, seguindo os campos do AGENTS.md da raiz,
mais ID do handoff. Relatar tokens/tempo apenas quando medidos; não inventar economia.
Detalhes ficam nas evidências e documentos, não em mensagens repetidas.
O responsável decide autorizações de ambiente e publicação. Relato de autorização
em outro chat não amplia automaticamente o escopo desta tarefa.
