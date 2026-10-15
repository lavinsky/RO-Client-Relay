# Auditoria e mapa de migração documental

Revisão local: **2026-10-15**, `main@87245d6491e6e27534ab6ada0b4d2cfe7225e43d`.
Escopo: consolidação documental e validação offline. Nenhum código funcional,
configuração, dado, fixture ou ferramenta de pesquisa foi alterado.

## 1. Preflight e arquivos protegidos

- `AGENTS.md` e `docs/AGENTS.md` lidos antes de editar; especificação recebida em
  `Texto_20colado.txt` e instruções do pacote consultadas.
- `git status --short`: somente dois arquivos não rastreados preexistentes,
  `docs/AGENTS.md` e `research/movement_035f/dispatcher_trial.py`; nenhum arquivo rastreado
  alterado. Branch `main`; HEAD acima. Nenhum checkout/reset/stash executado.
- ZIP `RO-Client-Relay-documentation-20261015.zip`: CRC íntegro; os dez arquivos listados
  no `MANIFEST.json` conferidos por tamanho e SHA-256. Extração isolada em `/tmp`.
- `validate_overlay.py`: PASS, seis documentos propostos. O pacote é ponto de partida,
  não fonte que prevalece sobre o checkout.
- Simulação `tools/apply_documentation.py <checkout>`: **recusa esperada**, HEAD diferente
  de `bdc2a07d982bdd393a22a0828a28bd0511145797`; nenhum arquivo escrito pelo aplicador.
  Não houve bypass do guard. Documentos novos foram reconciliados manualmente.
- `git diff bdc2a07..HEAD --stat`: dois commits posteriores, três arquivos rastreados
  envolvidos: pré-condições (+172 linhas), observador e teste. Dados recentes foram
  incorporados ao panorama sem sobrescrever o estudo especializado.

| Arquivo preexistente protegido | SHA-256 inicial / observação final |
|---|---|
| `docs/AGENTS.md` | `4d6dff77f05a728d2d6101a9b50df818a6d339ad95086525a6d641d5e196b843` |
| `research/movement_035f/dispatcher_trial.py` | Inicial `4c3b507cd0bbccdefd72d1dd08ab3e6d380a9a819368b521e765e1f0d72a5af6`; intermediário observado `64b04edad9a377256b2b229876341fa0f66ad7bdad01d3deb90c109a95ac025b` — alteração concorrente, não editada/restaurada nesta tarefa |

O arquivo não rastreado `dispatcher_trial.py` mudou durante a execução (mtime local
13:49:08); a origem da alteração não foi determinada. Seu hash voltou a mudar na última conferência, confirmando atividade concorrente. Sua integridade final não pode ser
declarada igual à inicial. Não foi sobrescrito nem incluído no escopo desta consolidação.

Recursos externos/ignorados, logs, snapshots e capturas privadas não foram abertos,
editados ou migrados. Não se afirma auditoria de conteúdo privado indisponível.

## 2. Estrutura final e mapa de migração

| Origem | Destino | Conteúdo / justificativa |
|---|---|---|
| `README.md` | [README da raiz](../README.md), [OPERATIONS.md](OPERATIONS.md), [ARCHITECTURE.md](ARCHITECTURE.md) | Entrada breve; requisitos, setup, faixa Gadget, configuração OpenKore, stdin, INI, precedência e testes nos manuais; módulos e fluxos na arquitetura |
| `ARCHITECTURE.md` (410 linhas) | [HISTORY/ARCHITECTURE_LEGACY.md](HISTORY/ARCHITECTURE_LEGACY.md) | Corpo completo, §§1–13, figuras, tabelas, ABI, endereços, sondas, experiências e limites; cabeçalho qualifica alegações superadas. Raiz virou redirecionamento |
| `gepard_investigation.md` (222 linhas) | [HISTORY/GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md) | Corpo completo com sanitização explícita de conta/endpoints, sem corte de assembly/constantes/candidatos. Raiz virou redirecionamento |
| `research/cipher/README.md` (166 linhas) | [CIPHER_TOOLS.md](CIPHER_TOOLS.md) | Manual integral: formatos, limites, privacidade, CLI, mecanismos de coleta, limpeza, doubles e interpretação. README local virou entrada curta |
| Quatro estudos especializados | Mesmos caminhos em `docs/` | Movimento, pré-condições, cifra e controle permanecem independentes; referências atualizadas, sem condensar experimentos |
| `docs/RESEARCH_DECISIONS.md` | Mesmo caminho | Decisões confirmadas preservadas; nota diferencia observação inicial e resultado posterior |
| `docs/CODEX_WORKFLOW.md` | Mesmo caminho | Instruções operacionais e medição preservadas, sem mudar ferramentas/modelos |
| Pacote inicial (seis documentos) | Índice, estado, evidências, arquitetura, operação, esta auditoria | Base reconciliada com HEAD; texto provisório de migração pendente substituído por resultado local |
| Inventário recursivo e código/testes | [DOCUMENTATION_SOURCES.md](DOCUMENTATION_SOURCES.md) | Fontes Markdown e hashes de origem, famílias de implementação, testes, histórico Git e limites da inspeção |
| `AGENTS.md` | Raiz | Somente referências documentais atualizadas; decisões/restrições intactas |
| `.agents/`, `.codex/`, `.claude/` | Mesmos caminhos | Configuração, skills, agentes e espelhos preservados |

Não há segunda cópia integral dos documentos migrados na raiz. `HISTORY/` guarda somente
as duas fontes mistas cuja informação técnica exclusiva precisa permanecer contextualizada.
A arquitetura atual usa links para o histórico, não reproduz todos os seus mapas.

## 3. Auditoria de preservação técnica

Comparação automatizada entre `git show HEAD:<origem>` e o corpo migrado:

- Arquitetura: **410/410 linhas preservadas**, removidos somente espaços finais;
  cabeçalho histórico adicionado. Mesmas sequências de caracteres técnicos e ordem.
- Gepard: **222/222 linhas preservadas** após substituir exclusivamente endpoints,
  usuário e as duas representações do identificador de conta por placeholders.
  Sanitização não altera offsets, portas, IDs de pacote, constantes ou assembly.
- Manual da cifra: **166/166 linhas preservadas**, apenas título atualizado e seção
  de localização adicionada. Comandos continuam relativos à raiz.
- Quatro estudos: nenhum experimento ou tabela removido. Pré-condições recebeu nota
  de precedência e correção do rodapé que ainda dizia 256 B após extensões 1024 B/128 B.
  O trecho inicial continua indicando a cobertura original, sem reescrever o resultado antigo.
- `README.md` antigo: explicações de pipeline/módulos já constam da arquitetura;
  requisitos, comandos e opções estão em operações. Alegação geral sobre ptrace foi
  delimitada ao ambiente histórico. Referências inexistentes §§22–23 foram corrigidas.

Elementos conferidos no histórico preservado incluem:

| Família | Elementos preservados / destino |
|---|---|
| Movimento e memória | Bases `0x400000/0x401000`, `+0x816640`, `+0x875400`, `+0x9463b0`, `+0x18eff2`, pilha/ring, DR0/DR1, thiscall → arquitetura histórica §§2,6,8–10 |
| Contrato natural/nativo | `0xd473b0`, `0xd477bc/0xd477bf`, `+0x10A90`, cinco argumentos, slots 64 bits, `+0x70/+0x500/+0x50c/+0x510/+0x520/+0x534/+0x538`, gate `0x15E` → estudos originais |
| Cifra histórica | `gepard_crypt_unit`, pseudocódigo, constantes, ramp/posições, unidades de sessão e resultados negativos → histórico Gepard §§3–4, qualificado como hipótese para uaRO |
| Cifra recente | `+0x1C752B`, `+0x1B223C/+0x1B2252/+0x1B2255`, `+0x18EFEC..+0x18EFF2`, `ESI/CL/EAX/AL/ECX/EBX/EBP/BL`, `EBP+0xA5`, 26 rodadas e limites → cifra original |
| Controle | `0x8280/0x8285/0x4754/0x5395/0xC392`, tamanhos, nomes 2016 e lacunas → controle original e histórico Gepard |
| Perícia não verificada | Diagrama final, `0x14b`, clusters `+0x930xxx..+0x932xxx`, RVAs e candidatos → histórico Gepard final |
| Negativos | Fila inadequada para `035F`, merge persistente, wrapper não discriminatório, nativo sem store/envio, timeouts de cifra, falhas de instrumentação → históricos e estudos mantidos |

Essas comparações comprovam preservação textual sanitizada; não autenticam novamente as
capturas históricas nem tornam seus diagnósticos fatos do build atual.

## 4. Matriz de contradições e resolução

| Assunto | Afirmação anterior | Evidência / formulação canônica |
|---|---|---|
| Observabilidade da chamada nativa | Sem store/ACK não se podia concluir nada sobre envio | Correto para a sonda inicial; etapa 6.4 usa canais independentes e refuta H1 naquele recorte, sem ausência absoluta de tráfego |
| H2/H3 no pacote | H2 prioritária, H3 viável | `2645fad`/`87245d6`, pré-condições §12: sem argumento de estado e sem ponteiro nas regiões examinadas; H2 por valor global continua aberta; H3 relativamente reforçada, não provada |
| Cobertura §12 | Rodapé dizia apenas 256 B unidirecionais | O próprio corpo relata extensões de 1024 B bidirecionais e 128 B do registro global; rodapé agora distingue fases. TLS/indireções/fora do recorte não excluídos |
| Gate e preparação | Campos escritos antes do receptor seriam sua pré-condição demonstrada | Produtor não demonstra consumidor; gates decidem chamar, não demonstram geração de pacote após chamada |
| `0x8280` | Heartbeat igual ao `0x8285` de 2016 | Apenas tamanho tabelado é observável aqui; papel, direção, handshake e equivalência permanecem hipóteses |
| Cifra e estado | Ramp/word-based/posições e XOR final como modelo resolvido | Cargas/cópias/store comprovados em recortes; falta geração de CL, estado consumido, inicialização e vetor P/C completo. `C_INSUFFICIENT` |
| Falha de perícia / flag | Causa exclusivamente sincronia; flag de conta como diagnóstico | Causas não demonstradas; parser, pré-condições, estado e conectividade continuam alternativas. Histórico explicitamente qualificado |
| Dreno SendPacket | Apenas recv/send, latência ~700 ms | Agente atual também hooka `poll/ppoll/select/pselect/pselect6` (`agent/relay_hook_linux.js:732`); latência atual não medida |
| Identidade XKore | Frame preservaria identificador de conexão | Pipeline usa identidade interna (`relay/protocol.py:124`), frame contém tipo+tamanho+payload (`relay/relay.py:14`) |
| Semântica do writeback | Apenas chamar SendPacket e trocar corpo | `relay/writeback.py:224` também seleciona alvo `0368`, deduplica e ignora IDs; agente descarta casts no intervalo (`:617`) |
| Testes históricos PASS vs NOT RUN | Estudos registram resultados diferentes | São execuções/etapas diferentes, com falha ambiental de socket em uma delas. Não apagar registros nem somar como única rodada; validação desta consolidação abaixo |
| §§22–23 e HANDOFF | Referências antigas pareciam destinos existentes | `05fb8d3` reescreveu histórico e `f98e466` removeu handoff. Registrar proveniência e usar §§3–4 atuais; não restaurar material removido com dados privados |
| Recursos Gepard | Arquitetura antiga dizia fonte versionada | `relay/resources/` é externo/ignorado conforme regras atuais; arquivo histórico mantém frase original sob ressalva |

## 5. Verificações desta consolidação

| Comando / verificação | Resultado | Escopo |
|---|---|---|
| ZIP CRC + tamanho/SHA-256 de `MANIFEST.json` | PASS (10 arquivos) | Integridade do pacote recebido |
| `python3 <pacote>/tools/validate_overlay.py` | PASS | Estrutura dos seis documentos iniciais |
| `python3 <pacote>/tools/apply_documentation.py <checkout>` | RECUSA ESPERADA | HEAD divergente; simulação sem escrita |
| Comparação integral das três fontes migradas | PASS | Corpos, ordem, sanitização e linhas preservadas |
| Hashes dos arquivos preexistentes | PARCIAL / alteração concorrente | `docs/AGENTS.md` igual; `dispatcher_trial.py` mudou externamente e foi deixado intacto |
| `python3 scripts/validate-research.py` | PASS | Marcadores/tamanhos, não comprova hipóteses |
| `python3 scripts/validate-codex.py` | PASS | Estrutura/configuração/espelhos, não runtime |
| `bash scripts/test-offline.sh` no sandbox | FAIL ambiental | PermissionError ao criar socket local em integração; testes anteriores passaram |
| `bash scripts/test-offline.sh` fora do sandbox, autorizado | PASS (10 scripts) | Somente suíte offline e sockets locais; saída em `/tmp/ro-doc-offline-tests.txt` |
| `python3 <pacote>/tools/validate_checkout_links.py <checkout>` | PASS | Caminhos relativos existentes; falso positivo da notação de assembly resolvido com comentário explícito para y |
| `git diff --check` | PASS | Espaços do diff rastreado; novos documentos também conferidos |
| Frida/CEServer/cliente/servidores | NOT RUN | Fora do escopo autorizado desta tarefa |
| Commit/push/PR/reescrita | NENHUM | Não autorizado |

## 6. Limites, delegação e próxima decisão

A centralização e a preservação das fontes documentais presentes estão implementadas.
O inventário [DOCUMENTATION_SOURCES.md](DOCUMENTATION_SOURCES.md) registra os documentos
versionados, fontes de contratos e cronologia examinada. A auditoria de implementação foi
estática e dirigida a afirmações documentais, não uma revisão linha a linha de todo o código
ou de cada versão desde a criação do repositório. Fontes privadas/externas indisponíveis
não foram autenticadas nem copiadas. O relatório DiE de outra branch não foi incorporado.

Dois explorers fizeram leituras independentes de arquitetura/operação e pesquisa recente;
somente o coordenador editou arquivos. Foram úteis para localizar a nuance do frame e a
atualização H2/H3; não houve medição comparativa de tokens/tempo/correção suficiente para
alegar economia. Revisões retornaram referências, sem logs completos. Um verifier final apontou PIDs,
FDs, loopback e caminhos históricos como possíveis metadados sensíveis. São referências
preexistentes necessárias à distinção de sessões, sem dados de conta ou conteúdo bruto;
foram mantidas com nota explícita de procedência histórica. Não indicam cliente vivo agora.
A recomendação de removê-las indiscriminadamente não foi adotada por conflitar com a
preservação de proveniência solicitada. A revisão não identificou credenciais nos trechos
examinados e não repetiu a suíte; os resultados acima foram executados pelo coordenador.

Continuam abertas **questões de pesquisa**, não migrações de conteúdo desta árvore:
consumo de valor global vs. contexto no movimento; produtor de CL e cifra completa;
IDs/transições de sessão e futura integração OpenKore. Novos experimentos vivos exigem
proposta/autorização própria. Próxima decisão humana: revisar o diff documental e decidir
se deseja um commit local; nenhum commit é necessário para usar os documentos no checkout.

## 7. Correções da revisão e sincronização solicitada

**HEAD da revisão:** `524b0f05fa61872e140f98ace9e503d12356641e`, posterior à base da
consolidação inicial acima. O commit concorrente incluiu `dispatcher_trial.py` e o
ensaio §13. O fato de ele estar rastreado agora não é alteração funcional desta revisão.

| Achado | Correção aplicada | Limite mantido |
|---|---|---|
| Panorama/arquitetura/índice ainda paravam em §12 | Incorporado M-08 com origem `524b0f0` e referência ao ensaio §13; índices e precedência atualizados | Store no destino pedido, mas sem retorno normal, transmissão ou resposta confirmados |
| §13 declarava H2/H3 necessárias e negava qualquer efeito de instrumentação | Necessidade individual reclassificada como não demonstrada; retorno/continuação e mecanismo do travamento permanecem hipóteses | Desarmar HW breakpoints exclui somente a explicação exclusivamente por esses breakpoints ativos |
| Throttle descrito como descarte ao exceder `castMs` | Corrigido para intervalo desde último cast **menor** que `castMs` | Descarte sem reenfileirar; comportamento do código, não regra criptográfica |

**Sincronização:** `git pull --ff-only --no-rebase` inicialmente bloqueado pelo sandbox
na escrita de `.git/FETCH_HEAD`; repetido fora do sandbox com autorização e concluído:
**Already up to date**. Branch `main` sincronizada com `origin/main`, sem rebase, descarte
de alterações ou mescla de branches de pesquisa. Alterações documentais locais preservadas.
Nenhum commit ou push foi criado por esta tarefa.

Os resultados da seção 5 pertencem à primeira consolidação. As verificações da correção
são registradas abaixo após execução; nenhum experimento vivo foi reexecutado.

| Verificação após as correções | Resultado |
|---|---|
| `python3 scripts/validate-research.py` | PASS — marcadores/tamanhos |
| `python3 scripts/validate-codex.py` | PASS — estrutura/espelhos |
| `python3 <pacote>/tools/validate_checkout_links.py <checkout>` | PASS — caminhos relativos |
| `git diff --check` + espaços dos novos documentos | PASS |
| `bash scripts/test-offline.sh` fora do sandbox, autorizado | PASS — 10 scripts; `/tmp/ro-doc-offline-tests.txt` |
| Inspeção das correções, tokens técnicos e ausência de diff funcional | PASS — três achados resolvidos |
| `git rev-list --left-right --count HEAD...origin/main` | PASS — `0 0` após pull |
| Experimentos vivos | NOT RUN |

**Resultado da revisão:** aprovada documentalmente após corrigir os três achados, dentro
do escopo estático e offline descrito. As hipóteses de pesquisa não se tornam fatos pela
aprovação. Mudanças continuam locais, sem commit/push desta tarefa. Próxima decisão:
versionar a consolidação quando houver autorização explícita para commit.

## 8. Exclusão de branches e integração da main solicitadas pelo responsável

As seis branches remotas explicitamente dispensadas foram excluídas em uma operação
atômica com conferência dos SHAs (`--force-with-lease` por ref). A consulta à API do
GitHub confirmou que somente `main` permanece. Branches locais não foram excluídas.

Antes do pull, os 20 arquivos locais alterados foram copiados para
`/tmp/ro-before-branch-cleanup-yjjwo1g7/` e guardados no stash
`preserve-local-docs-before-requested-pull-20261015`. O backup e o stash foram mantidos.
O pull por merge preservou `888764a` e integrou `origin/main@0a29193`, criando o commit
local de merge `677e51e`. Nenhum commit local foi publicado na main.

A reaplicação da documentação gerou conflito apenas em `ARCHITECTURE.md`: o remoto
acrescentava o resultado DiE ao documento antigo; o local mantinha uma entrada para a
arquitetura centralizada. A resolução conserva a entrada na raiz e integra a adição
à **§12 de `docs/ARCHITECTURE.md`**, com link ao relatório completo. Não se restaurou a
antiga organização. As adições remotas em cifra, pré-condições e decisões foram mantidas.

O panorama/índice local também refletem a correção já feita em `888764a`: trap pré-store
não prova escrita concluída; ABI da chamada de 44 bytes difere de `ret 0x34` (52 bytes).
O relatório DiE agora existe nesta árvore; menções anteriores à sua indisponibilidade
nesta auditoria descrevem a fase anterior ao pull e ficam superadas por esta integração.
Nenhum cliente, Frida, CEServer ou experimento de servidor foi executado nesta tarefa.

## 9. Preparação da publicação autorizada

O responsável autorizou publicar todas as alterações no GitHub. Além da consolidação,
o conjunto inclui o script preexistente `research/movement_035f/dispatcher_trial13.py`,
que captura 13 dwords para ensaio nativo experimental. Publicação do código não autoriza
executá-lo: esta tarefa não fez coleta viva. O script usa verificações de instruções/objeto,
sem conferir automaticamente os hashes dos módulos; sua configuração depende da build
já identificada. Os resultados vivos permanecem no estudo especializado e não são validados
pela suíte offline.

Verificações antes da publicação: suíte offline completa **PASS (10 scripts)**, sintaxe
Python por AST/compile **PASS**, JavaScript embutido por `node --check` **PASS**, validadores
de pesquisa/Codex **PASS**, caminhos Markdown e `git diff --check` **PASS**. A inspeção
estática não identificou credenciais nem capturas cruas nos arquivos novos; offsets e
hashes de build foram mantidos como proveniência. Artefatos ignorados e backups em `/tmp`
ficam fora do commit. O stash de segurança continua preservado.

Durante a preparação, outra sessão concluiu e commitou `7a64581` (script ABI13 e §13.5).
O panorama e o índice incorporam esse resultado: a variante de 52 bytes também travou,
sem retorno/envio observado. A publicação preserva esse commit, sem reproduzir a coleta.
Removida apenas uma linha vazia redundante no EOF do histórico Gepard para atender
`git diff --cached --check`; nenhum dado técnico foi removido.
