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
| Inventário recursivo e código/testes | [§10 desta auditoria](#10-inventário-de-fontes-da-consolidação-migrado-de-documentation_sourcesmd) | Fontes Markdown e hashes de origem, famílias de implementação, testes, histórico Git e limites da inspeção. **Migrado de `DOCUMENTATION_SOURCES.md` (2026-10-16)** |
| `DOCUMENTATION_SOURCES.md` | §10 deste documento | Inventário de fontes fundido nesta auditoria para reduzir dispersão; o caminho antigo vira redirecionamento curto |
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
O inventário da [§10 desta auditoria](#10-inventário-de-fontes-da-consolidação-migrado-de-documentation_sourcesmd) registra os documentos
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

## 10. Inventário de fontes da consolidação (migrado de DOCUMENTATION_SOURCES.md)

> Migrado de `DOCUMENTATION_SOURCES.md` em 2026-10-16 (consolidação: inventário de fontes incorporado
> a esta auditoria). Revisão de origem: `87245d6491e6e27534ab6ada0b4d2cfe7225e43d`, branch `main`,
> 2026-10-15. Inventário de arquivos rastreados via `git ls-files`; hashes abaixo são do conteúdo
> **antes** da consolidação, obtido por `git show HEAD:caminho`. Não inventaria logs privados ou
> recursos ignorados. Não houve leitura de memória/processo nesta manutenção.

### 10.1 Markdown versionado de origem

| Fonte | Linhas | SHA-256 de origem |
|---|---:|---|
| `.agents/skills/repo-evidence/SKILL.md` | 8 | `b9b81b04e1c3be3b3e3aabe5773e582e0732350f361d922e432bb41dafb5ec36` |
| `.agents/skills/research-handoff/SKILL.md` | 9 | `8d93d4e253ba94a8947f4f478bd7e04516f1b68dc67f9ba78acfbbefac1518d3` |
| `.claude/agents/explorer.md` | 9 | `4db0f165f968322b2940619ecaaefbd09f4b0d83af4eca0250a2c09b557298c1` |
| `.claude/agents/implementer.md` | 11 | `f3d7c2691d32a0a4e62f9a667546adec1b0f049765c5229ef7d7651dff899de2` |
| `.claude/agents/verifier.md` | 10 | `b4fbb3b5e8f1265c14a4528fad0a14286b9915cda4d3c91c4181f0352c26a1fc` |
| `AGENTS.md` | 46 | `632ab023574a3217f4a45860a5a692e91404257e648674e0ef7b69247a9a2873` |
| `ARCHITECTURE.md` | 410 | `ff3a43643bfd975f273336d82839d9082211a3ceccfa65c9fee9cc24be554a17` |
| `README.md` | 144 | `c6712f8cc0fdf87c3ff9b117e29aad44202134c46c64c0b2763ee1e7f987f108` |
| `docs/CIPHER_INVESTIGATION.md` | 344 | `b83abbd7a6b2120466ed5574164f6287c01ff3650d7b17c13f79882653b65d9c` |
| `docs/CODEX_WORKFLOW.md` | 35 | `57db19f342c885884bfc82d8b8f49c49757db6cf6b8286509c9e55e5dd6e8262` |
| `docs/GEPARD_CONTROL_PACKETS.md` | 41 | `f228ebc081e0e0ccd5329f5a0ef32a53219d19ea284d557b639a0b086d0e5005` |
| `docs/MOVEMENT_035F_INVESTIGATION.md` | 417 | `de35ed841b97b2fca4ca46d37a6f86bad8cfcbd1a4cc1ac273bf8ce904069926` |
| `docs/MOVEMENT_035F_PRECONDITIONS.md` | 413 | `f3b36fe8ea758dd44aa89d8be2b5b93d8748b48a720ce25ab9d551c61e24b9c6` |
| `docs/RESEARCH_DECISIONS.md` | 62 | `dc29c59cee12cf0be5a65f758078a30cb900c86b13cc875443dc04873ee9e327` |
| `gepard_investigation.md` | 222 | `1b03bb9734dddd5e635a37aa2fd7e13bbf3c8580564d2ebd15416daf93b3073a` |
| `research/cipher/README.md` | 166 | `f8e83a637c3c8fd2d467b5cd36d5ea91ba5fcc1f1da042cf73c6805cb7f3d7b1` |

Além do inventário versionado, `docs/AGENTS.md` (instruções desta tarefa) e
`research/movement_035f/dispatcher_trial.py` já estavam não rastreados. Não foram editados nesta tarefa; o segundo teve alteração concorrente detectada (ver auditoria);
a presença da ferramenta não demonstra execução nem validação em cliente.

### 10.2 Documentação embutida e destinos por família

| Fontes / cobertura de leitura | Informação / destino |
|---|---|
| `relay_capture_linux.py`, `relay/{protocol,runtime,wire_feed,relay,actors,packets,safety,writeback,cli,config}.py` | Contratos, fila, identidade, framing, sanitização, defaults e escrita → [arquitetura](ARCHITECTURE.md) e [operação](OPERATIONS.md) |
| `agent/relay_hook_linux.js` (hooks, sendcall, dreno e throttle) | DR0/DR1, thread, sondas e chamadas periódicas → arquitetura §§5,6,11; comentários criptográficos não viram prova |
| `relay/{agent,memory,sendwatch,research,console}.py` | Responsabilidades por módulo → arquitetura §2; leitura estática dirigida por símbolos, sem alegação de revisão exaustiva de cada linha |
| `setup.sh`, `run.sh`, `requirements.txt`, `relay_capture.conf` | Venv, Gadget, versão, stdin, configuração e defaults → operação |
| `research/cipher/{core,analyze,chain_audit,chain_capture,inspect_client}.py`, `chain_probe.js`, `chain_probe_test.js` | Contratos de análise/coleta e doubles → [manual integral](CIPHER_TOOLS.md), [cifra](CIPHER_INVESTIGATION.md) |
| `research/movement_035f/{analyze,observe_path,native_trial}.py`, commits `bdc2a07..87245d6` | Independência dos canais, campos e cobertura de ponteiros → [pré-condições](MOVEMENT_035F_PRECONDITIONS.md) §§6,10–12 |
| `tests/test_*.py`, `tests/_boot.py`, fixtures existentes | Contratos offline; cobertura por teste abaixo; fixtures não promovidas a vetores completos da cifra |
| `scripts/{test-offline.sh,validate-research.py,validate-codex.py}` | Critérios reais de PASS e limites → operação/auditoria |
| `data/uaro_recvpackets.txt` | Tamanhos, semântica não inferida → [controle](GEPARD_CONTROL_PACKETS.md) |
| `.agents/skills/*/SKILL.md`, `.codex/{config.toml,agents/*.toml}`, `.claude/agents/*.md`, symlinks `.claude/skills` | Instruções preservadas, validação de espelhos → [workflow](CODEX_WORKFLOW.md) |

O inventário distingue inspeção dos contratos de uma prova do comportamento em produção.
Não afirma auditoria exaustiva linha a linha do código funcional ou de toda revisão histórica.

### 10.3 Testes existentes e informação exclusiva de contrato

| Teste | Conhecimento verificável offline |
|---|---|
| `test_actors.py` | Cópias frescas/contextuais, descarte conservador, socket fechado e cadeia |
| `test_cipher_research.py` | Proveniência, perdas, isolamento, privacidade, formatos, doubles JS e limpeza; não cifra real |
| `test_config.py` | Defaults < INI < CLI, tipos inválidos e chaves desconhecidas |
| `test_integration.py` | Pipeline e escrita sobre sockets **locais**, requer permissão para criá-los |
| `test_movement_preconditions.py` | Canais independentes, ordenação por evento, limite do nativo e campos de linkage |
| `test_packets.py` | Framing, fragmentação, tamanho inválido e codificação de movimento |
| `test_relay.py` | Frames `S` cortados e reconstrução do retorno do consumidor |
| `test_safety.py` | Login/HTTP e sanitização |
| `test_sendwatch.py` | Recuperação conservadora das janelas de escrita |
| `test_writeback.py` | Merge/SendPacket, `0368`, dedup, skip, throttle encaminhado e descoberta idempotente |

### 10.4 Cronologia técnica conferida no Git

- `6a47d5c`: traço de cifra e modelo 2016; é origem histórica, não equivalência atual.
- `05fb8d3`: reescrita do histórico Gepard removeu narrativa antiga. As referências §§22–23
  sobreviveram em textos, mas as seções atuais equivalentes são §§3–4.
- `f98e466`: removeu `HANDOFF.md` e adicionou candidatos de perícia não confiáveis.
  Handoff anterior consultado: sínteses repetidas dos históricos; nomes de scripts externos
  `findunit.py`, `scanunit.py`, `difftrace.py`, `fitf.py` são pistas de método, não ferramentas
  disponíveis no checkout. Não se restauram dados de conta/rede daquele handoff.
- `0feb23a`/`b4724fc`: seleção de alvo, dedup/anti-flood, dreno periódico e paceamento;
  comentários históricos de drenagem exclusiva por tráfego estão superados pelo código.
- `3403a4c`/`5ea043f`: cadeia natural, ABI, controles e ensaios iniciais de movimento.
- `8006373`: ferramentas e continuação da cifra; dependências de bytes não resolvem F.
- `bdc2a07`: pré-condições e ensaio 6.4; base do ZIP recebido.
- `2645fad`, `87245d6`: auditoria produtor/consumidor e extensões de linkage; base da primeira consolidação.

Não houve fetch, merge, restauração de arquivos removidos ou exame de logs privados.
O relatório externo DiE citado nas pré-condições continua indisponível nesta árvore;
não há evidência local suficiente para incorporá-lo como descoberta.

### 10.5 Atualização após revisão do diff

A revisão subsequente usa `524b0f05fa61872e140f98ace9e503d12356641e` como HEAD.
Esse commit rastreou `research/movement_035f/dispatcher_trial.py` e acrescentou o ensaio
§13 às pré-condições. Os hashes da tabela inicial continuam descrevendo a origem em
`87245d6`, não o novo conteúdo. O panorama e o índice foram atualizados para o store
espontâneo sem retorno/envio confirmados; H2/H3 permanecem não isoladas.
`git pull --ff-only --no-rebase` concluiu com "Already up to date"; nenhuma branch de
pesquisa recém-descoberta foi mesclada nesta tarefa. O relatório DiE continua fora
da árvore de trabalho; disponibilidade de uma referência remota não valida seu conteúdo.

### 10.6 Integração posterior solicitada

O pull de `origin/main@0a29193` incorporou o relatório `PROTECTION_FINGERPRINT_DIE.md` e
suas referências; a integração local `677e51e` preserva também `888764a`. A informação DiE
que chegou na arquitetura antiga foi conciliada em `docs/ARCHITECTURE.md` §12. A nota
anterior de relatório fora da árvore refere-se ao momento anterior a esse pull.

### 10.7 Fonte experimental incluída por autorização de publicação

`research/movement_035f/dispatcher_trial13.py`: frame de 13 dwords, verificação do epílogo,
observadores de execução/transporte e registro incremental. A checagem antes de publicar
cobriu sintaxe Python/JS, não execução no cliente. Hashes dos módulos não são conferidos
automaticamente pelo script; parâmetros e endereços pertencem à build documentada.
