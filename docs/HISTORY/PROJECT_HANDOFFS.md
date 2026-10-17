# Arquivo de governança documental, handoffs de coordenação e redirecionamentos históricos

> **Registro histórico imutável de origem.** Contratos, instruções e briefings de tarefas concluídas não substituem `AGENTS.md` da raiz, `docs/AGENTS.md` vigente nem `research/COORDINATION.md`. Código/skills ativos e seus arquivos de configuração não foram movidos.

## Índice e blobs de proveniência

- [`docs/AGENTS.md`](#source-docs-agents-md) — blob `8e64a04107d15d89ad5cbe88b8039761181fb96a`
- [`docs/CODEX_WORKFLOW.md`](#source-docs-codex-workflow-md) — blob `d27d1f77fa3e53acb3e927607e611bcd7259a65e`
- [`research/DOCUMENTADOR_BACKLOG.md`](#source-research-documentador-backlog-md) — blob `c0c1f74bb03fa788f1f6489f04281212eeeeb4c0`
- [`research/HANDOFF_ORQUESTRADOR_CODEX.md`](#source-research-handoff-orquestrador-codex-md) — blob `0c346d486b8b6e74f030d2059619789ad21c2eb1`
- [`research/ORCHESTRATOR_RESUME_20261016.md`](#source-research-orchestrator-resume-20261016-md) — blob `699ffcc8eb3f08d4bad583a7e7c88b92fd59bf30`
- [`ro_ops/HANDOFF.md`](#source-ro-ops-handoff-md) — blob `d11f0791caaf1d2d2dfe6762e4bccdf01a7d5956`
- [`ARCHITECTURE.md`](#source-architecture-md) — blob `1f93ecbccd1a9832b617e3c8319bca3e9242b1c3`
- [`gepard_investigation.md`](#source-gepard-investigation-md) — blob `a646e3f0bc52268fd806e71d1f3689fdf2f85681`

Os corpos das fontes são preservados **sem cortes ou reescrita**. Referências antigas e ordens de pesquisa encerrada devem ser lidas como parte de sua cronologia, não instruções ativas.

<a id="source-docs-agents-md"></a>

## Fonte original: `docs/AGENTS.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `8e64a04107d15d89ad5cbe88b8039761181fb96a` · caracteres: 18911.

<!-- BEGIN ORIGINAL docs/AGENTS.md -->
# RO-Client-Relay — Auditoria, consolidação e manutenção integral da documentação

## 1. Papel e missão

Você é o **Agente Responsável pela Arquitetura Documental, Curadoria de Evidências e Manutenção do Conhecimento Técnico** do projeto RO-Client-Relay.

Sua missão é realizar uma auditoria completa da documentação existente, corrigir informações desatualizadas, resolver contradições e consolidar o conhecimento técnico do projeto dentro da pasta `docs/`.

**Não se limite a apresentar um plano. Execute efetivamente a reorganização e atualização dos arquivos, respeitando as restrições abaixo.**

O objetivo não é produzir documentação curta. É construir uma **base de conhecimento técnica, detalhada, confiável, navegável e adequada ao consumo por outros agentes de IA**, que futuramente executarão tarefas especializadas sem precisar reconstruir todo o histórico do projeto.

Leia integralmente o arquivo `AGENTS.md` antes de começar e siga as diretrizes aplicáveis do projeto.

### Skills ativas (usar sempre que aplicável — Claude e Codex)
Ver a lista completa no AGENTS.md da raiz. Para a curadoria documental, use especialmente:
- **`repo-evidence`** para conferir uma afirmação nova contra o trecho citado (`arquivo:linha`) sem
  auditar todo o repositório — é o modo barato de verificar um HANDOFF antes de integrá-lo.
- **`research-handoff`** para entender o formato dos HANDOFFs dos pesquisadores que você consome.
- **`ro-ops`** só como referência: os campos de `scaffold-state` (STATE/HANDOFF) definem o que os
  pesquisadores entregam; ao integrar, preserve a classificação OBSERVADO/INFERIDO/HIPÓTESE/
  NÃO VERIFICADO/REFUTADO. O kit é read-only e não autoriza nada.
Concluído (2026-10-16): o kit `ro-ops` já está citado em `docs/CODEX_WORKFLOW.md` (seção
*Kit operacional `ro-ops` e skills*). Consolidação: o antigo `docs/DOCUMENTATION_SOURCES.md` foi
fundido em `docs/DOCUMENTATION_AUDIT.md` §10 (redirecionamento curto mantido no caminho antigo).

### Princípio fundamental

**Consolidar não significa resumir indiscriminadamente.**

A documentação final pode continuar extensa quando a complexidade técnica exigir. O objetivo é eliminar redundâncias, informações superadas e dispersão, sem eliminar dados necessários à reprodução, interpretação ou continuidade das pesquisas.

Prefira um documento longo, estruturado e tecnicamente completo a um documento curto que obrigue outros agentes a redescobrir informações.

---

## 2. Levantamento integral do repositório

Antes de modificar qualquer arquivo, obtenha uma visão completa do estado atual.

Execute `git status`, registre o commit de referência e identifique alterações preexistentes. Não descarte nem sobrescreva trabalho de outras sessões.

Faça uma varredura recursiva do repositório, identificando:

- Todos os arquivos Markdown, independentemente da localização.
- Documentação embutida em scripts, código-fonte e comentários.
- Configurações com explicações sobre arquitetura ou comportamento.
- Documentos e instruções de agentes e subagentes.
- Histórico de decisões, hipóteses, experimentos e resultados.
- Referências cruzadas, caminhos de arquivos e links internos.
- Informações que existem apenas em testes automatizados ou ferramentas de pesquisa.

### Documentos inicialmente identificados

Na raiz:

- `AGENTS.md`
- `README.md`
- `ARCHITECTURE.md`
- `gepard_investigation.md`

Em `docs/`:

- `CIPHER_INVESTIGATION.md`
- `CODEX_WORKFLOW.md`
- `GEPARD_CONTROL_PACKETS.md`
- `MOVEMENT_035F_INVESTIGATION.md`
- `MOVEMENT_035F_PRECONDITIONS.md`
- `RESEARCH_DECISIONS.md`

Em outras pastas:

- `research/cipher/README.md`
- `.agents/skills/`
- `.claude/agents/`
- `.codex/agents/`

Consulte também `agent/`, `relay/`, `research/`, `tests/`, `scripts/`, `relay_capture.conf` e `data/uaro_recvpackets.txt` para verificar afirmações documentais contra a implementação atual.

Essa lista é apenas o ponto de partida. **Não presuma que ela representa todos os arquivos relevantes.**

Não mova arquivos de configuração, código executável, testes, fixtures ou dados técnicos para `docs/` apenas por conterem comentários explicativos.

---

## 3. Hierarquia de atualidade, evidência e confiabilidade

A documentação foi construída ao longo de diversas investigações. Muitas descobertas posteriores corrigiram ou limitaram interpretações anteriores.

O agente deve aplicar uma hierarquia explícita para resolver divergências.

### 3.1 Ordem de prioridade

Utilize a seguinte ordem geral:

1. Decisões técnicas atuais expressamente confirmadas pelo responsável pelo projeto.
2. Evidências reproduzíveis do build atual, verificadas em experimentos recentes.
3. Implementação atual do código e testes que comprovem comportamentos específicos.
4. Investigações recentes com resultados documentados e condições de observação claras.
5. Investigações anteriores do mesmo build, desde que ainda compatíveis.
6. Inferências, modelos explicativos e hipóteses fundamentadas, ainda não comprovadas.
7. Documentação histórica de builds antigos e analogias com outros projetos.

**A informação mais recente deve ter prioridade entre evidências comparáveis, mas a data sozinha não comprova a correção de uma afirmação.**

Uma observação antiga reproduzível não deve ser substituída por uma hipótese recente sem comprovação.

Da mesma forma, uma documentação antiga não deve prevalecer simplesmente por ter sido escrita com linguagem mais assertiva.

### 3.2 Não confundir tipos de evidência

Utilize obrigatoriamente estas classificações:

- **OBSERVADO:** comportamento diretamente registrado, com origem e condições conhecidas.
- **INFERIDO:** conclusão sustentada por evidências, mas não demonstrada diretamente.
- **HIPÓTESE:** explicação ou possibilidade ainda sujeita a teste.
- **NÃO VERIFICADO:** afirmação sem demonstração suficiente no escopo atual.
- **REFUTADO:** explicação incompatível com evidência obtida, especificando o escopo da refutação.

Não transforme uma hipótese em observação pela simples repetição da afirmação em vários documentos.

Não transforme ausência de observação em prova de ausência de comportamento sem verificar a cobertura dos instrumentos.

### 3.3 Critérios de procedência

Para descobertas importantes, preservar quando disponíveis:

- Data da investigação.
- Commit e revisão do código.
- Identificação do build.
- Identificação sanitizada da sessão.
- Método e ferramenta de coleta.
- Condições de execução.
- Endereços, offsets e símbolos relevantes.
- Resultados efetivamente observados.
- Explicações alternativas.
- Limites de cobertura e instrumentação.
- Evidências contrárias.
- Estado atual da conclusão.
- Experimento necessário para confirmação ou refutação.

Não trate endereços absolutos de sessões antigas como endereços universais.

Não misture experimentos de builds diferentes sem evidência de equivalência.

---

## 4. Estratégia de consolidação

A pasta `docs/` deve se tornar a **fonte canônica da documentação técnica**.

Cada assunto deve ter um documento principal claramente identificado.

Quando diversos arquivos abordarem o mesmo assunto, consolide as informações sem perder os detalhes exclusivos de cada um.

### 4.1 Estrutura documental sugerida

Avalie a seguinte organização, adaptando-a somente quando houver justificativa técnica:

**`docs/README.md` — Índice central**

Ponto de entrada para agentes e desenvolvedores. Deve permitir localizar rapidamente o documento apropriado, identificar seu escopo e saber quais arquivos consultar para cada tarefa.

**`docs/ARCHITECTURE.md` — Arquitetura atual**

Arquitetura do relay, Frida, Wine/Proton, OpenKore, xKore 1, fluxos de comunicação, módulos, threads, estado compartilhado, limites do sistema e relação com o objetivo futuro xKore 0.

**`docs/OPERATIONS.md` — Instalação e operação**

Instalação, configuração, execução, dependências, parâmetros, diagnósticos, testes, restrições e comportamentos operacionais.

**`docs/RESEARCH_STATUS.md` — Estado atual das investigações**

Visão consolidada do conhecimento atual, resultados mais recentes, hipóteses ativas, problemas resolvidos, problemas abertos e prioridades.

Este arquivo deverá ser especialmente útil para agentes que precisam compreender o estado do projeto antes de receber uma tarefa específica.

**`docs/RESEARCH_DECISIONS.md` — Decisões e restrições**

Preservar como documento canônico das decisões efetivamente tomadas, diferenciando-as de hipóteses ou propostas ainda não aprovadas.

**`docs/MOVEMENT_035F_INVESTIGATION.md` — Investigação do movimento**

Preservar em detalhe a pesquisa sobre o pacote `0x035F`, a cadeia de movimento, instrumentação, despacho, funções internas, ABI, resultados experimentais e limitações.

**`docs/MOVEMENT_035F_PRECONDITIONS.md` — Pré-condições do movimento**

Preservar especialmente a comparação entre execução natural e chamada nativa, preparação de estado, hipóteses discriminadas e experimentos que estabeleceram dependências.

Só fundir este documento ao anterior se isso melhorar significativamente a organização sem sacrificar rastreabilidade, detalhes ou acessibilidade.

**`docs/CIPHER_INVESTIGATION.md` — Investigação da cifra**

Preservar as descobertas sobre o processamento criptográfico, cadeia de bytes, dependências, registradores, estruturas em memória, observações dinâmicas, hipóteses e limites conhecidos.

**`docs/GEPARD_CONTROL_PACKETS.md` — Pacotes e estado de sessão**

Registro canônico das informações observadas sobre pacotes de controle, sincronização, inicialização e requisitos de sessão, mantendo distinção entre o build atual e referências históricas.

**`docs/CODEX_WORKFLOW.md` — Fluxo de trabalho dos agentes**

Uso das ferramentas, delegação, limites de subagentes, validação, economia de contexto e procedimentos de pesquisa.

**`docs/RESEARCH_EVIDENCE_INDEX.md` — Índice de evidências**

Criar um índice de evidências importantes com referências à origem, status, build, documento responsável e possibilidade de reprodução.

**`docs/HISTORY/` — Histórico técnico preservado**

Utilizar somente quando necessário para manter investigações antigas, resultados superados ou material detalhado que não deva mais ser apresentado como conhecimento atual.

Não crie arquivos artificiais ou fragmentação excessiva.

### 4.2 Arquivos fora de `docs/`

Manter `AGENTS.md` na raiz, por sua função de instrução aos agentes.

Manter o `README.md` da raiz como apresentação breve, orientação de instalação inicial e ponto de acesso ao índice em `docs/`.

Migrar o conteúdo técnico aprofundado de `ARCHITECTURE.md` e `gepard_investigation.md` para os documentos canônicos pertinentes.

Quando necessário, manter pequenos arquivos de redirecionamento ou orientação nos caminhos antigos para preservar compatibilidade.

O mesmo princípio vale para `research/cipher/README.md`: centralizar o conhecimento técnico em `docs/`, mas preservar um ponto de entrada local caso seja útil às ferramentas e aos desenvolvedores.

**Não duplicar documentos completos em múltiplos caminhos.**

Preservar instruções operacionais de agentes que precisam permanecer nos diretórios `.agents/`, `.claude/` e `.codex/`.

---

## 5. Preservação obrigatória de detalhes técnicos

Não elimine informações apenas porque parecem excessivamente específicas.

Os documentos serão utilizados posteriormente por subagentes que realizarão investigações delimitadas, sem necessariamente terem acesso a todo o contexto histórico.

### Informações que devem ser preservadas

- Endereços relativos, offsets e referências a módulos.
- Instruções assembly e sequências de execução relevantes.
- Assinaturas de funções e convenções de chamada.
- Registradores, pilha, argumentos, objetos e campos.
- Estruturas de pacotes, IDs, tamanhos e enquadramento.
- Ordem de chamadas e dependências temporais.
- Condições de disparo e pré-condições de execução.
- Comparações entre caminhos naturais e artificiais.
- Diagramas, tabelas, matrizes de hipóteses e fluxos.
- Procedimentos experimentais reproduzíveis.
- Resultados positivos, negativos e inconclusivos.
- Resultados que refutaram hipóteses anteriores.
- Limitações de observação e instrumentação.
- Cuidados relacionados à integridade do estado e concorrência.
- Exemplos técnicos sanitizados e comandos de reprodução offline.
- Referências exatas ao código e às evidências.

Preservar particularmente os experimentos negativos: eles frequentemente explicam por que determinadas abordagens não devem ser repetidas.

Se dois documentos contiverem partes complementares de um mesmo experimento, integrar essas partes.

Se apresentarem interpretações divergentes, registrar a divergência e sua resolução.

Se uma conclusão antiga estiver superada, preservar seu contexto histórico quando ele for útil à compreensão do resultado atual, marcando claramente sua condição.

**Nunca substituir uma sequência técnica detalhada por expressões vagas como "foi investigado", "o processo foi validado" ou "houve uma falha de estado".**

---

## 6. Assuntos que exigem atenção especial

### 6.1 Movimento `0x035F`

Confrontar especialmente:

- `ARCHITECTURE.md`
- `docs/MOVEMENT_035F_INVESTIGATION.md`
- `docs/MOVEMENT_035F_PRECONDITIONS.md`
- `docs/RESEARCH_DECISIONS.md`
- `research/movement_035f/`
- Testes associados.

As investigações mais recentes introduziram distinções importantes entre execução natural, preparação do dispatcher, entrada no receptor `0x8A`, observação do store, transporte e resposta.

Não tratar resultados de tentativas nativas antigas como explicação definitiva quando experimentos posteriores permitirem conclusões mais precisas.

Preservar quais hipóteses foram refutadas, quais continuam abertas e exatamente quais dependências ainda precisam ser identificadas.

### 6.2 Cifra uaRO/Gepard

Confrontar:

- `gepard_investigation.md`
- `ARCHITECTURE.md`
- `docs/CIPHER_INVESTIGATION.md`
- `research/cipher/README.md`
- Código em `research/cipher/`
- Testes de pesquisa da cifra.

Diferenciar estritamente a fonte histórica Gepard 2016 das observações do cliente uaRO atual.

Preservar integralmente as descobertas recentes sobre a cadeia de bytes, cargas, stores, produtores intermediários e dependências observadas.

Não confundir o transporte ou a cópia de um byte com a descoberta de sua operação criptográfica geradora.

Não afirmar que a cifra foi completamente compreendida enquanto existirem dependências fundamentais não identificadas.

### 6.3 Protocolo e objetivo xKore 0

Documentar claramente a separação de responsabilidades:

- OpenKore implementa a lógica do consumidor.
- RO-Client-Relay desempenha seu papel intermediário no fluxo com o cliente.
- O objetivo futuro é operação independente do cliente em xKore 0.
- Uma futura integração independente do protocolo pertence conceitualmente ao projeto OpenKore.

Não propor implementação de outro backend xKore dentro do relay.

### 6.4 Configuração e segurança

Não modificar o comportamento de execução do projeto durante esta tarefa documental.

Preservar os valores intencionais `inject = true` e `inject-call = true` de `relay_capture.conf`.

Manter as distinções entre defaults internos do CLI e configuração em arquivo.

Não confundir testes offline com validação em cliente real.

Não utilizar documentação histórica como autorização para novos experimentos de rede.

---

## 7. Método de execução

Realize o trabalho em etapas.

### Etapa A — Inventário documental

Construir uma matriz interna contendo:

| Fonte | Assuntos abordados | Atualidade | Evidência | Destino canônico | Ação proposta |
|---|---|---|---|---|---|
| Arquivo original | Tópicos | Data/build/commit | Grau de confiabilidade | Documento final | Manter, migrar, fundir, atualizar ou arquivar |

Identificar documentos duplicados, incompletos, desatualizados e conflitantes.

Não mover nem remover nada nesta etapa.

### Etapa B — Reconciliação técnica

Comparar afirmações equivalentes e contraditórias.

Para cada conflito relevante, determinar:

1. Qual é a afirmação original?
2. Qual evidência a sustentava?
3. Existe uma observação posterior?
4. A observação posterior se refere ao mesmo build e contexto?
5. O que foi confirmado, corrigido ou refutado?
6. Qual deve ser a formulação canônica?
7. Que informação histórica precisa ser preservada?

Quando não for possível resolver uma contradição, registrar explicitamente que ela permanece aberta.

Nunca criar uma conclusão artificial apenas para eliminar divergências.

### Etapa C — Consolidação

Executar a reorganização por assunto.

Preservar tabelas, detalhes, comandos, referências, experimentos e resultados.

Atualizar informações superadas e remover duplicações editoriais.

Utilizar links internos para remeter aos documentos especializados, em vez de replicar seções extensas.

Manter uma separação clara entre:

- Estado atual confirmado.
- Evidências e experimentos detalhados.
- Hipóteses e limitações.
- Histórico e conclusões superadas.
- Próximos passos.

### Etapa D — Auditoria de cobertura

Antes de eliminar um documento original, verificar que todo conteúdo tecnicamente relevante foi:

- Migrado para um documento canônico;
- Mantido como referência histórica identificada; ou
- Classificado como duplicação efetiva, sem informação exclusiva.

Produzir um registro de migração com origem, destino e justificativa.

**Não eliminar um arquivo simplesmente porque seu conteúdo aparece parcialmente em outro.**

### Etapa E — Atualização dos pontos de entrada

Atualizar `README.md`, `AGENTS.md` e os links necessários para indicar a documentação canônica.

Preservar o funcionamento das configurações existentes de agentes e skills.

O novo `docs/README.md` deve incluir, para cada documento principal:

- Finalidade.
- Escopo.
- Status de atualização.
- Assuntos cobertos.
- Relação com outros documentos.
- Perfil de tarefa ou subagente que deve consultá-lo.

O índice deve orientar quais documentos ler antes de executar tarefas sobre arquitetura, movimento, cifra, protocolo, instrumentação e testes.

---

## 8. Estrutura interna recomendada para documentos de pesquisa

Sempre que pertinente, padronizar:

1. **Objetivo e escopo** — qual problema o documento investiga.
2. **Estado atual** — melhor entendimento disponível e seus limites.
3. **Ambiente e procedência** — builds, sessões, revisões e condições.
4. **Evidências técnicas** — dados observados e referências.
5. **Análise** — interpretação dos resultados e hipóteses concorrentes.
6. **Experimentos** — métodos, parâmetros, resultados e reprodução.
7. **Descobertas refutadas ou superadas** — com contexto e explicação.
8. **Lacunas de conhecimento** — o que ainda não foi demonstrado.
9. **Próximos experimentos** — dependências e critérios de sucesso.
10. **Referências cruzadas** — código, testes e documentos relacionados.

Essa organização não deve obrigar a fragmentar sequências técnicas cujo entendimento dependa de sua apresentação contínua.

---

## 9. Prepar
<!-- END ORIGINAL docs/AGENTS.md -->

<a id="source-docs-codex-workflow-md"></a>

## Fonte original: `docs/CODEX_WORKFLOW.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `d27d1f77fa3e53acb3e927607e611bcd7259a65e` · caracteres: 3094.

<!-- BEGIN ORIGINAL docs/CODEX_WORKFLOW.md -->
# Codex CLI no Bazzite — rotina curta

O CLI é autenticado com ChatGPT. A configuração deste repositório só é lida quando o diretório for confiável para o Codex.

## Início
```bash
cd /caminho/RO-Client-Relay
codex login
codex
```

Use `/model` para confirmar disponibilidade de `gpt-6.1-sol`, `gpt-6-luna` e `gpt-6-astra`. Modelo de rotina: Sol; decisões abstratas: iniciar sessão `codex --model gpt-6-astra` quando realmente necessário.

## Delegação
- O coordenador não delega tarefas triviais que possa completar em uma leitura curta.
- Máximo de dois subagentes concorrentes, independentemente da quantidade de papéis configurados.
- `explorer` localiza evidência; `implementer` aplica patch delimitado; `verifier` revisa e testa. Não carregue todos em toda tarefa.
- Entregue sempre: pergunta, caminhos, critério de aceitação, no máximo 150 palavras de resposta.
- Não forneça a transcrição integral, logs extensos ou múltiplos documentos históricos se bastar um trecho com `arquivo:linha`.
- Não presuma que instruções são isolamento de filesystem; subagentes herdam permissões.

## Kit operacional `ro-ops` e skills
Skills do projeto em `.agents/skills/` (descobertas por Codex e Claude): `ro-ops`, `repo-evidence`,
`research-handoff`. Ver AGENTS.md da raiz para quando usar cada uma. Para tarefas recorrentes,
prefira o kit a reescrever shell:
```bash
python3 -m ro_ops discover        # PID/porta do gadget + main_tid (read-only)
python3 -m ro_ops env-check       # pré-requisitos e estado de limpeza (read-only)
python3 -m ro_ops sample-thread --pid P --tid T
python3 -m ro_ops new-artifact --dir D [--pid P] [--probe F]   # dir privado 0700 + PROVENANCE
python3 -m ro_ops scaffold-state --dir research/<trilha> --role R --id ID
```
Saída JSON `{cmd,status,data,caveats}`; exit codes 0 verified / 10 unverified / 20 undetermined /
1 erro de uso. `undetermined` nunca vira positivo — leia `caveats`. **O kit é read-only por padrão
e não autoriza experimento**; `env-check` **não** prova exclusividade da janela (ausência de lock
≠ autorização; a janela é combinada com o responsável e o `research/COORDINATION.md`).

## Validação
```bash
python3 scripts/validate-codex.py
python3 scripts/validate-research.py
bash scripts/test-offline.sh
```

Os scripts não executam cliente, Frida, rede ou testes externos. A validação Codex cobre **estrutura** de arquivos, não disponibilidade de modelos nem execução do CLI. Repetir testes locais no Bazzite antes de confiar na automação; CI executa mesma suíte em Linux GitHub-hosted.

## Medição da economia
Para cada tarefa comparável, anote: modelo coordenador, agentes utilizados, tempo, uso reportado pelo CLI quando disponível, testes aprovados e retrabalho. Não declare que multiagentes economizam tokens sem amostra comparativa.

## MCP, hooks e Ghidra
Nenhum MCP ou hook extra está habilitado por padrão: buscar primeiro evidência nos arquivos, validar comandos offline e pedir aprovação para atividade externa. A extensão por Ghidra/IDA deve responder a uma lacuna técnica concreta; não instalar MCP genérico apenas por disponibilidade.
<!-- END ORIGINAL docs/CODEX_WORKFLOW.md -->

<a id="source-research-documentador-backlog-md"></a>

## Fonte original: `research/DOCUMENTADOR_BACKLOG.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `c0c1f74bb03fa788f1f6489f04281212eeeeb4c0` · caracteres: 11865.

<!-- BEGIN ORIGINAL research/DOCUMENTADOR_BACKLOG.md -->
> **Integrado pelo Documentador (2026-10-16, segunda passada):** MOVER-20261016-08 (§13.12),
> ACT-20261016-01 (`GEPARD_CONTROL_PACKETS.md`, §13.13, RESEARCH_STATUS A-01, índice A-01; refutação
> do `0368` aplicada em OPERATIONS/ARCHITECTURE/DECISIONS) e CIFRA STACK-04…SLICE-12
> (`CIPHER_INVESTIGATION.md`, RESEARCH_STATUS/índice C-10). Afirmações "06b não reproduzida" corrigidas.

# Backlog do Documentador

> **PARCIALMENTE INTEGRADO pelo Orquestrador (2026-10-15, commit a seguir), enquanto o Documentador
> estava sem tokens.** JÁ FEITO: §13.8–§13.10 em `MOVEMENT_035F_PRECONDITIONS.md` (tarefas 1a, 1a-bis,
> 1a-ter e a CORREÇÃO CRÍTICA na parte de movimento); citação do kit em `CODEX_WORKFLOW.md` (tarefa 4).
> PENDENTE p/ o Documentador: tarefa 1b (conferir se §13.5/§13.7 foram temperadas no corpo antigo do
> doc), tarefa 2 (CIFRA em `CIPHER_INVESTIGATION.md` — NÃO toquei, há diff concorrente), tarefa 3
> (`RESEARCH_STATUS.md`/índice — NÃO toquei, diff concorrente), e revisar o que integrei.

Fila de integração montada pelo Orquestrador. **Não é documento científico** e não
concede autorização. Ao retomar, leia `research/COORDINATION.md` (§Entrega ao
documentador) e as instruções de `docs/`. Classifique tudo em
OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO. Não transforme relato em
prova. Preserve rodadas anteriores. Atualizado 2026-10-15.

## CORREÇÃO CRÍTICA (2026-10-15, confirmada pelo responsável) — aplicar antes das demais
Entra via MOVER (retratação) + responsável. Reclassifica a leitura do 035F e conecta MOVER↔CIFRA.

- **FATO:** o **035F é CIFRADO** — XOR-scramble byte-a-byte em memória **antes** do envio. Qualquer
  afirmação de que 035F trafega/é montado em "texto claro" é **REFUTADA**. (A retratação do MOVER
  foi sobre uma leitura `0x5F03` num `send` da libc, pós-scramble, irrelevante.) Varra os docs de
  movimento por linguagem que sugira 035F claro e corrija. **Nota:** "relay de texto claro" em
  `GEPARD_CONTROL_PACKETS.md:41` é OUTRO contexto (saída decifrada do relay p/ OpenKore em xKore 1)
  e está **correto** — não confundir.
- **FATO (validado p/ este cliente, `relay_capture.conf:99-111`):** o que as sondas de movimento
  chamam `store_035f` em **gepard+0x18eff2** (`mov byte [ecx],bl`) **é o byte-store in-place do
  scrambler do Gepard** (= `scramble-bp=18eff2`). O cliente monta o 035F em
  `scramble-range=2632000-2730000`, cifra ali byte-a-byte e envia. Isto **liga** o `store_035f` da
  trilha MOVER ao scrambler que a CIFRA investiga — anote a conexão nos dois documentos.
- **VALIDADO (relay, `relay/writeback.py`, `relay/sendwatch.py`):** a injeção de andar pelo relay =
  substituir o corpo **ANTES do XOR nesse store** (BP exec DR0); o cliente então cifra+envia. É o
  caminho correto conhecido para o 035f (merge reativo, `inject=true`/`inject-call=true`).
- **Reenquadramento da rodada 04:** a chamada direta ao dispatcher ORIGINOU um 035F e **chegou ao
  scrambler** (`store_035f` id=0x35F during_call) → movimento de fato injetado, mas **retornou antes
  do estágio natural de envio e travou**. Causa **líder (HIPÓTESE, não provada):** reentrância Wine
  (disparo de dentro de um `read` da libc, no pump do wineserver). Documente como hipótese líder,
  não como mecanismo demonstrado.
- **Direção vigente (responsável, sobrepõe o contrato da rodada 05):** retomar a origem via chamada
  ao dispatcher e **estabilizar o crash**; **não** seguir a via "caminho de envio natural" pura.
  Ajuste a §13 para refletir que a via de envio natural foi preterida por decisão humana.

## 0. Antes de tocar em docs
- `git status` / `git log`. Há **mudanças não commitadas em `docs/`** (CIPHER_INVESTIGATION,
  CIPHER_TOOLS, RESEARCH_EVIDENCE_INDEX, RESEARCH_STATUS) e em `research/cipher/*.py` —
  são edições em andamento (consolidação / CIFRA). **Confirme a propriedade antes de
  sobrescrever**; não reverta diffs alheios. MOVER e CIFRA já entregaram a propriedade dos
  docs ao Documentador (ver HANDOFFs), mas o diff em curso precisa ser conciliado, não descartado.
- Kit `ro-ops` já commitado e pushado (commit `b003b1d`). Não precisa integrar código; ver tarefa 4.

## 1. MOVER — integrar em `docs/MOVEMENT_035F_PRECONDITIONS.md`
Fonte: `research/movement_035f/HANDOFF.md` (IDs 01, 02, 04) e `STATE.md` (rodadas 03, 04).
Rodada 05 (via de envio natural) **está em andamento — aguarde o HANDOFF 05 antes de fechar §13**.

### 1a. §13.8 NOVA (rodada 04) — ainda ausente do doc
O resultado mais recente demonstrado **não está em docs**, só em HANDOFF:04 e STATE.
Integrar como §13.8:
- **OBSERVADO:** cliente é Wine; a main thread drena o wineserver por `read` (~1308/5 s) e
  `writev`, quase não usa libc `poll` (2/5 s). A âncora antiga (`poll` onLeave) não disparava
  por isso. Âncora corrigida p/ `read` onLeave.
- **OBSERVADO:** chamada nativa 13-dword no `read` onLeave, dest (274,315), **RETORNOU**
  (`emit_return` retval=1010077) e montou corpo 0x35F no dest, `during_call`. **SEM**
  `sendmsg`/`recv_0087`. Cliente **congelou e encerrou após o retorno**.
- **Contraste §13.5** (poll onEnter / pré-poll): lá congelava DENTRO, sem retorno.
- **Classificação correta:** dependência de fase/contexto = OBSERVADA (pós-espera retorna ×
  pré-poll trava). Transmissão ausente = OBSERVADA. **O `store_035f` observado = o byte-store do
  scrambler** (ver CORREÇÃO CRÍTICA): a chamada chegou a cifrar o corpo in-place, mas retornou
  antes do estágio natural de envio. **Mecanismo do freeze = HIPÓTESE, líder = reentrância Wine**
  (disparo de dentro de um `read` da libc); flush pulado é alternativa. **NÃO** escrever que
  "anda" nem que o mecanismo está resolvido.
- **Critério ponta-a-ponta:** retorno SIM / envio NÃO / resposta NÃO / responsivo NÃO → FALHOU.
- Evidência: artefato privado `/tmp/claude-035f-20261015-160152-read-anchor/` (não versionar).

### 1a-bis. §13.9 NOVA (rodada 05) — abort mid-call (fonte: HANDOFF:05)
Chamada direta ao dispatcher, âncora `read` onLeave, dest (273,313), **delay 2 s** (autorizada e
assistida pelo responsável). Cliente DOWN depois.
- **4 critérios:** retorno NÃO / envio NÃO / resposta NÃO / responsivo NÃO → FALHOU.
- **Modo de falha = OBSERVADO:** **não** foi freeze — `native_exception type="abort"` (SIGABRT),
  `pc=vdso`, **DURANTE** a chamada. `hang_diagnosis="absent"` (processo já ausente; responsável:
  "o cliente simplesmente fechou").
- A chamada **entrou, rodou o receptor, e o scrambler cifrou o corpo injetado** (`store_035f`
  id=0x35F body [273,313] dir=1, during_call) — origem autônoma do 035F chegou ao scrambler de novo —
  **e então abortou**.
- **Discriminador (OBSERVADO):** delay 700 ms (rodada 04) → RETORNOU+travou; delay 2 s (rodada 05)
  → abort mid-call. **Manifestações diferentes, causa provável a mesma.**
- **Classificação:** reentrância Wine = **HIPÓTESE LÍDER, não provada** (chamada de lógica PE de
  dentro do `onLeave` de um `read` da libc = pump do wineserver → check de consistência libc/Wine →
  abort). Não escrever como mecanismo demonstrado.
- Próxima rodada (06): discriminante = disparar **fora** do contexto do `read` (HW exec BP em sítio
  de main-loop do `uaRO.exe`, base fixa 0x400000). Aguardando relogin.

### 1a-ter. §13.10 NOVA (rodada 06b) — SUCESSO ponta-a-ponta (fonte: HANDOFF:06)
**MARCO.** Primeira origem autônoma de 035F que retorna, transmite, recebe resposta e mantém o
cliente vivo. PID 3338296, artefato `/tmp/claude-035f-20261015-170143-round06b/trial.json`.
- **Disparo:** dispatcher 0x11 a partir de um **sítio de main-loop do `uaRO.exe` (HW exec BP em
  `0x4dcba0`, base fixa 0x400000)**, FORA do contexto do `read` do wineserver.
- **Trace OBSERVADO:** `disp_captured` passivo (code120, this_ecx=0x28c7b158) → `emit_call`
  dest[273,313] frame `[0,17,0,273,0,313,0×7]` → **`sendmsg` fd195 5 B during_call** →
  **`emit_return` retval=215959, sem exceção** → **`recv_0087` src[273,314] dst[273,313] =
  destino injetado** → cliente state S, vivo/estável.
- **4 critérios:** retorno SIM / envio 5 B SIM / recv_0087 dst=destino SIM / responsivo SIM → **PASSOU.**
- **Correção de método:** a rodada 06 não disparou por **bug de guard** (no modo `--construct-frame`
  o capFrame é null de propósito; o guard exigia `!=null`). Corrigido. **NÃO** era slot/threading de HW BP.
- **Classificação (respeitar o limite do MOVER):** sustenta que **o contexto read/wineserver era a
  causa** dos crashes r04 (freeze, delay 700) e r05 (abort, delay 2000). **NÃO** escrever
  "reentrância resolvida em geral" — o callback de HW-BP ainda é contexto não-natural.
- **Cobertura/perda:** BPs desarmados em `doFire` → o `store_035f` do scrambler **não** foi observado
  during_call nesta rodada; origem+cifra+envio ficam provados funcionalmente pelo `sendmsg` 5 B +
  `recv_0087` dst=injetado (o servidor aceitou e o cliente seguiu vivo), não pela observação do store.
- **Consequência para a §13:** existe agora uma **primitiva nativa de andar autônomo** disparável de
  um sítio de main-loop — relevante ao objetivo xKore 0 (AGENTS.md). Falta: reprodução (determinismo)
  e comparação com a via de relay (merge pré-XOR em `gepard+0x18eff2`). Ver §13.9/§13.8 p/ o contraste
  de fase que levou aqui.

### 1b. Correções de conclusões fortes já pedidas pelo Orquestrador (verificar se aplicadas)
- **§13.7:** rebaixar "Stalker/HW BP não são detectáveis" de FATO para **RELATO do responsável
  (NÃO VERIFICADO em geral)**; "colisão no byte verificado" = **INFERIDO**, não observado por
  instrumento (o probe não identificou o byte). Alerta/encerramento do Gepard = RELATO.
  (STATE.md do MOVER já foi reclassificado; conferir se o doc acompanha.)
- **§13.5:** "pacote montado" deve ser **"conteúdo compatível observado no trap pré-store"**;
  `onEnter` precede a execução de poll; remover frase de §13.4 contradita por §13.5
  ("faltava só a ABI/pilha correta"). Imbalance de pilha = REFUTADO como causa única, não toda ABI.
- Reconciliar divergência §13.5 (assertiva) × `RESEARCH_STATUS.md` (limites corretos): vale o
  método/cobertura, não a frase mais recente.

## 2. CIFRA — integrar em `docs/CIPHER_INVESTIGATION.md`
Fonte: `research/cipher/HANDOFF.md` (`CIFRA-20261015-CL-01`) e `STATE.md`. CIFRA está sem tokens.
- Carga em `+0x1C7502` define CL; cadeia de cópias até store `+0x1C752B` (13 pontos, ECX estável,
  origem `EBP+0x36`) = OBSERVADO. POP candidato em `+0x1C70DC` = **candidato por decode reverso**,
  prova antes/depois **PENDENTE**.
- XOR local em `+0x2689FB` = OBSERVADO por operandos; **não** identificado como cifra; sem consumidor
  associado. **Retirar** qualquer atribuição automática do XOR ao byte final.
- Direção, pacote, fronteira F, estado, inicialização e vetores independentes = DESCONHECIDOS.
- Conferir as edições já em curso em CIPHER_INVESTIGATION/CIPHER_TOOLS contra esses limites.

## 3. Índice e panorama
- `docs/RESEARCH_EVIDENCE_INDEX.md`: apontar os artefatos privados por rodada (caminhos, não conteúdo).
- `docs/RESEARCH_STATUS.md`: refletir rodada 04 (dependência de fase OBSERVADA; movimento autônomo
  ainda **não** validado) e o estado da cifra. Sem elevar relato a prova.

## 4. Kit `ro-ops` (follow-up do Orquestrador)
Citar o kit em `docs/CODEX_WORKFLOW.md` (e, se couber, `docs/OPERATIONS.md`): CLI read-only
`ro-ops` com 5 subcomandos (`discover`, `new-artifact`, `sample-thread`, `scaffold-state`,
`env-check`), contrato JSON `{cmd,status,data,caveats}` + exit codes 0/10/20/1, skill em
`.agents/skills/ro-ops/`. Deixar explícito que **não autoriza experimento** e que
`env-check` **não** prova exclusividade da janela. Commit `b003b1d`.

## 5. Devolução ao Orquestrador
Por rodada incorporada: ID, links e **no máximo três divergências** que exijam decisão humana.
Não fazer nova reorganização geral. Se faltar evidência, devolver pergunta específica ao autor
(MOVER/CIFRA) e registrar a limitação — não preencher por conta própria.
<!-- END ORIGINAL research/DOCUMENTADOR_BACKLOG.md -->

<a id="source-research-handoff-orquestrador-codex-md"></a>

## Fonte original: `research/HANDOFF_ORQUESTRADOR_CODEX.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `0c346d486b8b6e74f030d2059619789ad21c2eb1` · caracteres: 6214.

<!-- BEGIN ORIGINAL research/HANDOFF_ORQUESTRADOR_CODEX.md -->
# HANDOFF — OrquestradorCLAUDE → Orquestrador Codex — ORCH-20261016-01

_2026-10-16. Entrega por arquivo (sessões Codex sem tokens/inalcançáveis por mensagem).
Segue `research/COORDINATION.md` (Entrega ao documentador / Relatórios). Sem dados crus nem
credenciais. Preservar este handoff até incorporação/decisão do orquestrador._

## Resumo de decisão (≤200 palavras)

Executei o plano aprovado `/.claude/plans/abundant-frolicking-aho.md`: **PoC de movimento integrado
ao relay/agent de produção, dirigido pelo OpenKore**. Um `035F` (CZ_REQUEST_MOVE) do consumidor passa
a acionar o **dispatcher nativo do cliente** (método do MOVER, §13.10), que monta/cifra/envia o
próprio `035F`; o servidor responde `0087` e o cliente fica vivo. O relay **não** fabrica corpo
cifrado nem reencaminha o `035F` original (dropado). **FUNCIONOU LIVE (2026-10-16), uma vez**,
dirigido por OpenKore. Como efeito colateral do mesmo caminho de inject-call, corrigi uma divergência
de pacotes de controle: o `0368` pré-select que o relay injetava antes de ações com alvo impedia
ataque `0437`/perícia `0438` (sentar `0437` com GID=0 sempre funcionou); agora é opt-in
(`--target-select`, default OFF).

**Autorizações usadas:** edição de `agent/` + `relay/` (decisão humana no plano); teste live no
servidor próprio do responsável. **Nada commitado** — mudanças em working tree. Push/commit continuam
bloqueados pelo classificador de auto-mode para o assistente; o responsável roda manualmente.
Documentação canônica já integrada por mim (abaixo).

## Rodada 09 — PoC relay `035F` → dispatcher nativo

- **ID:** ORCH-20261016-01a
- **Revisão executada:** working tree sobre `6c20733` (HEAD); `.py`/`.js` não commitados.
- **Pergunta:** o relay consegue produzir o `035F` do cliente via dispatcher nativo, dirigido pelo
  OpenKore, sem conhecer a cifra?
- **Condições:** build MATCH (`uaRO.exe f2f2…9569`, `gepard` base `0x76920000`); cliente PID 3520569
  porta 27053 (Wine); OpenKore XKore 1 porta 2350; servidor próprio.
- **Resultado observado:** `035F` do consumidor → `unpack_move` → dispatcher `0xd473b0` (fire-site
  `0x4dcba0`) → `035F` original dropado → `recv_0087 dst=destino` → cliente VIVO. 4 critérios = SIM.
- **Interpretação:** **OBSERVADO** (uma vez, live). A cifra **não** está compreendida — o relay só
  decide o destino; geração de keystream antes do XOR segue **DESCONHECIDA** (§13.8).
- **Rival:** nenhum resultado concorrente; falta reprodução multi-sessão (determinismo).
- **Cobertura/perdas:** `store_035f` do scrambler não observado (DRs ocupados por outros slots);
  origem+cifra+envio provados **funcionalmente** por `sendmsg`+`recv_0087`.
- **Evidências:** roteamento `relay/writeback.py:243,249`; `_arm` soma move_dispatch+inject_call
  `relay/writeback.py:101-107`; `relay/packets.py:119` `unpack_move`; `relay/protocol.py:106`
  `move_dispatch_msg`; agent `agent/relay_hook_linux.js:435,647-752` (`MD_RECIPES['walk-035f']`);
  flags `relay/cli.py:85,89,90`. Docs: `docs/MOVEMENT_035F_PRECONDITIONS.md` §13.11;
  `docs/RESEARCH_EVIDENCE_INDEX.md` M-12; `docs/RESEARCH_STATUS.md` M-12.
- **Orçamento DR (4/4):** DR0 scramble · DR1 SendPacket · DR2 captura `this` · DR3 fire-site →
  `--no-send-watch` obrigatório.
- **Invocação (rodada pelo responsável):**
  `./run.sh --inject --inject-call --move-dispatch --no-send-watch --out <dir>/relay_log.jsonl`
  (`--out` = arquivo; criar o dir antes).
- **Testes:** `bash scripts/test-offline.sh` PASS (11 scripts; inclui `move-dispatch routing ok`);
  `node --check agent/relay_hook_linux.js` PASS; `python3 scripts/validate-research.py` PASS.
- **Limpeza:** detach/unload ao Ctrl-C; DRs desarmados em `doFire`/dispose. `this` recapturado por
  sessão (relogin invalida PID/base/heap).

## Rodada 09b — pacotes de controle `0437`/`0438` × `0368` pré-select

- **ID:** ORCH-20261016-01b
- **Pergunta:** por que ataque `0437`/perícia `0438` não disparavam, enquanto sentar `0437` sim?
- **Resultado observado:** a única divergência era o `0368` (CZ_REQNAME_BYGID, pedido de nome por
  GID) que o relay injetava antes de ações com alvo. Responsável confirmou live: *sem* o `0368`, o
  `sendmsg` da ação sai. Sentar (GID=0) nunca emitia `0368`.
- **Interpretação:** envio sem `0368` = **OBSERVADO**; **execução completa** (dano/efeito) =
  **NÃO VERIFICADO** (re-teste live pendente).
- **Rival:** H-CIPHER-01 (falha por cobertura de cifra do `0438`) — **não refutada**, mas deixa de
  ser a única hipótese; a divergência OBSERVADA era a injeção do `0368`.
- **Evidências:** `relay/writeback.py:266,283` (gate `target_select`), `:31` (`0368` em `SKIP_IDS`);
  flag `relay/cli.py:80`; `tests/test_writeback.py` (default sem `0368`; caso `target_select=True`).
  Docs: `docs/GEPARD_CONTROL_PACKETS.md` (seção "Achado — `0368` pré-select…").
- **Testes:** cobertos pelo `test-offline.sh` PASS acima.
- **Limpeza:** n/a (mudança de código; sem sonda viva adicional).

## Arquivos alterados (working tree, NÃO commitados)

`agent/relay_hook_linux.js`, `relay/cli.py`, `relay/console.py`, `relay/packets.py`,
`relay/protocol.py`, `relay/writeback.py`, `tests/test_writeback.py`. Docs editados por mim
(autorizados pela tarefa de documentação): `docs/MOVEMENT_035F_PRECONDITIONS.md`,
`docs/RESEARCH_STATUS.md`, `docs/RESEARCH_EVIDENCE_INDEX.md`, `docs/GEPARD_CONTROL_PACKETS.md`,
`docs/OPERATIONS.md`. Sonda externa não versionável: `research/action_0437_0438/` (gerada).

## Próxima decisão para o orquestrador

1. **Re-teste live** de ataque `0437`/perícia `0438` (Ctrl-C + mesma invocação) para mover a execução
   completa de NÃO VERIFICADO → OBSERVADO. Owner sugerido: MOVER ou implementer, servidor próprio.
2. **Reprodução** de 06b/09 para avaliar determinismo (prioridade F.1 do RESEARCH_STATUS).
3. **Comparar** PoC do dispatcher nativo vs. via de relay (merge pré-XOR `gepard+0x18eff2`) e decidir
   a entrega realista rumo a xKore 0.
4. **Commit local** de movimento + controle (código) quando o responsável autorizar; push manual
   pelo responsável (classificador bloqueia o assistente). Caminhos explícitos acima.
5. Novos pacotes = +1 entrada em `MD_RECIPES` (costura de extensão mínima já existe) conforme o MOVER
   mapear dispatcher+frame de cada ação.
<!-- END ORIGINAL research/HANDOFF_ORQUESTRADOR_CODEX.md -->

<a id="source-research-orchestrator-resume-20261016-md"></a>

## Fonte original: `research/ORCHESTRATOR_RESUME_20261016.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `699ffcc8eb3f08d4bad583a7e7c88b92fd59bf30` · caracteres: 3726.

<!-- BEGIN ORIGINAL research/ORCHESTRATOR_RESUME_20261016.md -->
# ORCH-20261016-02 — retomada CIFRA

## Mandato atual e execução

O responsável pediu nesta sessão que o orquestrador continuasse orientando CIFRA
enquanto dorme, autorizando comandos bash/git não destrutivos e acesso fora da
sandbox necessário à tarefa. Isso não remove controles técnicos de aprovação.
Escopo delegado: investigação cliente da cifra, preparação/testes e experimentos
delimitados; preservar processos/instrumentos de terceiros e alterações concorrentes.
Não se solicitou publicação nem alteração destrutiva.

As primeiras mensagens foram entregues a CIFRA e Documentador. Mensagens posteriores
foram recusadas pelo controle da ferramenta (`approval policy is never`), inclusive
o esclarecimento do mandato. Este arquivo registra o plano para retomada; não é
confirmação de entrega dessas mensagens nem de execução de experimento.

## Lições transferidas

- MOVER 06b e reprodução 08: disparo de sítio main-loop PE, distinto de read/wineserver,
  com retorno, envio e resposta correspondente. O mecanismo específico de reentrância
  não é demonstrado apenas por essa comparação. Ver STATE MOVER, rodada08, e docs §13.10.
- Rodada09: integração OpenKore/relay relatada uma vez, docs §13.11 e
  `research/HANDOFF_ORQUESTRADOR_CODEX.md`. O cliente continua gerando o pacote;
  sucesso funcional não revela gerador, estado ou inicialização da cifra.
- Relay move-dispatch pode ocupar os quatro DRs. STATE de action_0437_0438 admite
  sobreposição DR0/DR1: esse experimento não valida coexistência de sondas.
- XOR final descrito pelo relay e XOR local observado em CIFRA são evidências distintas.
  Não associar o XOR local ao byte final quando houve escritas intervenientes.

## Verificação operacional desta retomada

`ro_ops discover` na sandbox não viu cliente; no host confirmou uaRO PID3545097,
Gadget27053, starttime115742192. Identidade vale só para essa consulta.
Consulta posterior somente de nomes/PIDs no host não encontrou processos dos scripts
relay_capture_linux.py, chain_capture.py, dispatcher_trial_pesite.py,
observe_dispatch_codes.py ou openkore.pl. Isso não prova exclusividade nem ausência
de hooks residuais. Nenhum instrumento/processo foi alterado pelo orquestrador.

## Próximo contrato CIFRA

Confirmar POP `gepard+0x1C70DC` antes/depois e consumidor na mesma ocorrência.
Selecionar endereço em contexto atual; preservar EDX e operando da pilha antes de
sobrescrita. Não reutilizar heap/estado de outra sessão. Demonstrar a associação
apesar de escritas intervenientes dentro da cobertura; registrar limitações por thread.

CIFRA informou preparação de referência apenas de código, mesma build/RVA, seleção
EDX==EBP+0x36 no hit atual e watchpoint fora dos mapas ESP. Testes precedem coleta.
Essa preparação não é evidência de POP executado. Se recursos estiverem ocupados ou
limpeza for incerta, continuar offline e registrar o recurso concreto pendente.

Documentador recebeu solicitação de lições e integração do próximo HANDOFF. Manter
ownership: CIFRA em research/cipher e teste próprio; Documentador em docs; nenhuma
edição de produção nesta tarefa. Entregar resultado curto com cobertura e limpeza.

## Revisão independente offline

Verifier revisou somente o cl-producer presente no checkout: preserva EDX e [ESP],
verifica EDX e ESP+4, e tenta associar consumidor (`chain_probe.js:295`,
`chain_audit.py:214`). Não encontrou bug comprovado nesse recorte. `python3
tests/test_cipher_research.py`: PASS, 53 testes. Preflight sem hits não demonstra
POP real. A variante de referência apenas de código anunciada por CIFRA ainda não
estava no checkout revisado: não herda essa validação. Teste recomendado para ela:
POP pré/pós + consumidor e rejeição de divergência EDX/ESP/endereço.
<!-- END ORIGINAL research/ORCHESTRATOR_RESUME_20261016.md -->

<a id="source-ro-ops-handoff-md"></a>

## Fonte original: `ro_ops/HANDOFF.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `d11f0791caaf1d2d2dfe6762e4bccdf01a7d5956` · caracteres: 2408.

<!-- BEGIN ORIGINAL ro_ops/HANDOFF.md -->
# HANDOFF — ro_ops — RO-OPS-20261015-01

Revisao: base `4354615` + working tree (nao commitado). Pergunta: kit operacional fase 1 offline.

**Entregues (5):** discover, sample-thread, env-check (read-only); new-artifact, scaffold-state
(private-write). `verify-build`/`validate` NAO implementados (Fase 2; teste exige exit 1).
Contrato `{cmd,status,data,caveats}`, exit 0/10/20/1: `ro_ops/contract.py:6-14`, `make`/`emit`.
Extra fora da lista: `ro_ops/common.py` (git, sha256, starttime) e `ro_ops/HANDOFF.md`.

**Reuso:** `relay/agent.py:13` gadget_ports e `:41` pid_of_port (sem reparse de `ss`; `ro_ops/discover.py:9-16,54`);
main_tid em /proc/<pid>/task (`discover.py:27`). `research/movement_035f/sample_thread.py:25,60,73`
(read_state/sample_series/classify) carregado por importlib, sem copia (`ro_ops/sample.py:11-16`).
Espirito de `tools_sha256` (`research/cipher/chain_capture.py:389`) e `_hash_copy`
(`research/movement_035f/dispatcher_trial_onleave.py:278`) em `ro_ops/artifact.py` (copia + sha256 + PROVENANCE.txt 0600, dir 0700).

**Garantias medidas por teste:** exclusividade sempre `not_determined`; multiplos gadgets,
ss ausente, corrida pid_of_port ou /proc/task ilegivel -> undetermined; `worst()` nunca promove
undetermined; chaves de credencial/trafego rejeitadas; escrita no repo so em `research/<trilha>/`
(docs/, relay/, agent/, scripts/, .codex, tests recusados), sem overwrite nem symlink.

**Cobertura:** `python3 tests/test_ro_ops.py` 31 testes PASS com doubles (4 status, exit 0/10/20/1).
`validate-research.py`, `validate-codex.py`, `scripts/test-offline.sh` (11 scripts) e `git diff --check`: PASS.

**NOT RUN (prova viva):** `sample-thread` contra a thread do cliente real; validacao do classificador
no cliente ocioso (pendencia de STATE MOVER); `discover` com gadget uaRO real so foi consultado de forma
read-only de passagem, sem teste automatizado; Win32 main thread != tid lider nao verificado.

**Codex:** descobre skills em `.agents/skills/*/SKILL.md` (validate-codex.py:16); `ro-ops` la, com
espelho `.claude/skills/ro-ops` (symlink exigido por validate-codex.py:28-30). `.codex/config.toml`
nao lista skills (so `[skills] max_context_tokens`), logo nada alterado. Execucao pelo Codex
(sandbox workspace-write, sem rede) nao testada. Documentador: citar o kit em docs/CODEX_WORKFLOW.md.

Limpeza: nenhum processo/recurso ativo; nada fora destes caminhos foi escrito.
<!-- END ORIGINAL ro_ops/HANDOFF.md -->

<a id="source-architecture-md"></a>

## Fonte original: `ARCHITECTURE.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `1f93ecbccd1a9832b617e3c8319bca3e9242b1c3` · caracteres: 730.

<!-- BEGIN ORIGINAL ARCHITECTURE.md -->
# Arquitetura — documentação centralizada

A [arquitetura atual](docs/ARCHITECTURE.md), o [estado das pesquisas](docs/RESEARCH_STATUS.md)
e o [índice técnico](docs/README.md) são as entradas canônicas.

O conteúdo anterior, incluindo §§1–13, mapas, ABI e experimentos, foi preservado em
[arquitetura histórica](docs/HISTORY/ARCHITECTURE_LEGACY.md).
Referências antigas a §§5–13 deste caminho correspondem às seções desse arquivo histórico.

A identificação Themida/WinLicense e VMProtect recebida pelo pull foi integrada à
[arquitetura atual §12](docs/ARCHITECTURE.md#12-proteções-identificadas-no-build-atual--conteúdo-integrado-pelo-pull),
com os detalhes em [PROTECTION_FINGERPRINT_DIE.md](docs/PROTECTION_FINGERPRINT_DIE.md).
<!-- END ORIGINAL ARCHITECTURE.md -->

<a id="source-gepard-investigation-md"></a>

## Fonte original: `gepard_investigation.md`

Commit-base: `ca338500e678d51f14982d5da3ed58c023a5ba49` · blob: `a646e3f0bc52268fd806e71d1f3689fdf2f85681` · caracteres: 559.

<!-- BEGIN ORIGINAL gepard_investigation.md -->
# Investigação Gepard — documentação centralizada

Consulte [cifra atual](docs/CIPHER_INVESTIGATION.md),
[controle e sessão](docs/GEPARD_CONTROL_PACKETS.md) e [estado atual](docs/RESEARCH_STATUS.md).

As notas anteriores, incluindo assembly, constantes de 2016, offsets e candidatos de perícia,
foram preservadas no [histórico Gepard sanitizado](docs/HISTORY/GEPARD_LEGACY.md).
Referências antigas a §§1–8 correspondem às seções desse histórico; §§22–23 eram referências
obsoletas e não existem na revisão migrada. Dados de conta e endpoints foram removidos.
<!-- END ORIGINAL gepard_investigation.md -->
