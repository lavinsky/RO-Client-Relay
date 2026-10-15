# Inventário de fontes da consolidação

Revisão de origem: `87245d6491e6e27534ab6ada0b4d2cfe7225e43d`, branch `main`, 2026-10-15.
Inventário de arquivos rastreados via `git ls-files`; hashes abaixo são do conteúdo **antes**
da consolidação, obtido por `git show HEAD:caminho`. Não inventaria logs privados ou recursos
ignorados. Não houve leitura de memória/processo nesta manutenção.

## Markdown versionado de origem

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

## Documentação embutida e destinos por família

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

## Testes existentes e informação exclusiva de contrato

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

## Cronologia técnica conferida no Git

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

## Atualização após revisão do diff

A revisão subsequente usa `524b0f05fa61872e140f98ace9e503d12356641e` como HEAD.
Esse commit rastreou `research/movement_035f/dispatcher_trial.py` e acrescentou o ensaio
§13 às pré-condições. Os hashes da tabela inicial continuam descrevendo a origem em
`87245d6`, não o novo conteúdo. O panorama e o índice foram atualizados para o store
espontâneo sem retorno/envio confirmados; H2/H3 permanecem não isoladas.
`git pull --ff-only --no-rebase` concluiu com “Already up to date”; nenhuma branch de
pesquisa recém-descoberta foi mesclada nesta tarefa. O relatório DiE continua fora
da árvore de trabalho; disponibilidade de uma referência remota não valida seu conteúdo.

## Integração posterior solicitada

O pull de `origin/main@0a29193` incorporou o relatório `PROTECTION_FINGERPRINT_DIE.md` e
suas referências; a integração local `677e51e` preserva também `888764a`. A informação DiE
que chegou na arquitetura antiga foi conciliada em `docs/ARCHITECTURE.md` §12. A nota
anterior de relatório fora da árvore refere-se ao momento anterior a esse pull.

## Fonte experimental incluída por autorização de publicação

`research/movement_035f/dispatcher_trial13.py`: frame de 13 dwords, verificação do epílogo,
observadores de execução/transporte e registro incremental. A checagem antes de publicar
cobriu sintaxe Python/JS, não execução no cliente. Hashes dos módulos não são conferidos
automaticamente pelo script; parâmetros e endereços pertencem à build documentada.
