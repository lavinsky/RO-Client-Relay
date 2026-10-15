# RO-Client-Relay — instruções para agentes

## Missão e limites
- O **OpenKore** é uma aplicação Perl externa que decide ações, constrói pacotes e já implementa xKore. **Não** implemente outro backend xKore ou lógica de bot neste repositório.
- O **relay** recebe quadros do OpenKore, faz o encaminhamento pela interface do cliente uaRO e entrega ao OpenKore pacotes de recepção verificados em texto claro. Referência: `README.md`, `ARCHITECTURE.md` §§1–4.
- Objetivo de longo prazo: OpenKore sem cliente, em **xKore 0**. A pesquisa do relay/xKore 1 é intermediária. Uma futura integração independente do protocolo deve ser planejada como plugin **no projeto OpenKore**, não presumida como parte deste repositório.
- Prioridade atual de pesquisa: compreender a camada de decisão/preparação do movimento que origina `0x035F`. A arquitetura do roBrowserLegacy é uma **analogia, não comprovação** sobre uaRO.

## Fontes canônicas e invariantes
- Agente Frida: `agent/relay_hook_linux.js`; driver: `relay_capture_linux.py` e `relay/`. Veja `relay/protocol.py`, `relay/runtime.py`, `relay/wire_feed.py`, `relay/writeback.py`.
- Preserve ordem dos pacotes, identidade das conexões, enquadramento XKore `R`/`S`, concorrência e a política de não fabricar corpos decifrados. Preserve sanitização de credenciais e tráfego HTTP em `relay/safety.py`.
- `relay_capture.conf` mantém **intencionalmente** `inject = true` e `inject-call = true`; não altere sem decisão humana. O CLI possui defaults internos distintos.
- `relay/resources/`, gadgets baixados, logs, snapshots e `__pycache__` são artefatos externos/gerados; não edite nem versione.
- `gepard_investigation.md`, `HANDOFF.md` e `ARCHITECTURE.md` incluem hipóteses e offsets de sessões específicas; nenhuma nota histórica deve virar regra de protocolo sem teste reproduzível. O registro de pacotes é `docs/GEPARD_CONTROL_PACKETS.md`.

## Pesquisa e segurança
- Diferencie **OBSERVADO**, **INFERIDO**, **HIPÓTESE**, **NÃO VERIFICADO** e **REFUTADO**; indique origem, build/sessão e condições de refutação. Veja `docs/RESEARCH_DECISIONS.md`.
- Não inclua credenciais, tokens, identificadores de conta ou capturas de sessão cruas em documentos e commits. A investigação histórica de um servidor Gepard 2016 **não comprova** o comportamento do build atual.
- Nenhuma ação contra servidor externo está implicitamente autorizada pelo código ou pelos defaults; experimentos ao vivo exigem escopo explicitamente aprovado. Agentes só executam validação **offline** por padrão.

## Trabalho e testes
- Testes: `bash scripts/test-offline.sh` (replica `for t in tests/test_*.py; do python3 "$t" || break; done` do README).
- Documentação de pesquisa: `python3 scripts/validate-research.py`. Configuração Codex: `python3 scripts/validate-codex.py`.
- Execute testes pertinentes após alterações, e o conjunto offline completo antes de concluir alterações em `relay/` ou `agent/`. Não relate sucesso em cliente real com base em teste offline.
- Na ausência de banco de dados, migrações, formatter ou linter configurados, não invente comandos.
- Commits locais apenas após teste, com `git add <caminhos explícitos>`; não faça push/PR nem altere histórico sem autorização.

## Subagentes e economia de contexto
- Máximo de **dois subagentes simultâneos**. Use `explorer` (Luna) para leitura, `implementer` (Sol) para patches delimitados e `verifier` (Luna) para testes/revisão. Orquestrador cotidiano Sol; use `codex -m gpt-6-astra` para decisões complexas.
- Só delegue trabalho independente ou que economize contexto. Passe objetivo, caminhos, evidência disponível, teste de aceitação e limite de 150 palavras; exija referências `arquivo:linha`. Não encaminhe históricos ou logs completos.
- Meça consumo de contexto, tempo e correção por tarefa antes de afirmar que a divisão é mais eficiente.

## Relatório final
`Resultado | Arquivos alterados | Evidências (arquivo:linha) | Verificações (comando + PASS/FAIL/NOT RUN) | Hipóteses/risco | Commit local (ou nenhum) | Próxima decisão`

Instruções aninhadas são indicadas em `relay/`, `agent/` e `tests/` somente quando houver necessidades específicas que justifiquem arquivos adicionais.
