# RO Client Relay

Relay Python/Frida para depurar o fluxo de pacotes do cliente uaRO sob Wine/Proton 32 bits.
Entrega ao OpenKore externo em xKore 1 um fluxo ordenado, com corpos decifrados somente
quando verificados. A escrita opcional usa o próprio cliente. Objetivo final: xKore 0
sem cliente, com futura integração no projeto OpenKore.

- [Índice técnico e leitura por tarefa](docs/README.md)
- [Estado atual das pesquisas](docs/RESEARCH_STATUS.md)
- [Arquitetura](docs/ARCHITECTURE.md)
- [Operação, instalação e diagnóstico](docs/OPERATIONS.md)
- [Recuperação dinâmica de atores e evidências](docs/DYNAMIC_ACTOR_RING.md)
- [Observer read-only para roBrowser/UI externa](docs/RO_BROWSER_OBSERVER.md)
- [Resumo da auditoria e alterações locais de 2026-10-20](docs/RESEARCH_STATUS.md#revisão-do-checkout--2026-10-20)
- [Regras dos agentes](AGENTS.md)

## Setup rápido

Requer Linux, Python/Frida, Gadget de 32 bits e leitura de `/proc/<pid>/mem`.
Em ambiente autorizado, `./setup.sh` prepara o venv e imprime a opção Steam para o Gadget.
O OpenKore é instalado separadamente.

## Consumidor (OpenKore)

Configure seu xKore 1 conforme [operação](docs/OPERATIONS.md#openkore-e-enquadramento-xkore).
Com cliente e consumidor prontos, `./run.sh` usa `relay_capture.conf`;
`./run.sh --raw --no-inject` desativa escrita nessa execução (o wrapper normal não reconhece `--no-inject`). Os valores intencionais
`inject = true` e `inject-call = true` do arquivo permanecem preservados.
Na configuração atual, `035F` segue o dispatcher nativo e `0437`/`0438`/`0AF4` usam carriers com merge; a cifra independente permanece não resolvida.

## Testes

```sh
bash scripts/test-offline.sh
python3 scripts/validate-research.py
python3 scripts/validate-codex.py
```

Testes offline não comprovam funcionamento em cliente real. Histórico e mapa de migração
no [arquivo integral das auditorias](docs/HISTORY/STATUS_AND_AUDIT.md).
