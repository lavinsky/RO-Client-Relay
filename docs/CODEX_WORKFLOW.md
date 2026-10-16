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
