# Handoff — RC-20261018-01

**Pergunta:** Onde acontece a escrita final do texto claro recebido?

**Resultado:** Instrumentação de escrita ainda não executada; nenhum PC escritor identificado. Criada a trilha isolada com script de inventário e teste delimitado de depuração.

**Evidência:** `agent/relay_hook_linux.js` observa `recvmsg`; `relay/actors.py` usa o ring; `relay/cli.py` configura `--probe-at` como breakpoint de execução, não watchpoint de dados.

**Rival:** o plaintext pode ser montado em mais de uma rotina, ou escrito por múltiplas threads. Um watchpoint de um byte não estabelece cobertura total.

**Cobertura:** somente preparação, sem eventos do escritor. `run_probe.sh` precisa ser executado pelo responsável e suas saídas avaliadas.

**Limpeza:** nenhum recurso de depuração deixado armado por esta preparação.

**Próximo passo:** executar `bash research/recv_cipher/run_probe.sh`; em seguida planejar watchpoint de escrita dirigido e limitado.
