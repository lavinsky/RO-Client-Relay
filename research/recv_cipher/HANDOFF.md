# Handoff — RC-20261018-01

**Pergunta:** Onde acontece a escrita final do texto claro recebido?

**Resultado:** Instrumentação de escrita ainda não executada; nenhum PC escritor identificado. Criada a trilha isolada com script de inventário e teste delimitado de depuração.

**Evidência:** `agent/relay_hook_linux.js` observa `recvmsg`; `relay/actors.py` usa o ring; `relay/cli.py` configura `--probe-at` como breakpoint de execução, não watchpoint de dados.

**Rival:** o plaintext pode ser montado em mais de uma rotina, ou escrito por múltiplas threads. Um watchpoint de um byte não estabelece cobertura total.

**Cobertura:** somente preparação, sem eventos do escritor. `run_probe.sh` precisa ser executado pelo responsável e suas saídas avaliadas.

**Limpeza:** nenhum recurso de depuração deixado armado por esta preparação.

**Próximo passo:** executar `bash research/recv_cipher/run_probe.sh`; em seguida planejar watchpoint de escrita dirigido e limitado.

## RC-20261018-02

- **Observado:** Frida Gadget conectado sem ptrace; 80 chamadas gráficas na primeira janela (5s). Após filtro, 15 chamadas `ntdll.so+0x980e8`, 3 PipeWire em 8s. Ambas limpas com `rpc stop` e `errors=0`.
- **Não verificado:** esses callsites decifram ou processam `09FD/09FF/0229`; são evidência somente de recepção da camada Wine.
- **Próxima discriminação:** identificar FD/socket e payload id de entrada sem dados privados persistidos; localizar a fronteira da cópia do ring antes de propor Interceptor de plaintext.

## RC-20261018-03

54 recepções via Frida, 46 FD 194/`ntdll.so+0x980e8` e 8 FD 36/`ntdll.so+0x4eb5e`, sem erro; classificação do FD inconclusiva. Não há prova de decifragem. Sonda passa a registrar apenas FD/callsite; classificar externamente por `/proc` antes de selecionar watchpoint.
