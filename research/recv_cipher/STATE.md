# Estado — recepção cifrada

- **Objetivo:** localizar a rotina que entrega plaintext completo após a decifragem e antes da reutilização do buffer.
- **Revisão executada:** ver `git rev-parse HEAD` na rodada local; nenhum experimento novo de escrita instrumentada realizado.
- **Fatos estabelecidos:** o relay observa `recvmsg`; `ActorDecrypt` consulta cópia no ring em memória; o endereço de ring é específico da instância, não uma função; `--probe-at` usa breakpoint de execução de disparo único.
- **Hipóteses:** existe um ponto de código comum após a transformação de `09FD`, `09FF` e `0229`. Não verificado.
- **Sondas:** `run_probe.sh` (PID uaRO.exe descoberto dinamicamente, guarda de identidade PID+starttime, inventário somente via `/proc`, sem `ptrace`, CEserver debugger ou watchpoint); infraestrutura de hardware em `research/cipher/chain_probe.js` (requer adaptação antes de usar na recepção).
- **Autorizações/limites:** não alterar produção; somente uma instância instrumentada de cada vez; preservar outros registros de debug.
- **Limpeza:** nenhum instrumento permanente criado por esta trilha.
- **Próxima etapa:** identificar PC escritor com watchpoint delimitado, após revisão de sua implementação e condições de desarme.

- **Restrição confirmada pelo responsável:** ptrace congela o cliente; não executar CEserver debug trace/attach ou sondas baseadas em ptrace.
