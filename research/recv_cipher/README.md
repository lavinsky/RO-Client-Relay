# Pesquisa: plaintext na recepção cifrada

Trilha isolada para localizar a fronteira de texto claro dos pacotes de entrada (`0x09FD`, `0x09FF`, `0x0229` e outros ainda não identificados), sem alterar o relay de produção.

## Execução

Com uaRO aberto, relay fechado e CEserver ativo:

```bash
bash research/recv_cipher/run_probe.sh
```

O script identifica PID e início da instância, verifica CEserver e identidade (PID + tempo de inicio) do processo Wine/Proton, registra apenas inventário do processo via `/proc` e grava evidência privada em `artifacts/<data-hora>/`. Não instala `Interceptor`, breakpoint de execução ou watchpoint, nem identifica por si só o escritor do plaintext.

## Próximo experimento

Usar um watchpoint **de escrita** em byte do corpo de um pacote cifrado confirmado enquanto ocorre uma recepção real. Registrar PC/thread, endereço, valor antes/depois, instante e relação com `recvmsg`, mantendo limite de eventos e limpeza comprovada. Somente depois utilizar `--probe-at <PC>` para examinar uma rotina candidata. Não usar endereço do ring como endereço de função. A instrumentação deste experimento ainda não foi implementada/validada.

As capturas são confidenciais: não versionar dumps, IPs, nomes ou payloads reais.

O cache `.relay_actor_ring` é deliberadamente ignorado após reinícios: a região precisa ser redescoberta na nova instância antes de qualquer watchpoint. **Proibido nesta trilha:** `cecli debug trace`, attach do depurador CEserver ou qualquer uso de `ptrace`, pois congela o cliente Wine/Proton.
