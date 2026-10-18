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

## Frida Gadget: observação de entrada (rodada RC-20261018-02)

`recv_probe.py` instala temporariamente Interceptors em chamadas libc `recvmsg`, `__recvmsg64`, `recv` e `recvfrom`, apenas para registrar callsite, thread e quantidade de bytes. Não coleta payloads e exclui ruído conhecido XCB/Wayland. Tem teto de 80 eventos e duração máxima de 15 segundos; o script principal executa 8 segundos. O mecanismo **não** identifica ainda o escritor ou plaintext, nem arma watchpoint de dados. A execução é in-process através do Gadget (sem attach ptrace/CEserver). Arquivos em `artifacts/` são privados e ignorados pelo Git.

Na coleta inicial, o callsite `ntdll.so+0x980e8` apareceu 15 vezes após filtrar o ruído gráfico. Isto evidencia um caminho de recepção via Wine, **não** a rotina de decifragem do uaRO. A conclusão requer associação posterior aos pacotes cifrados.

## RC-20261018-03 — separação por descritor

Sonda ampliada para registrar somente número de FD e callsite, sem payload. Em 8 segundos: 54 recepções, das quais 46 no FD 194 via `ntdll.so+0x980e8` e 8 no FD 36 via `ntdll.so+0x4eb5e`. A classificação automática de tipo de FD retornou `unknown`; portanto **nenhum deles está comprovado como socket do jogo**. A classificação por caminho foi removida do hook para evitar acesso ao filesystem durante interceptação.
