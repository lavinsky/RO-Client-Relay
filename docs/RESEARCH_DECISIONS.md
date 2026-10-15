# Decisões e hipóteses de pesquisa (2026-10-15)

## Decisões confirmadas pelo responsável
- **Final:** usar OpenKore (Perl, externo) em xKore 0, sem cliente oficial.
- **Intermediário:** xKore 1 existente no OpenKore + RO-Client-Relay + cliente uaRO, para encaminhar texto claro e utilizar o cliente como executor do protocolo.
- **Padrões intencionais:** manter `inject = true` e `inject-call = true` em `relay_capture.conf`.
- **Prioridade:** investigar o fluxo que antecede e prepara o movimento `0x035F`; não limitar a pesquisa à função final de transmissão.
- **Futuro:** documentar os pacotes de controle e requisitos de sessão para avaliar um plugin no OpenKore; referência: `docs/GEPARD_CONTROL_PACKETS.md`.

## Hipóteses ativas, não decisões técnicas finais

| Hipótese | Base | Limitação / alternativa |
|---|---|---|
| A intenção de mover aciona uma cadeia de preparação antes do envio de `0x035F` | `ARCHITECTURE.md` §§9–10; analogia com roBrowserLegacy relatada pelo responsável | A analogia não prova equivalência entre implementações |
| A falha de `0x0438` está relacionada à cobertura/estado da cifra | Código servidor Gepard 2016 descrito em `gepard_investigation.md` §3; comportamento descrito em `HANDOFF.md` | Diferentes pré-condições de ação, parser e estado interno também podem explicar falhas |
| A sincronização do servidor é governada pelos estados de cifragem e mensagens de controle | Modelo do servidor 2016 | IDs, transições e algoritmos do build atual não estão completamente identificados |
| `0x8280` serve como heartbeat uaRO | `gepard_investigation.md` §3.3; entrada 128 bytes na tabela | Papel/direção e equivalência com `0x8285` histórico pendem de evidência específica |

## Evidência nova de movimento — coleta autorizada em 2026-10-15

Origem/build, método, artefatos e limites: `docs/MOVEMENT_035F_INVESTIGATION.md`.
Cliente uaRO e servidor próprio expressamente autorizados; primeira etapa manual,
seguida de cliques uinput e dois ensaios nativos delimitados. Código do relay/agente
não foi alterado.

- **OBSERVADO:** seis capturas manuais, três por instância do mesmo build, com
  códigos internos `0x11 → 0x0D → 0x5B` antes de `0x035F`. Por código, caso `0x11`
  emite os dois seguintes; `0x5B` tem gate numérico `0x15E` e repassa `0x8A` ao slot
  virtual atual `gepard+0x10A90`. São mensagens internas, não IDs de rede.
- **OBSERVADO na automação:** seis cliques alternados com `0x8A == 0x035F`; três
  controles de cursor sem clique sem correspondência. Duas rodadas adicionais de
  três cliques validaram ECX/objeto, argumentos `(0x8A,x,y,0,0)`, remoção de 20 bytes
  pelo callee e resposta `0x0087` com destino igual. `0x11` do dispatcher também
  recebeu esse destino e teve retorno imediato em Gepard+`0xB2C251`.
- **REFUTADO no recorte:** presença isolada das duas chamadas históricas ao wrapper
  `+0x875400` distingue intenção: ocorreram também em 3/3 controles de repouso.
  Isso não refuta sua participação no fluxo.
- **OBSERVADO / limite:** ensaio nativo revisado entrou em `0x8A` com argumentos
  corretos na thread principal e retornou, sem par store/resposta confirmado em 10 s.
  Não demonstra ausência de tráfego nem rejeição. Rivais: estado preparatório,
  contexto VM/callsite, efeito local ou cobertura da sonda. Nenhuma integração dessa
  chamada ao relay foi autorizada por evidência suficiente; controles UI seguintes passaram.
- **HIPÓTESE/próximo teste:** localizar a produção do destino anterior ao dispatcher
  pelo chamador real na VM em Gepard+`0xB2C251`. A entrada `(0x11,x,y,0,0)` em
  `0xc7650e` é outro candidato; uma amostra teve movimento/ACK sem hit nesse callsite
  antes do store. O elo permanece não confirmado. Os inteiros vêm do estado de entrada;
  inspeção de `0xa797b0` sustenta hit-test de UI no recorte, sem projeção demonstrada.
  Pontos fixos de tela mudaram de destino de mapa entre rodadas; não congelar o par.
- **NÃO VERIFICADO:** transformação completa, requisitos autossuficientes da chamada,
  unidade do gate, cobertura entre builds e protocolo suficiente para xKore 0.

## Método de atualização
1. Para cada afirmação, classificar: **OBSERVADO**, **INFERIDO**, **HIPÓTESE**, **NÃO VERIFICADO** ou **REFUTADO**.
2. Registrar prova/reprodução e versão. Uma análise histórica não demonstra o comportamento de builds posteriores.
3. Declarar pelo menos uma explicação rival e qual observação poderia refutar a hipótese.
4. Em handoffs, registrar somente conclusões e referências, sem copiar logs brutos nem dados de conta.
5. Resultados que dependam de cliente real/servidor externo devem indicar claramente se não foram reproduzidos em ambiente autorizado.

## Pendências humanas
- Determinar quais pacotes marcam estabelecimento e reinicialização de sessão no **build atual**.
- Decidir em qual repositório/estrutura manter um futuro plugin OpenKore e sua interface.
- Definir um protocolo de medição de economia de tokens: tarefas equivalentes, correção, retrabalho, duração e uso de franquia.
