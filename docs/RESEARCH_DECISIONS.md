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
