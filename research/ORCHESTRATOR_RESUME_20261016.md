# ORCH-20261016-02 — retomada CIFRA

## Mandato atual e execução

O responsável pediu nesta sessão que o orquestrador continuasse orientando CIFRA
enquanto dorme, autorizando comandos bash/git não destrutivos e acesso fora da
sandbox necessário à tarefa. Isso não remove controles técnicos de aprovação.
Escopo delegado: investigação cliente da cifra, preparação/testes e experimentos
delimitados; preservar processos/instrumentos de terceiros e alterações concorrentes.
Não se solicitou publicação nem alteração destrutiva.

As primeiras mensagens foram entregues a CIFRA e Documentador. Mensagens posteriores
foram recusadas pelo controle da ferramenta (`approval policy is never`), inclusive
o esclarecimento do mandato. Este arquivo registra o plano para retomada; não é
confirmação de entrega dessas mensagens nem de execução de experimento.

## Lições transferidas

- MOVER 06b e reprodução 08: disparo de sítio main-loop PE, distinto de read/wineserver,
  com retorno, envio e resposta correspondente. O mecanismo específico de reentrância
  não é demonstrado apenas por essa comparação. Ver STATE MOVER, rodada08, e docs §13.10.
- Rodada09: integração OpenKore/relay relatada uma vez, docs §13.11 e
  `research/HANDOFF_ORQUESTRADOR_CODEX.md`. O cliente continua gerando o pacote;
  sucesso funcional não revela gerador, estado ou inicialização da cifra.
- Relay move-dispatch pode ocupar os quatro DRs. STATE de action_0437_0438 admite
  sobreposição DR0/DR1: esse experimento não valida coexistência de sondas.
- XOR final descrito pelo relay e XOR local observado em CIFRA são evidências distintas.
  Não associar o XOR local ao byte final quando houve escritas intervenientes.

## Verificação operacional desta retomada

`ro_ops discover` na sandbox não viu cliente; no host confirmou uaRO PID3545097,
Gadget27053, starttime115742192. Identidade vale só para essa consulta.
Consulta posterior somente de nomes/PIDs no host não encontrou processos dos scripts
relay_capture_linux.py, chain_capture.py, dispatcher_trial_pesite.py,
observe_dispatch_codes.py ou openkore.pl. Isso não prova exclusividade nem ausência
de hooks residuais. Nenhum instrumento/processo foi alterado pelo orquestrador.

## Próximo contrato CIFRA

Confirmar POP `gepard+0x1C70DC` antes/depois e consumidor na mesma ocorrência.
Selecionar endereço em contexto atual; preservar EDX e operando da pilha antes de
sobrescrita. Não reutilizar heap/estado de outra sessão. Demonstrar a associação
apesar de escritas intervenientes dentro da cobertura; registrar limitações por thread.

CIFRA informou preparação de referência apenas de código, mesma build/RVA, seleção
EDX==EBP+0x36 no hit atual e watchpoint fora dos mapas ESP. Testes precedem coleta.
Essa preparação não é evidência de POP executado. Se recursos estiverem ocupados ou
limpeza for incerta, continuar offline e registrar o recurso concreto pendente.

Documentador recebeu solicitação de lições e integração do próximo HANDOFF. Manter
ownership: CIFRA em research/cipher e teste próprio; Documentador em docs; nenhuma
edição de produção nesta tarefa. Entregar resultado curto com cobertura e limpeza.

## Revisão independente offline

Verifier revisou somente o cl-producer presente no checkout: preserva EDX e [ESP],
verifica EDX e ESP+4, e tenta associar consumidor (`chain_probe.js:295`,
`chain_audit.py:214`). Não encontrou bug comprovado nesse recorte. `python3
tests/test_cipher_research.py`: PASS, 53 testes. Preflight sem hits não demonstra
POP real. A variante de referência apenas de código anunciada por CIFRA ainda não
estava no checkout revisado: não herda essa validação. Teste recomendado para ela:
POP pré/pós + consumidor e rejeição de divergência EDX/ESP/endereço.
