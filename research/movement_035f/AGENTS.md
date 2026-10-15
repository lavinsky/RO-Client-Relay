# MOVER — investigação de movimento 0x035F

Leia o AGENTS.md da raiz e `research/COORDINATION.md`. Estas instruções se aplicam
ao diretório; para trabalho em testes/docs, leia também as instruções desses locais.
Se o cliente de IA não carregar AGENTS.md automaticamente, leia-o explicitamente.

## Missão

Demonstrar as condições do movimento natural e identificar uma forma de solicitar
movimento que conclua normalmente, tenha envio/resposta associados e mantenha o
cliente responsivo. Não implementar bot/backend OpenKore, reconstruir a cifra ou
desvirtualizar todo o cliente. CIFRA cuida da transformação; documentador integra docs.

## Skills ativas (usar sempre que aplicável — Claude e Codex)
Ver a lista completa no AGENTS.md da raiz. Para a trilha de movimento, use especialmente:
- **`ro-ops`** antes de cada rodada ao vivo: `discover` (PID/porta/`main_tid`), `env-check`
  (confirmar limpeza antes de nova sonda), `new-artifact` (diretório privado + `PROVENANCE`),
  `sample-thread` (diagnóstico do travamento/abort), `scaffold-state` (manter STATE/HANDOFF). Não
  substitui a validação de ambiente/exclusividade nem autoriza experimento.
- **`repo-evidence`** para checar offset, símbolo ou regra sem reler todo o código.
- **`research-handoff`** ao fechar a rodada, separando OBSERVADO de HIPÓTESE.
- **`cheat-engine-cli`** (lado Claude) só para inspeção de memória autorizada; o responsável sobe o
  `ceserver`. Lembrete de memória: **sem HW watch de dados no slot de pilha do walk** (derruba o cliente).

## Retomada sem reconstruir todo o histórico

Mantenha `STATE.md` e `HANDOFF.md` conforme o protocolo. Na primeira adoção, reconcilie
uma única vez a rodada mais recente com os artefatos e o diff atual. Não assuma que
§13.5 continua sendo a última rodada: procure títulos posteriores e seu trabalho em
curso. Não execute uma sonda só porque você a escreveu em uma sessão anterior.

Comece cada rodada com uma pergunta e um resultado capaz de distinguir rivais.
Declare o que permanecerá controlado e o que mudará. Use evidência da versão realmente
executada; teste posterior de outra versão não valida retroativamente uma coleta.

## Regras para conclusões

- Separe conteúdo no trap pré-store, escrita concluída, pacote completo, envio
  solicitado, bytes aceitos, resposta associada e chegada ao destino.
- `sendmsg` é transporte observado, não fronteira automática de pacote/cifra.
  Recepção deve ser observada independentemente do store; associação vem depois.
- Os códigos 0x11/0x0D/0x5B/0x8A são internos. Objetos de dispatcher e receptor
  são distintos até prova em contrário. Endereços e objetos de sessão não são constantes.
- Comparar folha e dispatcher muda preparação e contexto: não isola H2/H3.
  Produzir coordenadas corretas não valida toda a ABI nem prova retorno/envio.
- A variante com 13 dwords também falhou no recorte documentado. Isso exclui a
  falta de oito bytes como explicação única, não toda falha de ABI nem sua contribuição
  na variante antiga. Confirmar o caminho executado, não apenas um epílogo estático.
- Ausência de evento é ausência observada dentro da cobertura. Ausência de
  `native_exception` não prova ausência de toda exceção. Silêncio não prova deadlock.
- Desarmar HW breakpoints não elimina outros hooks, trampolins ou interferências.
  `onEnter` de poll/select precede a execução da função. Trocar o callback não prova
  eliminação da reentrância. Sucesso em outro ponto inicialmente prova dependência
  do contexto, não o mecanismo exato responsável.
- Envio/resposta podem ocorrer após o retorno por enfileiramento. Não limitar o
  critério de sucesso a `during_call`; demonstrar a associação e sua janela.
- Trap pré-store com destino pedido não prova montagem concluída. Coordenada+delta
  não garante tile caminhável. Presença de protetor não prova VM naquele callsite.
- Não afirmar necessidade, suficiência ou refutação global por teste que muda várias
  condições. Nomeie a explicação específica excluída e mantenha os demais rivais.

## Próximas rodadas

Parta da última evidência disponível, não de um plano antigo. Se ainda houver
congelamento, o próximo ensaio deve localizar ou distinguir a falha, inclusive se
o callback JS parar de responder. Prepare diagnóstico independente quando necessário.
Não repita chamadas que congelam sem um discriminador novo. Uma mudança de ponto de
chamada precisa de evidência natural sobre thread, contexto e condições de entrada.

Antes de cada coleta, validar ambiente e exclusividade, versão da sonda e mecanismo
de parada/limpeza. Escolher limites explícitos de tempo/eventos/bytes. Preservar
observações parciais e perdas; não preencher lacunas. Parar novas tentativas se a
limpeza falhar. Recuperação/relogin deve seguir o escopo autorizado pelo responsável.

## Entregas e limites

Propriedade: este diretório e `tests/test_movement_preconditions.py`. Não editar
arquivos de CIFRA, produção/configuração ou docs compartilhados por conveniência.
Entregar alterações científicas ao documentador via HANDOFF com evidências citadas.
Não renomear todos os scripts nem criar framework genérico para resolver uma rodada.
Testar alterações pertinentes, incluindo análise de observabilidade e falhas quando
relevante. Registrar PASS/FAIL/NOT RUN sem confundir testes sintéticos e prova viva.
Não fazer commit/push/PR sem autorização aplicável; permissões antigas de uma entrega
não são mandato permanente para publicação.

Quando concluir, entregar o resumo curto do protocolo e uma próxima decisão concreta.
Se houver conflito entre docs, código e artefato, sinalizar exatamente a divergência;
não escolher a narrativa mais favorável nem editar memória para fazê-la parecer provada.
