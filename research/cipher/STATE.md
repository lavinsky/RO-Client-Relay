# CIFRA — estado operacional


<!-- CIPHER-SPECIALIST-REFERENCES-2026-10-17 -->

## Direção de pesquisa prioritária — variantes reais Gepard (2026-10-17)

**FONTE TÉCNICA ESPECIALIZADA — ALTA CONFIANÇA:** recebidos exemplos completos de duas variantes reais, de servidores distintos, de versões atuais do Gepard. A origem especializada não equivale a uma captura de uaRO; **não** desqualifica a validade dos exemplos. [Código e diferenças estruturais](../../docs/CIPHER_INVESTIGATION.md#cipher-specialist-20261017).

**Decisão:** antes de continuar perseguindo o byte de CL isoladamente, priorizar a **identificação da família/variante, inicializador e estado**: tabela mutável de 256 bytes, três posições, seed, constantes, lógica por byte, dependência do comprimento e sessões/unidades. A cadeia POP/STACK/SLICE-12 até candidata `EBP+0x09` continua resultado observado de transporte, **não é gerador criptográfico identificado**.

**Informação especializada:** valores/seed acessíveis em memória; rotina protegida por VMProtect; reconstrução baseada em hypervisor, entradas/saídas e templates aritméticos, com ferramenta especializada relatada na ordem de ~2 min. No build atual **não foi demonstrada** a correspondência do callsite/código virtualizado nem a variante A/B. A aplicação dessas informações ao uaRO segue por localizar, sem desmerecer o conhecimento recebido.

**Login:** o responsável já confirmou recebimento de valores relacionados à cifra no login. A interpretação de que sejam seeds dessa família é **hipótese de mapeamento** (ID/campos/consumo não verificados); não logar credenciais.

**Sequência de investigação proposta (somente planejamento documental, sem sonda nesta atualização):** (1) vetores sintéticos offline A/B, explicitando tipos, máscaras e hash; (2) assinaturas de ordem/índice/sinal/shift por operação; (3) seed recebida vs estado derivado; (4) vínculo login→inicializador→unidade/direção; (5) persistência e reset; (6) sync `0x8280` como dependência para xKore 0. **Nenhum vetor gerado nem cliente executado nesta revisão.**

**Condições para promoção a uaRO:** no mesmo build e sessão, obter operações/estado antes/depois para vetores independentes e dimensões de pacote distintas. Não usar constantes de A/B como constantes atuais do uaRO até essa correspondência. `resources/` não está disponível na árvore Git versionada revisada; eventual fonte local precisa ser apresentada antes de comparar.

**Histórico de execução abaixo:** estado anterior à mudança de prioridade; manter SLICE-12/limpeza/cotas/erros e pré-condições literalmente, sem tratá-los como conclusão da nova linha.
Atualizado em 2026-10-16 após SLICE-12; protocolo `research/COORDINATION.md`.

## Estado atual e próximo recorte

Usuário confirmou reinício e exclusividade após SLICE-12. /proc do alvo
antigo ausente, novo runtime em `inventory-session4.json`, dois hashes revalidados.
Não transportar heap/estado entre instâncias. A rodada compartilhada permanece
inválida para conclusões de cifra ou causa do travamento.

SLICE-12 concluiu gate experimental no quarto hit: 73 traps, 20 escritas destino
+0x36/14 fonte +0x57, duas trocas, 151 ms, 13 pontos CL, sem limites/perdas/erros.
Limpeza do coletor confirmada; nenhum instrumento próprio ativo.
Evidência `session4-slice-late4-1/{chain-capture,audit,candidate-slice}.json`.
Plano offline HIPÓTESE atravessou quatro transportes candidatos e parou em fonte
EBP+0x09 da candidata +0x256809 POP/EDI: primeiro POP não observado nesse byte.
Só o prefixo +13A194..+13A19A foi executado pré/pós dentro desta coleta; não
promover demais padrões reversos a fluxo provado.

Próximo: observar +0x09 mantendo associação ao consumidor e no máximo quatro DRs.
Não ampliar janela de 500 ms. Gate reduz cobertura inicial; contagem não é regra.

## Revisão e evidência atual

HEAD `6c20733ef0af42d8a618bba39a16322f316207db`, diffs locais em instrumentos;
revisão/digest do diff/hashes de fonte e script em cada `chain-capture.json`.
Raiz privada 0700 `/tmp/ro-cipher-resume-20261016/`; inventário validado nesta
conversa contra hashes dos dois módulos. Cliente reiniciado novamente pelo usuário; inventário novo
`inventory-session4.json`, sem continuidade de heap com capturas anteriores. Driver confere starttime/build antes de anexar.

`lineage-passive-and-1/chain-capture.json:DONE` e `audit.json`: coleta sem clique
solicitado/automatizado, seis trocas, 306 traps, destino 130 escritas, origem 120,
13 pontos CL, 414 ms de sequência, sem teto/discontinuidades/erros de leitura e
sem SCRIPT_ERROR; desarme automático/unload/detach confirmados pelo coletor.
Cobertura: uma thread, um byte de cada alvo, sem excluir outras threads.
Não atribuir a movimento: mecanismo any-chain, tráfego/direção não observados.

## Fatos e limites

- POP-03 e STACK-04 provaram transporte por pilha; STACK-04 tinha ESI==EDX.
- SOURCE-06 provou troca EBP+0x68→+0x36, mas houve 102 escritas posteriores.
- REPEAT-07 selecionou pela execução a última troca: fonte EBP+0x57, destino +0x36;
  seu byte permaneceu igual através das escritas cobertas até CL. Isso não é
  atribuição causal ao último escritor direto, nem identifica cifra.
- LINEAGE-08 associou última escrita observada em +0x57 à leitura da última troca;
  decode único +0x256889 POP/EAX é candidato nessa ocorrência; pré/pós local
  foi comprovado independentemente em UPSTREAM-09.
- XOR local anterior continua sem atribuição ao byte final; inicialização, estado,
  keystream e fronteira F permanecem desconhecidos.

## Autorização, instrumentos e limpeza

Mandato autônomo vigente; exclusividade restaurada explicitamente nesta conversa.
Perguntar prontidão antes do input manual. Preservar instrumentos de terceiros;
sem login/reinício automático, publicação ou commit.
`chain_capture.py`/`chain_probe.js`: 10 s de espera, 500 ms de sequência, 1000 traps,
256 KiB, até 256 escritas por alvo/32 trocas. Nenhum watchpoint stack.
`candidate_slice.py`: plano offline HIPÓTESE, até 32 arestas, para em lacuna/conflito.
Cache novo conserva apenas padrões de código e verifica oito bytes a cada uso;
registradores são atuais, com teste sintético de invalidação por mudança de bytes.

## Saúde e testes

Rodadas anteriores tinham TypeError após DONE. Trocar null por callback e evitar
RPC stop redundante não eliminaram erro. Desarmar antes do callback adiado, testado
com scheduler sintético adiado, foi seguido por LINEAGE-08 sem erro. Causa ainda
NÃO VERIFICADA; não validar retroativamente capturas anteriores.
63 testes próprios PASS; não validam segurança em cliente compartilhado.
Validadores serão registrados no HANDOFF. Sem commit/docs/produção.
