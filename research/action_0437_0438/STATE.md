# STATE — ação/perícia 0x0437 / 0x0438 (método MOVER aplicado)

_Trilha aberta 2026-10-16. Pergunta inicial: qual `code` do dispatcher `0xd473b0` origina 0x0437
(ação) e 0x0438 (perícia), análogo a `code 0x11 → 035f`? Evoluiu para: a ação/perícia podem ser
INJETADAS pela via nativa (como o PoC 035f)? Resposta curta: os codes de origem estão OBSERVADOS, mas
a injeção da perícia pela via nativa NÃO funciona do jeito testado (ver §Testes live)._

Classificação: **OBSERVADO** = medido ao vivo nesta build; **INFERIDO** = deduzido por sequência/cross-check;
**REFUTADO** = testado e negado; **RETIRADO** = afirmação minha anterior que não se sustenta.

---

## 1. Mapa code → pacote (OBSERVADO, ao vivo, read-only, corpos em claro conferindo com `relay/writeback.py`)

Captura com 2 HW exec BP (sem injeção): DR0 no dispatcher `0xd473b0` (lê `code=[esp+8]`, frame nos 13
dwords `[esp+4+4k]`), DR1 na `SendPacket(this,len,buf)` do cliente em **uaRO+0x816640 (VA `0xC16640`)**,
onde o pacote está EM CLARO antes do scrambler do Gepard (`mov [ecx],bl` em `gb+0x18eff2`). Tudo na main.

| ação (usuário) | dispatcher code | pacote CZ | corpo observado (hex) |
|---|---|---|---|
| andar | `0x11` (17) | 0x035f | frame `[0,17,0,X,0,Y,…]` (X,Y no próprio frame) |
| sentar/levantar | `0x1f` (31) | 0x0437 | `3704 <GID próprio> 02/03` (02=senta/03=levanta) |
| **atacar** | `0x28` (40) | **0x0437** | `3704 <GID> 07` (ação 07=ataque, GID≠0) |
| **usar perícia** | `0x2a` (42) | **0x0438** | `3804 0a00 0d00 <GID>` (nível 10, skill `0x0d`=13 Soul Strike) |
| selecionar alvo | `0x0a` (10) | (via 0x0368) | GID do alvo no frame arg3 |

Artefatos: `/tmp/claude-act-20261016-031147-sendpkt/observe.json` (map inicial);
`/tmp/claude-act-20261016-110249-soulstrike2/inject.json` (cast Soul Strike em claro = `3804 0a00 0d00 51c18e06`).
Sonda: `observe_dispatch_codes.py`.

## 2. ABI do dispatcher (OBSERVADO)
- `0x11` (move) carrega **X,Y no próprio frame** e comete sozinho.
- `0x28` (ataque) e `0x2a` (perícia) **NÃO levam args no frame** (`[0,40,0,0,…]` / `[0,42,0,0,…]`): leem
  **alvo/perícia correntes de estado global** montado por passos anteriores.
- Preparação (INFERIDO, por sequência + cross-check): `0x29` frame `[.,41,.,GID,.,13,…]` = seta skill id=13 + GID;
  `0x5a` frame `[.,90,.,10,…]` = seta nível=10; `0x0a` = seleciona alvo (GID). O corpo do 0438 (nível10/skill13)
  casa exatamente com `0x29`(skill13)+`0x5a`(nível10). **Cadeia de cast OBSERVADA: `0x29 → 0x5a → 0x2a`**
  (sem `0x0a` neste cast — o GID já vem embutido no frame do `0x29`; alvo também passou pela via do `0x0368`).

## 3. Caller imediato do dispatcher (OBSERVADO, sólido)
Em TODOS os codes, o retorno imediato na pilha (`[esp]`) é o **shim do Gepard `gepard+0xb2c251`** — o
Gepard relaia a chamada do dispatcher. (O PoC 035f contorna esse shim via `NativeFunction` direta e ainda
funciona, então o shim **não** é o bloqueio.)

## 4. Testes de INJEÇÃO nativa da perícia (ao vivo, autorizados) — resultado NEGATIVO
Método capture+replay: capturar os frames reais da conjuração do usuário e repeti-los via o mecanismo de
disparo do PoC 035f (captura passiva do `this`=ECX + chamada `thiscall` a partir do fire-site de main-loop
`0x4dcba0`). Sonda `inject_soulstrike_live.py`.
- **Rodada 1** (bug meu: replay de superset incluindo movimento `0x11` + code `0x00`): **CRASH** do cliente.
- **Rodada 2** (corrigido: allowlist estrita, cadeia congelada = `[0x29,0x5a,0x2a]`): as 3 chamadas retornaram
  (`0x29`→13, `0x5a`→17, `0x2a`→**0**) sem exceção, MAS **nenhum `0x0438` saiu na rede** (perícia NÃO conjurada)
  e o cliente **crashou de forma deferida** (chegou ao `DONE` aos 90s; caiu depois).
- **Conclusão (OBSERVADO):** disparar `0x29→0x5a→0x2a` do fire-site `0x4dcba0` é **inócuo** (`0x2a`→0, sem egress)
  **e instável**. Diferente do movimento (`0x11` carrega tudo e comete em segurança), o commit da perícia
  depende de estado/contexto que o handler de input natural monta e que esse disparo fora de contexto não tem.

## 5. REFUTADO e RETIRADO
- **REFUTADO (responsável, 2026-10-16):** a hipótese "o `0368` (CZ_REQNAME_BYGID) pré-ação era o bloqueio da
  SendPacket de 0437/0438" é FALSA. **Com ou sem `0368` o SendPacket SEMPRE ocorria**; o problema (ação sem
  efeito) é ANTERIOR ao `0368`, que foi tentativa que NÃO resolveu. Logo: rotear 0437/0438 pela SendPacket crua
  **não executa** a ação. A flag `--target-select` / `0368` em SKIP_IDS segue no código, mas NÃO é solução.
- **RETIRADO (meu erro, 2×):** as cadeias de chamadores obtidas por `Backtracer.FUZZY` e por walk de EBP. Ao
  validar no objdump, quase nenhum endereço é retorno de `call` genuíno (o "folha" `0x944002`/`0x943fda` cai
  dentro de um loop de 0x102 entradas após um `jb`; os "profundos" `0x874a40` [+3 após `call *0x98(eax)`],
  `0x874b32` [prólogo `push ebp;mov ebp,esp`+2], `0x874f0b` [após `mov`], `0x66baea` [prólogo SEH+0xa] não são
  retornos). As funções aqui não mantêm frame de EBP padrão (SEH/FPO) e o shim do Gepard provavelmente usa
  trampolim `ret`/`jmp`, quebrando a disciplina de pilha. **Toda afirmação de cadeia além do shim imediato fica
  RETIRADA**; o split "prepare vs commit" NÃO está provado.

## 6. Em aberto (o que resolver em seguida)
- **Sítio real que dispara o `0x2a`** e a **pré-condição/estado global** que ele lê (o que faz `0x2a` devolver 0
  fora de contexto). O stack-walk não resolve aqui.
- **Método proposto (read-only, ainda não feito):** *validated stack scan* — no BP do dispatcher, varrer a pilha
  e manter **só** os dwords `V` em `.text` do uaRO onde um `call` termina exatamente em `V` (checar bytes
  `V-5==E8` ou `V-6..-2` = `FF /2`), produzindo a cadeia de retornos VERDADEIRA sem depender de EBP. Alternativa:
  desmontar a partir de um frame comprovadamente genuíno; ou instrumentar o próprio shim para logar seu chamador.
- Se achado o sítio/precondição: avaliar injeção ou pela via natural (setar estado + disparar do sítio certo) ou
  por outra entrada. Movimento 035f segue funcionando como referência do padrão.

## 7. Ferramentas desta trilha (todas read-mostly; a de injeção só sob autorização direta)
- `observe_dispatch_codes.py` — map code→pacote (DR0 dispatcher + DR1 SendPacket). Read-only.
- `inject_soulstrike_live.py` — capture+replay da perícia (allowlist estrita; **disparo** — usar só sob OK direto).
- `capture_skill_callers.py` — caller via `Backtracer.FUZZY` (resultado RETIRADO — não confiável aqui).
- `capture_skill_ebp.py` — caller via EBP-walk (resultado RETIRADO — não confiável aqui).
- `debug_inventory.py` — (pré-existente da trilha; não alterado aqui).

## 8. Limpeza / limites
Todas as sondas finalizam com DR desarmado (DONE/stop); nenhuma sonda minha fica ativa. Build uaRO+gepard = MATCH.
Autorização direta do responsável para cada rodada ao vivo (servidor próprio). Não editei `docs/` nem
`relay/`/`agent/` — entrega ao Documentador via `HANDOFF.md`. Nenhum commit feito.
