# Investigação de engenharia reversa — gepard do uaRO

Notas de RE do cliente uaRO (próprio) e do seu Gepard Shield, para o debug via Frida descrito em
`ARCHITECTURE.md`. Só o que foi **confirmado** e é **útil**; teorias refutadas foram removidas.
Contexto operacional e próximo passo ficam em `HANDOFF.md`; endereços e caminhos de escrita, em
`ARCHITECTURE.md` (§5, §6, §9).

---

## 1. Rede, servidor e conta

- Servidor `51.89.96.177`: login `6900`, char `6121`, mapa/jogo `5121`, API HTTP de config `3000`
  (POST `/userconfig/load`, `/charconfig/load` — JSON em texto claro).
- Backend do gepard: `server0.gepardshield.com` → `139.99.40.25:6700`.
- O **char server (6121) é RO padrão em texto claro** (sem camada gepard): fluxo
  `0x0065/0x082d/0x0187/0x0066/0x0ac5`.
- Login é por **HTTP/token** (porta 3000), **não** pelo pacote clássico `0x0064` usuário+senha:
  não há tráfego no login server (6900); a porta 3000 é HTTP (fragmentos `POST`/multipart); o
  usuário aparece em memória só como texto `user=lavinsky`. Logo `version`/`master_version` vivem
  no `clientinfo.xml`/login HTTP, não no fluxo de pacotes RO.
- Conta de referência: AID **2158435** = `0x0020EF63`.

## 2. serverType

Derivado do conjunto de pacotes servidor→cliente decodificados:
- IDs da era: `0x0B1A/0x0B1B`, `0x0ADF`, `0x0AFF`, `0x0AC5`, `0x0A30`, `0x082D`, `0x09FF/0x09FD/0x09FE`,
  `0x0ADD`, `0x01C8` → cliente RagexeRE 2020–2021.
- Layouts RECV batem com a família `RagexeRE_2020_03_04a` (ex.: `0x0ADD`=24B, `0x01C8`=15B,
  `0x009D`=19B, `0x0A37`=69B); o fluxo do mapa tokeniza 100% nessa tabela.
- **serverType = kRO RagexeRE 2020_03_04a .. 2021_11_03** (a família é RECV-idêntica; as diferenças
  entre os membros estão em pacotes de ENVIO e no tamanho do bloco de char). `RagexeRE_2021_11_03`
  configurado é consistente. `data/uaro_recvpackets.txt` (baseline OpenKore + os 4 pacotes de
  controle gepard) tokeniza 100% do tráfego real de mapa.

## 3. Modelo do gepard (fonte de referência de 2016)

`relay/resources/Gepard-SRC-LGP-master` é um rAthena com a integração gepard do **lado servidor**
(build `CODE_VERSION=2016122701`). As **constantes** desse build **não** valem para o uaRO (ver §4),
mas a **estrutura** vale. Tudo em `src/common/socket.cpp`/`.hpp`.

### 3.1 Cifra — stream cipher auto-modificante

```c
struct gepard_crypt_unit { unsigned int flag; unsigned char pos_1,pos_2,pos_3; unsigned char key[256]; };

void gepard_session_unit(unsigned seed, gepard_crypt_unit* u){        // 2016: tabela derivada da seed
    for (unsigned i=0;i<256;++i)
        u->key[i] = (((seed -= seed*SESSION_CONST_1 - SESSION_CONST_2*i) >> 15) & 0xFF);
    u->pos_1 = seed%20; u->pos_2 = seed%30; u->pos_3 = seed%50;
}
void gepard_enc_dec(unsigned char* data, uint32 n, gepard_crypt_unit* u){   // enc == dec (XOR)
    for (unsigned i=0;i<n;++i){
        u->pos_1 += u->key[u->pos_2]*ALGO_KEY_1;  u->key[u->pos_3] ^= u->pos_1;
        u->pos_2 += u->key[u->pos_3]*ALGO_KEY_2;  u->key[u->pos_1] ^= u->pos_2;
        u->pos_1 -= u->pos_3*ALGO_KEY_3;          data[i] ^= u->key[u->pos_3];   // saída = key[pos_3]
        u->pos_2 ^= u->pos_3 + (n%0xFF);          u->pos_3++;
    }
}
```
Três unidades por sessão: `recv_crypt`, `send_crypt`, `sync_crypt`. O keystream é **independente do
texto** (o dado só é XORado, não realimenta), **depende de `n` (tamanho)** e avança a cada byte. As
seeds vêm no `SC_GEPARD_INIT` em texto claro.

Constantes de 2016 (não casam com o uaRO): `SESSION_CONST_1=0x582B11D8`, `SESSION_CONST_2=0xB63EBE8B`,
`ALGO_KEY_1/2/3 = 0x2A/0x4E/0x5D`, `DATA_HASH_CONST_1=0xBD72F3DA`, `DATA_HASH_CONST_2=0xCD7972A4`.

### 3.2 A cifragem é SELETIVA por id e cobre só o CORPO (offset 2+)

`gepard_process_cs_packet` (cliente→servidor) só cifra/decifra: andar (`035f`), ação (`0437`),
perícia on-target (`0438`), perícia on-ground (`0af4`), login, sussurro (`0096`), `INIT_ACK` e `SYNC`.
IDs fora disso (ex.: `0368`, seleção de alvo) passam **em claro** — bate com o fio. O id (bytes 0–1)
e o campo de tamanho ficam em claro; só o corpo é cifrado.

### 3.3 Não há validação por-ação; `8280` é heartbeat

Para os ids de ação o servidor faz **apenas** `gepard_enc_dec(corpo, recv_crypt)` e deixa o rAthena
parsear — **sem hash, sem token, sem checagem**. A ação é aceita se e só se o corpo **decifra com o
`recv_crypt` na posição certa do stream**.

`CS_GEPARD_SYNC` (`0x8285` em 2016; `0x8280` no uaRO, 128 B) é **heartbeat**: corpo = constante
`0xDDCCBBAA` cifrada com `sync_crypt`; o servidor só confere a constante e atualiza um tick. **Não
libera ação.** (As strings "0.23"/"FEFA3"/"0x3020ffff"/`0x7a959568` vistas em memória são uma **tabela
interna do gepard**, não o payload do heartbeat.)

**Consequência:** a ação injetada crua falha por **sincronia de cifra** — o corpo precisa estar
cifrado com o `send_crypt` do cliente, na posição correta, com o mesmo `n`. O merge do `035f` funciona
justamente porque passa pela cifragem real do cliente, que avança o estado naturalmente.

## 4. A cifra no build atual (uaRO)

A `gepard.dll` é **VMProtect** (seções `.vmp*`); as constantes de 2016 não aparecem estaticamente e a
busca por elas não casou. Mas o estado vivo é observável em memória, e difere de 2016:

- **Tabela inicial = ramp fixo** `key[i]=rol8(i,2)` (`00 04 08 0c ...`), **não** derivada de seed. Ao
  vivo bate em ~130/256 (o resto já mutou). O único segredo por sessão é o pequeno estado de posições.
- **Word-based (16 bits):** bytes de `key` mudam em pares adjacentes; o build de 2016 é byte-a-byte.
- **Posições lineares e independentes do dado:** das 5 posições em `key[0]+0x100`, só `0x101` e `0x104`
  mudam durante a cifragem; `0x100/0x102/0x103` são constantes por sessão. Por palavra `j`:
  `0x104 += 1` (contador de palavras), `0x101 += 0x21`. Difere do passeio data-dependente de 2016.
- **A função por-palavra `f`** (como a tabela muta + índice de saída indireto, estilo RC4) **não foi
  resolvida** e não sai de snapshots de rede/antes-depois: a tabela muda a cada palavra e os índices
  no passo `j` dependem da tabela como está em `j`.
- **`gepard+0x18eff2` fica DEPOIS da geração do keystream** (é o XOR/store final, `88 19`
  `mov [ecx],bl`; `ecx`=ponteiro do dado, id em `ecx-2`). O traço por-byte ali mostra tabela/posições
  **estáticas** e nenhuma relação `db==key[pos]`, então esse ponto **não expõe `f`**. Resolver `f`
  exigiria achar a estrutura de estado real e as instruções que a mutam (RE profundo, sem garantia).

**Veredito:** "cifrar nós mesmos" (reproduzir a cifra offline) depende de `f` e **não vale o custo
agora**. Como a ação injetada só falha por sincronia (§3.3), a rota robusta é o **caminho 1**: chamar
a função do próprio cliente, que cifra+envia em sincronia (ver `HANDOFF.md`).

### Unidades em memória (sessão de referência; mudam a cada relog)

recv `key[0]=0x3efdd00`, send `key[0]=0x3efddd8`; posições em `key[0]+0x100`. Localizadas pontuando os
registradores do BP contra o ramp e varredura **externa** limitada. Ferramenta: `--scramble-trace N`
(ARCHITECTURE §8). **Varredura só externa** (`/proc/<pid>/mem`); varrer muita memória de dentro do
agente trava o cliente.

## 5. Caminhos de escrita e por que a ação injetada falhava

Detalhe em `ARCHITECTURE.md` §6. Resumo: dois caminhos, combinados por id —
- `035f` (andar): **merge** antes do XOR no BP de execução em `gepard+0x18eff2`. Reenviar `035f` pela
  `SendPacket` **dessincroniza a cifra** (becco sem saída confirmado).
- `0437/0438/0af4`: **`SendPacket`** do cliente (`uaRO.exe+0x816640`, `this` capturado no DR1).

Perícia on-target injetada não conjurava de forma confiável. O §3.3 explica: **não** era token de
validação faltando; era sincronia de cifra / a ação precisar partir do próprio cliente.

## 6. Feed recv para o consumidor (OpenKore, XKore 1)

- **Invariantes (verificados em 420/420 pacotes):** id (bytes 0–1) e campo de tamanho em texto claro;
  `len(claro)==len(cifrado)`. Por isso, mesmo um corpo não decodificado mantém o stream alinhado
  (só aquele corpo fica ilegível) — sem dessincronizar o tokenizador.
- O feed lê a cópia decifrada da **ring de recepção** do cliente (offset fixo `ring+0x40`) e a entrega
  em ordem; enquadra como quadros `R` (recv) e `S` (send observado) para o OpenKore.
- **Causa do crash do OpenKore:** entrar **no meio da sessão**. O OpenKore começa com listas de atores
  vazias; um pacote de status/efeito de um ator que ele nunca viu nascer → store em `{}` não-abençoado
  → fatal. **Não** é problema do feed. Fluxo correto: subir relay + OpenKore (interface Console) e
  **só então** logar o cliente, para o OpenKore ver login→mapa→spawns do início.

## 7. Risco de flag de conta (operacional, importante)

Após uma sessão instrumentada, um relogin falhou ("disconnected") mesmo com lançamento limpo (sem
gadget, sem hooks) — servidor no ar, portas acessíveis. Diagnóstico: provável **flag de conta/máquina**
do gepard ligada à sessão instrumentada (não é rede). O usuário considerou flag temporária que passa
com o tempo. **Tomar cuidado:** rodar instrumentação contra um cliente com gepard pode marcar a conta/
máquina, e a flag pode persistir além da sessão. Carregar o gadget só quando necessário; sessões
repetidas podem transformar flag temporária em permanente. Contornar a flag em si está fora de escopo.

## 8. Conclusão e próximo passo

- `8280` é heartbeat; não há validação por-ação; a falha da injeção é **sincronia de cifra** (§3.3).
- A cifra do build atual é ramp-fixo + posições lineares, mas `f` fica sem solução barata (§4).
- **Rota robusta: caminho 1** — chamar a função de perícia on-target do próprio cliente (estende o
  `--inject-call`), que gera o keystream correto sozinho. Passo e riscos em `HANDOFF.md`.
  
  9# Novas descobertas (NÃO CONFIAVEL, VERIFICAR)
  
    ### Cadeia Mapeada da Perícia no uaRO

  A desmontagem do binário cruzada com o traço revelou 3 camadas bem delimitadas:

  ┌────────────────────────────────────────────────────┐
  │                                                    │
  │              1. Evento de Clique / UI              │
  │                                                    │
  │           uaRO+0x9b7100 (MainWindowProc)           │
  │                                                    │
  │                         ↓                          │
  │                                                    │
  │       uaRO+0x66f5b0 (CGameMode::ProcessMsg)        │
  │                                                    │
  └──────────────────────────┬─────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────┐
  │                                                    │
  │               2. Despachador de Ação               │
  │                                                    │
  │              uaRO+0x873dc6..0x873fd6               │
  │                                                    │
  │         Dispara mensagem 0x14b (USE_SKILL)         │
  │                                                    │
  │        Chama uaRO+0x865ab0 / uaRO+0x875400         │
  │                                                    │
  └──────────────────────────┬─────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────┐
  │                                                    │
  │ 3. Camada de Execução da Perícia (Candidatos Topo) │
  │                                                    │
  │       Cluster uaRO+0x930xxx .. uaRO+0x932xxx       │
  │                                                    │
  │          • uaRO+0x9309a8 -> uaRO+0x932020          │
  │                                                    │
  │          • uaRO+0x931930 -> uaRO+0x848d20          │
  │                                                    │
  │          • uaRO+0x847d2d -> uaRO+0x841450          │
  │                                                    │
  └──────────────────────────┬─────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────┐
  │                                                    │
  │                  4. Envio de Rede                  │
  │                                                    │
  │     uaRO+0x8148e0 (CRagConnection::SendPacket)     │
  │                                                    │
  │                         ↓                          │
  │                                                    │
  │         uaRO+0x816640 (SendPacket da fila)         │
  │                                                    │
  └────────────────────────────────────────────────────┘

  #### Endereços Candidatos Identificados:

  1. uaRO+0x873fe1 (RVA 0xc73fe1): ponto exato no despachador de ação onde a mensagem 0x14b (Uso de Perícia) é empurrada para a pilha (push $0x14b; call *0x18(%eax)).
  2. uaRO+0x932020 / uaRO+0x931930 (RVA 0xd32020 / 0xd31930): rotinas chamadas no momento da seleção de alvo e preparo dos dados da perícia.
  3. uaRO+0x8148e0 (RVA 0xc148e0): a rotina de alto nível da conexão (CRagConnection::SendPacket(len, buf)), que roteia para o SendPacket (0xc16640) da fila.

