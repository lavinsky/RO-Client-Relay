# Registro de pacotes de controle e sessão — Gepard / uaRO

**Objetivo:** reter evidências verificáveis para avaliar futuramente um plugin OpenKore de protocolo/sessão independente do cliente (xKore 0). Este arquivo **não** é uma implementação, especificação final de wire protocol ou prova de compatibilidade entre builds.

## Evidências disponíveis

- **Build servidor 2016 (referência histórica, não verificada no uaRO atual):** a investigação documenta unidades independentes `recv_crypt`, `send_crypt`, `sync_crypt`; inicialização `SC_GEPARD_INIT`; resposta `CS_GEPARD_INIT_ACK`; sincronização periódica `CS_GEPARD_SYNC`. Origem relatada: `docs/HISTORY/GEPARD_LEGACY.md` §3 e `docs/HISTORY/ARCHITECTURE_LEGACY.md` §5.1. O código histórico não está versionado (`relay/resources/` é ignorado).
- **uaRO, tabela de tamanhos:** `data/uaro_recvpackets.txt` contém `8280 128`, `4754 -1`, `5395 -1` e `C392 -1`. A presença na tabela **não demonstra** direção, papel no handshake ou associação exclusiva ao Gepard.
- **uaRO, hipótese de heartbeat:** `docs/HISTORY/GEPARD_LEGACY.md` §3.3 associa `0x8280` ao heartbeat de 128 bytes; no histórico 2016 a nota associa `0x8285` ao nome `CS_GEPARD_SYNC`. A equiparação entre builds é uma **inferência**, ainda não uma especificação validada.
- **Login:** `docs/HISTORY/GEPARD_LEGACY.md` §1 documenta login uaRO via HTTP/token e char server sem camada Gepard. Isso **não identifica o ID ou a sequência exata** do pacote de inicialização/sincronização da cifra na sessão de mapa.

## Inventário com níveis de evidência

| Mensagem / ID | Direção | Tamanho | Papel proposto | Nível e fonte | Lacunas para xKore 0 |
|---|---|---:|---|---|---|
| `SC_GEPARD_INIT` / ID atual não confirmado | servidor → cliente (no build 2016) | desconhecido no uaRO | estabelecimento de estado de sessão/cifra | **DOCUMENTADO PARA 2016**: investigação §3.1 | ID atual, fase, campos, condições de reinicialização |
| `CS_GEPARD_INIT_ACK` / ID atual não confirmado | cliente → servidor (no build 2016) | desconhecido no uaRO | confirmação de inicialização | **DOCUMENTADO PARA 2016**: investigação §3.2 | ID atual, dependências, conteúdo, transição de estado |
| `0x8280` | cliente → servidor (hipótese) | 128 na tabela uaRO | heartbeat/sincronização | **TAMANHO OBSERVADO NA TABELA**; papel **INFERIDO**: investigação §3.3 | confirmação de direção e cadência, comparação de sessões, comportamento de timeout |
| `0x8285` (build 2016) | cliente → servidor | não estabelecido aqui | heartbeat histórico | **DOCUMENTADO PARA 2016**: investigação §3.3 | não assumir correspondência binária com `0x8280` |
| `0x4754`, `0x5395`, `0xC392` | não estabelecida | variável (`-1` na tabela) | desconhecido | **LISTADOS** em `data/uaro_recvpackets.txt` | verificar origem e se são realmente pacotes de controle |
| `0x035F`, `0x0437`, `0x0438`, `0x0AF4` | cliente → servidor | consultar fonte do protocolo | pacotes de ação, **não confundir com heartbeat** | **DOCUMENTADOS** em `docs/HISTORY/ARCHITECTURE_LEGACY.md` §§5–6 | comportamento no build atual e requisitos do OpenKore |

## Hipótese separada da evidência

**H-CIPHER-01 — integridade do conteúdo em comandos com corpo mais expressivo.** O fonte servidor de 2016 sugere decifragem de corpos selecionados antes do parser, com estado de recepção que deve avançar na sequência correta. Conjectura atual: bytes de conteúdo incorretamente decifrados podem fazer o parser/servidor rejeitar `0x0438`; operações de corpo menor, como algumas variantes de `0x0437`, podem parecer funcionar mesmo se a cobertura da cifra estiver incorreta. **Não está provado** que exista validação criptográfica por byte, que o servidor descarte o pacote por esse motivo, ou que a cifra atual seja idêntica à de 2016.

**Evidência que falta:** comparar resultados reproduzíveis de sessões de teste autorizadas e dados sanitizados, separados por versão, ID, comprimento e estado de sessão, para distinguir diferença de corpo, dessincronização, pré-condição de ação e rejeição de parser. Não concluir causalidade apenas pela ausência da animação de perícia.

## Ficha obrigatória para novas descobertas

- ID/nome proposto; direção e fase (login/char/mapa); versão/build e data;
- Comprimento e se a observação ocorreu em wire, após decifragem ou somente em tabela;
- Relação temporal com inicialização, reconexão ou heartbeat;
- Referência exata `arquivo:linha` ou teste reproduzível **sanitizado**;
- Classificação: OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO;
- Explicação alternativa e teste offline capaz de distinguir interpretações;
- Informação necessária para futura interface de plugin OpenKore, **sem** assumir que o relay implementará xKore 0.

## Limite de arquitetura do futuro plugin

Quando houver protocolo demonstrado, a responsabilidade por inicialização de sessão, mensagens de controle periódicas e estado do protocolo deverá ser especificada como extensão **do OpenKore**. Este repositório permanece responsável pelo relay de texto claro na fase xKore 1. Nenhuma implementação de controle deve preceder evidência suficiente de direção, transições de estado e testes reproduzíveis.
