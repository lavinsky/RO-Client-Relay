# Índice de evidências técnicas — RO-Client-Relay

**Revisão:** 2026-10-15. **Referência:** revisão local `524b0f05fa61872e140f98ace9e503d12356641e`. Os resultados abaixo são **documentados em fontes primárias do repositório**, não verificados de novo em cliente real por esta auditoria. Os artefatos privados citados nos estudos **não acompanham** este índice.

| ID | Estado | Evidência / método original | Build e condições | Documento canônico / código | Limitação principal |
|---|---|---|---|---|---|
| M-01 | **OBSERVADO** | S1/S2: 6/6 capturas positivas, sequência `0x11→0x0D→0x5B→0x8A` até store de `0x035F` | Duas instâncias do mesmo build documentado, sessões distintas | [Investigação §§S1/S2](MOVEMENT_035F_INVESTIGATION.md); `research/movement_035f/` | Capturas até primeiro hit, não cobertura total de movimentos |
| M-02 | **OBSERVADO/INFERIDO** | ABI natural `(0x8A,x,y,0,0)`; ECX manager; ESP compatível com cinco argumentos; resposta `0x0087` correspondente | Mesmo build, cliques alternados e controles | [Investigação §ABI](MOVEMENT_035F_INVESTIGATION.md); `relay/packets.py` | ABI semântica inferida; ACK não prova conclusão do percurso |
| M-03 | **OBSERVADO** | Observadores independentes dispatcher/receptor/store/`sendmsg`/`recv_0087`, ordenação por evento | Run read-only de 10 s na janela controlada | [Pré-condições §5](MOVEMENT_035F_PRECONDITIONS.md); `research/movement_035f/observe_path.py` | `sendmsg` temporalmente correlacionado, bytes não identificados naquele run |
| M-04 | **REFUTADO no recorte** | Ensaio 6.4: `0x8A` isolado entra e retorna, sem store/`sendmsg` atribuível; controles naturais funcionam antes/depois | Mesmo build, objeto/args/thread conferidos, observadores independentes | [Pré-condições §§4–5](MOVEMENT_035F_PRECONDITIONS.md); `research/movement_035f/native_trial.py` | Refuta M-H1 (falha apenas de observabilidade), não distingue M-H2/M-H3; não ausência global |
| M-05 | **OBSERVADO/INFERIDO** | Disassembly dos casos `0x11/0x0D/0x5B`, campos +0x500/+0x50c/+0x510/+0x520/+0x534/+0x538 | Código identificado; distinção dos objetos dispatcher/receptor | [Pré-condições §3](MOVEMENT_035F_PRECONDITIONS.md); [Investigação §Casos internos](MOVEMENT_035F_INVESTIGATION.md) | Consumidor dos campos e unidade de `0x15E` não observados |
| M-06 | **REFUTADO no recorte** | Wrapper `+0x875400` observado em controles de repouso e de movimento; `0xc7650e` faltou em uma amostra positiva | S1 e uma amostra de callsite | [Investigação §§S1/Origem](MOVEMENT_035F_INVESTIGATION.md) | Não elimina esses caminhos de todos os ramos ou funções |
| C-01 | **OBSERVADO** | Breakpoints com operandos preservados verificaram `+0x1B223C → +0x1B2255 → +0x18EFEC..+0x18EFF2` em recortes delimitados | Arquivos de módulos identificados e revalidados em 2026-10-15 | [Cifra §Continuação dinâmica](CIPHER_INVESTIGATION.md); `research/cipher/chain_capture.py` | Não identifica entrada/saída de função criptográfica |
| C-02 | **OBSERVADO independente** | Watchpoint do byte consumido + escritor `+0x1C752B mov [esi],cl` confirmado em rodada isolada | Mesmo build; recortes não fundidos indevidamente | [Cifra §Evidências e limites](CIPHER_INVESTIGATION.md) | Última definição de CL e conexão com recorte consumidor não concluídas numa só rodada |
| C-03 | **OBSERVADO** | 26 rodadas, contagem de matches/timeouts/exceções e limpeza | Capturas reportadas em 2026-10-15, observação por thread | [Cifra §Rodadas](CIPHER_INVESTIGATION.md); `research/cipher/chain_audit.py` | Timeout ≠ ausência global de escrita; alguns observadores incompletos |
| C-04 | **NÃO VERIFICADO** | Auditoria de onze fontes: nenhuma chamada P/C/estado completa; ferramenta retorna `C_INSUFFICIENT` | Escopos variados, não unir sessões por nome/tempo | [Cifra §§Auditoria/Ferramenta](CIPHER_INVESTIGATION.md); `research/cipher/analyze.py` | Sem identidade de F, estado, inicialização, pacote ou cifragem independente |
| G-01 | **OBSERVADO apenas na tabela** | IDs `8280 128`, `4754 -1`, `5395 -1`, `C392 -1` | Tabela do repositório, não captura de sessão | [Controle](GEPARD_CONTROL_PACKETS.md); `data/uaro_recvpackets.txt` | Tamanho tabelado não determina direção, função ou handshake |
| G-02 | **DOCUMENTADO apenas para 2016** | `SC_GEPARD_INIT`, `CS_GEPARD_INIT_ACK`, `CS_GEPARD_SYNC`, estados históricos | Fonte Gepard 2016, não equivalência do uaRO atual | [Controle](GEPARD_CONTROL_PACKETS.md); [investigação histórica](HISTORY/GEPARD_LEGACY.md) | Necessário revalidar IDs/algoritmo/direção no build atual |
| R-01 | **OBSERVADO no código/configuração** | `inject = true`, `inject-call = true`; separar merge stack do `SendPacket` fila; frames XKore | Revisão de código publicada em 2026-10-15 | `relay_capture.conf`; `relay/writeback.py`; [arquitetura](ARCHITECTURE.md) | Verificação estática não prova cliente/servidor funcionando agora |

## Notas de procedência e auditoria

- **Identidade de módulos do estudo:** `uaRO.exe` SHA-256 `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569`; `gepard.dll` SHA-256 `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b`. Hashes citados em [CIPHER_INVESTIGATION §Build](CIPHER_INVESTIGATION.md); não provam identidade do estado criptográfico entre sessões.
- **Bases de endereços:** código anônimo uaRO referenciado em `0x401000`, base PE em `0x400000`, bases Gepard variáveis por relog. Offsets de sessão só podem ser interpretados junto às bases e hashes; não são assinatura universal. [MOVEMENT_035F_INVESTIGATION §Convenções](MOVEMENT_035F_INVESTIGATION.md).
- **Artefatos externos:** caminhos em `/tmp/` citados nos estudos apontam para material de execução original; este índice não afirma que continuam disponíveis. Para reproduzir, exigir autorização separada, revalidar build e limites e não copiar dados privados.
- **Independência epistemológica:** códigos `M-H1` e `C-H1` são linhas de pesquisa diferentes; não fundi-los. Ausência de hit não é ausência de evento fora da cobertura observada.

## Evidência incorporada após o pacote inicial

| ID | Status e origem | Recorte e resultado | Limite / refutação |
|---|---|---|---|
| M-07 | OBSERVADO no registro; commits `2645fad`, `87245d6`; `MOVEMENT_035F_PRECONDITIONS.md` §12 | Argumentos iguais; sem ponteiro nos 1024 B bidirecionais + 128 B do registro global, 8+ eventos; contexto de retorno difere | Refuta passagem de campo por argumento nesse callsite e restringe ligação por ponteiro; não exclui valor global/TLS/indireções |
| D-01 | OBSERVADO offline nesta consolidação; `DOCUMENTATION_AUDIT.md` | Manifesto/CRC conferidos; aplicador recusou HEAD divergente sem escrita; reconciliação manual | Não valida resultados vivos nem integridade atual de capturas externas |

Reprodução offline dos contratos: `python3 tests/test_movement_preconditions.py` e
`python3 tests/test_cipher_research.py`. Não reproduzem os experimentos históricos vivos.

## M-08 — ensaio do dispatcher, corrigido após integração

**Origem:** `524b0f0`, corrigido em `888764a`; [pré-condições §13](MOVEMENT_035F_PRECONDITIONS.md).
**OBSERVADO no registro:** buffer compatível no trap pré-store em `disp2`, sem confirmação
de escrita final, pacote completo, retorno normal, envio ou resposta. `disp5` sem HW BPs
é outra condição; não fornece confirmação daquele trap. **OBSERVADO por disassembly:**
`ret 0x34` = 52 bytes; chamada com 44 bytes. **HIPÓTESE então levantada:** desequilíbrio de 8 bytes como causa da falha;
explicação exclusiva superada pelo ensaio M-09 abaixo. Necessidade individual H2/H3 não demonstrada; reentrância segue aberta.
Nova coleta requer proposta própria. Capturas privadas não foram abertas nesta integração.

## P-01 — identificação de proteções recebida na main

**Origem:** `77954b2`, integrado em `origin/main@0a29193`;
[PROTECTION_FINGERPRINT_DIE.md](PROTECTION_FINGERPRINT_DIE.md).
**OBSERVADO e confirmado pelo responsável no DiE:** Themida/WinLicense 3.XX em `uaRO.exe`,
VMProtect em `gepard.dll`, arquivos da mesma build. **NÃO VERIFICADO:** quais funções estão
virtualizadas; não atribuir automaticamente uma região anônima a um protetor.

## M-09 — ABI de 13 dwords também trava

**Origem:** `7a64581`, [pré-condições §13.5](MOVEMENT_035F_PRECONDITIONS.md).
**OBSERVADO no registro:** replay com 13 dwords/52 bytes do frame natural, alterando x/y;
conteúdo de movimento no trap pré-store, sem retorno, exceção reportada ou envio/resposta
observados durante a chamada; cliente congelou. **REFUTADO no recorte:** discrepância de
8 bytes como explicação exclusiva da falha. **HIPÓTESE:** reentrância em `poll/select` ou
outra dependência de contexto/estado. Trap de execução não prova escrita concluída;
ausência de exceção reportada não exclui toda falha fora da cobertura. H2/H3 não isoladas.
A publicação não executou a sonda. Arquivo-fonte incluído no commit `7a64581`.
