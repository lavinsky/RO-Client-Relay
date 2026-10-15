# GepardByPass (2022): comparação histórica com uaRO/Gepard

**Classificação:** evidência histórica de código-fonte, **não** evidência dinâmica da build uaRO atual.
**Fonte congelada:** [99hertz/GepardByPass, commit `49564450d94b3a6ff66e8da6488eafd2e56aace6`](https://github.com/99hertz/GepardByPass/commit/49564450d94b3a6ff66e8da6488eafd2e56aace6), datado de **2022-03-27**. Revisão documental em 2026-10-15.
**Escopo desta revisão:** leitura do commit, de arquivos C++ presentes na árvore e de notas associadas. **Não houve execução do código de terceiros, teste de breakpoint no cliente atual, leitura de memória de sessão, nem validação ao vivo.**

O [README.MD](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/README.MD#L1-L20) declara teste em Windows 10 x64 20H2, **não** na versão mais recente do Gepard da própria época; o autor diz que o último teste havia ocorrido meses antes. Os arquivos C++ são parte da árvore nesse commit, mas nem todos foram introduzidos por ele. Diferenças de executável (`Jogar.exe` vs. `uaRO.exe`), versão de Gepard, Wine/Proton, loader, proteção, layout e ASLR impedem transportar offsets ou mecanismos automaticamente.

## Achados verificáveis no código antigo

| Evidência histórica (origem) | Interpretação limitada | Relação com nossa pesquisa |
|---|---|---|
| [`addresses.h:10`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/addresses.h#L6-L12) e [`addresses.cpp:5-10`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/addresses.cpp#L5-L10) | `receivePacketSubAddr = base(Jogar.exe) + 0x4C5860`; `receivePacketMidHookAddr = base(Jogar.exe) + 0x4C59CF` (**0x4C5860 + 0x16F**). O código trata a posição final como ponto `INT3` de **recepção**; não é RVA do Gepard. | **Pista de arquitetura de recepção**, não ponto de origem de movimento `0x035F` nem da cifra de envio. A identidade funcional/ABI no uaRO atual é **NÃO VERIFICADA**. |
| [`recvpackethook.cpp:8-41`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/recvpackethook.cpp#L8-L41) | O hook lê/restaura um registrador e deriva *endereço e comprimento* de uma mensagem; `OnReceivePacket` imprime `isLogin` e comprimento. A chamada que registraria bytes está comentada. | Sugere que existia uma fronteira interna observável de recepção naquela build; **não** mostra bytes decifrados, ID, framing, entrada/saída de cifra ou `0x0087`. |
| [`dllmain.cpp:14-31`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/dllmain.cpp#L14-L31) | A lista de funcionalidades menciona `encryption of network packets with dynamic key`. | **Alegação do autor**, não algoritmo, tabela, chave, snapshot ou prova de compatibilidade com a cifra atual. |
| [`some stuff/vmp_tracker.txt`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/some%20stuff/vmp_tracker.txt) | Script de trace de chamadas/branches em faixas `.text` e VMP da sessão antiga; faixas `0x6F6D1000..0x6F754000` e `0x6F778000..0x6FF8E000` resultam de endereços/tamanhos literais. Reconhece possível VM-entry com heurística de `push imm32` antes de `call`. | Ideia geral de **separar execução do interpretador de seus pontos de entrada/saída**. Faixas absolutas e heurística **não** demonstram os limites, handlers ou VM-entries do uaRO atual. |
| [`some stuff/gepard_notes.txt`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/some%20stuff/gepard_notes.txt) | `gepard:65CCF` aparece com a pergunta especulativa sobre cópia de seção/array. | **HIPÓTESE histórica de integridade/cópia**, com convenção de endereço não demonstrada; não promover a endereço atual nem função criptográfica. |
| [`some stuff/crc_patch.txt`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/some%20stuff/crc_patch.txt) | Menciona `gepard sub $79A30` e um teste de CRC. Não há build, base ou prova da função. | **Referência incompleta de verificação de integridade**, não indício de keystream ou da cadeia `0x11→0x8A`. |
| [`dllmain.cpp:34-58`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/dllmain.cpp#L34-L58), [`exceptionhandler.cpp`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/exceptionhandler.cpp), [`hwbreakpoint.cpp`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/hwbreakpoint.cpp) | Mistura INT3, HWBP, dispatcher próprio de exceções, contexto DRx e carregamento via dependência de `binkw32.dll`. | Mostra que instrumentos alteram o comportamento de exceções e competem por registradores de depuração; **não** constitui DLL proxy da interface do Gepard nem método portátil para Frida/Wine. |

As notas [`some stuff/okl.txt`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/some%20stuff/okl.txt) e [`some stuff/syscall.txt`](https://github.com/99hertz/GepardByPass/blob/49564450d94b3a6ff66e8da6488eafd2e56aace6/some%20stuff/syscall.txt) são registros/inventários de syscalls com frequências/identificadores da plataforma antiga, não pares P/C, rastros de estado ou catálogo de mensagens internas `0x035F`.

## Consequências para movimento `0x035F`

**OBSERVADO apenas na fonte histórica:** havia um ponto intermediário de recepção no *executável* antigo, diferente das rotinas de Gepard estudadas no uaRO. O código não demonstra envio `0x035F`, não registra o dispatcher `0x11→0x0D→0x5B→0x8A`, não identifica campos `+0x500/+0x50C/+0x510/+0x520/+0x534/+0x538` e não separa H2 (preparação) de H3 (contexto da VM).

**Hipótese comparativa limitada:** versões distintas podem expor fronteiras de recepção observáveis no cliente. **Rival:** o ponto antigo é específico de uma organização/ABI inexistente no uaRO atual. **Verificação preliminar offline:** conferir identidade de módulo, mapeamentos, instrução e fluxo funcional em análise estática do **build identificado**; não inferir equivalência por aritmética de RVA ou presença de `INT3`. A prioridade atual continua no consumidor concreto de estado antes/depois do receptor `0x8A`, conforme [`MOVEMENT_035F_PRECONDITIONS.md`](MOVEMENT_035F_PRECONDITIONS.md).

## Consequências para a cifra

O comentário de “chave dinâmica” é compatível com muitas construções e **não** evidencia algoritmo XOR específico, estado de 256 bytes, cinco posições, unidade de 16 bits, inicialização, chave ou geração de `CL`. O hook antigo é de **recepção** e sequer registra conteúdo do pacote; não fornece `input_hex/output_hex` pareados. O `vmp_tracker` é uma heurística de classificação de fluxo, não pseudocódigo da cifra ou desvirtualizador.

**Hipótese comparativa limitada:** distinguir fronteiras de entrada/saída de funções virtualizadas pode ajudar a evitar seguir cópias de bytes sem observar a transformação. **Rival:** os limites e interfaces internos do Gepard uaRO diferem dos de 2022. **Verificação documental/offline:** relacionar apenas convenções de rastreio com a cadeia executada já observada; não atribuir instruções antigas a endereços atuais. A prioridade evidencial continua na última definição executada de `CL` antes de `gepard+0x1C752B`, conforme [`CIPHER_INVESTIGATION.md`](CIPHER_INVESTIGATION.md).

## Registro de endereços históricos — não reutilizar como BP atual

| Valor | Base / significado na fonte | Status para uaRO |
|---|---|---|
| `0x4C5860`, `0x4C59CF` | Deslocamentos de `Jogar.exe` para recepção; o segundo é calculado | **NÃO VERIFICADO**; outro executável/build |
| `gepard:0x65CCF` | Nota especulativa sem instrução conferida | **NÃO VERIFICADO** |
| `$79A30` | Referência de subrotina Gepard em script CRC sem identidade de build | **NÃO VERIFICADO** |
| `Kernelbase.FindNextFileW+0x160/+0x163` | Offsets de versão Windows em scripts de enumeração | Não relacionados a `0x035F`/cifra; não portáteis para Wine |
| `ntdll+0x1269A0/+0x10D5B0` | Endereços assumidos pelo código antigo para tratamento de exceções | Não relacionados à cifra; específicos de módulo/versão |
| `0x6F6D1000` e `0x6F778000` | Bases **absolutas** de faixas no rastreador VMP | Não são RVAs; não transportar |
| `0x1FB3B3E0` | Valor arbitrário empregado no script CRC | Não é chave, semente ou constante demonstrada da cifra |

**Decisão:** não executar ou instalar o projeto antigo, não aplicar seus patches de integridade/ocultação e não armar seus breakpoints no cliente atual por valor numérico. Antes de qualquer experimento *vivo*, há necessidade de identificação do build, controle exclusivo do processo, verificação do papel da instrução, limites/limpeza e nova autorização; **nenhum desses testes ocorreu nesta revisão**. Este registro é uma fonte comparativa de baixo a médio valor, não evidência suficiente para reorientar as duas linhas de pesquisa.
