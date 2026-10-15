# Identificação de proteções — Detect It Easy (15/10/2026)

## Proveniência e build

**OBSERVADO E CONFIRMADO PELO RESPONSÁVEL, no Detect It Easy (DiE):**
os próprios arquivos `uaRO.exe` e `gepard.dll` da **build atual,
utilizada nas investigações de movimento `0x035F` e cifra**, foram
submetidos ao DiE. Esta associação de identidade **foi esclarecida
expressamente pelo responsável**, não se trata de extrapolação de uma
build histórica ou de um cliente diferente.

- **uaRO.exe:** Detecção **Themida/WinLicense 3.XX**; PE32, x86 de 32 bits.
- **gepard.dll:** Detecção **VMProtect**, conforme resultado informado
  pelo responsável sobre o arquivo atual; versão exata do VMProtect
  não especificada no material textual.
- **Nível de evidência:** observação estática feita pelo responsável
  nos binários usados no projeto e resultado reproduzido nesta conversa.
  Não se fez uma segunda execução independente do DiE neste trabalho;
  isso **não coloca em dúvida a identidade da build informada**.
- **Limite técnico:** a detecção de um protetor **não identifica quais
  funções concretas estão virtualizadas**, nem as fronteiras de VM
  ou o código executado em uma região de memória.

Hashes **já documentados** dos arquivos atuais da pesquisa
(`docs/CIPHER_INVESTIGATION.md`; valores não extraídos do próprio
texto do DiE):

| Arquivo | SHA-256 da build pesquisada |
|---|---|
| `uaRO.exe` | `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569` |
| `gepard.dll` | `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b` |

O responsável confirmou **a identidade dos arquivos usados no DiE com
os arquivos atuais da pesquisa**. Os hashes são referências de build já
existentes na documentação; não foram medidos novamente nesta alteração.

## Saída DiE fornecida para uaRO.exe

| Grupo | Valor comunicado | Interpretação |
|---|---|---|
| DOS | `MS-DOS [8086, 16-bit]` | Stub DOS normal do formato PE; **não** significa aplicativo 16 bits |
| Imagem | `PE32`, `Windows (Vista) [I386, 32-bit]` | PE32/x86; a etiqueta de SO é informação do DiE, não teste de suporte ao Vista |
| Linker | `Microsoft Linker (6.00.8447)` | Metadado identificado pelo DiE |
| Compilador | `Microsoft Visual C/C++ (19.29.30153) [C++]` | Identificação de compilador, sem atribuição de todas as rotinas |
| Ferramenta | `Microsoft Visual Studio (6.0)` | Outra assinatura detectada; não inferir cronologia a partir de rótulos conflitantes |
| Bibliotecas | Direct3D 9, DirectDraw, MSVC Runtime (dynamic), Miles Sound System, RAD Video Tools | Dependências indicadas |
| Assinatura | `Windows Authenticode (2.0) [PKCS #7]` | Presença da estrutura; não constitui verificação de confiança da assinatura |
| Integridade (heurística) | `Generic (Uncritical)`: `Certificate table overlaps image data`; `Malformed certificate table` | Alerta estrutural do DiE, **não** prova de arquivo malicioso |
| Proteção | `Themida/Winlicense (3.XX, Winlicense)` | Identificação do protetor aplicado ao cliente atual |
| Seções (heurística) | `#11 ".winlice"` RWX; seções incomuns; IAT data directory vazia | Compatível com proteção/empacotamento |
| Packer (heurística) | Seções características do Themida 3.x, nomes repetidos, seção `#12 ".boot"` comprimida, imports recorrentes | Características estáticas da imagem protegida |
| Depuração | Registros CodeView, VC Feature, POGO; seção `#5 ".debug"` | Metadados detectados, não garantia de símbolos úteis |
| Recurso: ícone | Offset `0x00f520c8`, tamanho `0x02e8` | Offset de recurso em arquivo, não breakpoint |
| Recurso: ícone | Offset `0x00f523c0`, tamanho `0x14` | Offset de recurso em arquivo, não RVA de função |
| Recurso: manifesto XML | Offset `0x00f523e4`, tamanho `0x0312` | Offset de recurso em arquivo, não endereço executado |

A detecção do DiE para `uaRO.exe` e `gepard.dll` identifica
**dois protetores diferentes na mesma build**, mas não demonstra que
o componente Themida ou o componente VMProtect tenha virtualizado
cada caminho específico já rastreado.

## Consequências para as duas investigações

### Movimento `0x035F`

**OBSERVADO anteriormente:** no caminho natural aparece o dispatcher
`0x11 → 0x0D → 0x5B → 0x8A`; no ensaio nativo exclusivo o
receptor `0x8A` entrou/retornou e não produziu store `0x035F`
ou envio observado na janela. O resultado do DiE confirma a presença
de Themida no executável e VMProtect na DLL dessa **mesma build**.

**INFERÊNCIA:** agora é especialmente importante não atribuir
regiões de código desempacotado/anônimo, trampolins e callsites a
uma VM específica sem observar a origem de execução. Alternativas
incluem código nativo do cliente, rotina Gepard, stub/protetor
e suporte Wine/Proton. **H2 (preparação) e H3 (contexto/callsite)**
continuam hipóteses distintas; a detecção de proteção, por si só,
não resolve qual delas explica a ausência de `0x035F`.
Ver `MOVEMENT_035F_PRECONDITIONS.md`.

### Cifra

**OBSERVADO anteriormente:** escritor `gepard+0x1C752B`
com `mov [esi],cl` e cadeia parcial de transporte até
`gepard+0x18EFF2`. **OBSERVADO via DiE na build atual:**
a `gepard.dll` possui VMProtect. **AINDA DESCONHECIDO:**
a última definição executada de `CL`, função de keystream,
estado consumido, inicialização e fronteiras da transformação.

A ferramenta de desvirtualização VMProtect de Jonathan Salwan
trabalha com traces completos de funções puras, não com os
snapshots seletivos que já foram coletados. Não transferir
automaticamente a metodologia para código Themida, nem presumir
que o gerador de `CL` esteja virtualizado só pela presença
de VMProtect na DLL. Ver `CIPHER_INVESTIGATION.md`.

## Estado desta edição

**Documentação somente.** Sem execução local de DiE, breakpoints,
instrumentação, extração de código, tráfego de rede, instalação
ou modificação de mecanismos de proteção.

**Próximo registro útil:** preservar a versão do Detect It Easy e,
se conveniente, a saída bruta sanitizada para rastreabilidade.
Isso melhora a proveniência, mas **não é requisito para aceitar
a confirmação já fornecida sobre a build utilizada**.
