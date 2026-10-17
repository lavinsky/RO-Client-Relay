# Ferramentas de pesquisa da cifra

Manual completo centralizado em [apêndice integral de ferramentas em docs/CIPHER_INVESTIGATION.md](../../docs/CIPHER_INVESTIGATION.md#original-docs-cipher-tools-md):
formatos, limites, privacidade, CLI, mecanismos de coleta e limpeza.
Execute os comandos a partir da raiz do repositório.

Estado científico e limitações em [CIPHER_INVESTIGATION.md](../../docs/CIPHER_INVESTIGATION.md).
Análise offline: `python3 research/cipher/analyze.py --help`.
Coleta viva requer autorização específica; testes sintéticos não demonstram a cifra.

Preparação atual da linhagem (2026-10-16):

- `cl-producer --cl-relocate-source --cl-producer-rva RVA` escolhe somente código
  de um POP observado; o destino é resolvido no contexto atual. A opção
  `--cl-stack-prefix-capture` acrescenta a candidata PUSH/PUSH/POP/POP contígua,
  validada contra instruções atuais antes de armar.
- `--cl-producer-repeat` observa até 32 trocas com breakpoint independente em CL.
  `--cl-lineage-capture` deriva de evidência auditada um offset relativo a EBP e
  observa um byte adicional fora dos mapas ESP. São quatro DRs próprios: não
  combinar com outra instrumentação na mesma instância.
- `--cl-upstream-reference CAPTURA --cl-upstream-rva RVA` seleciona um POP da lista
  de escritores da fonte auditada e encerra após sua prova local. A referência
  contém somente a seleção de código/offset; o driver não reutiliza operandos
  antigos. Esse recorte não captura CL e não prova causalidade entre capturas.
- `--cl-producer-hit N` é seletor experimental limitado a 32; contagens de hits não
  são invariantes do protocolo. Prefira repetição até o consumidor quando viável.

Cada alvo tem teto de 256 escritas; permanecem 500 ms de sequência, 1000 traps e
256 KiB. `--inspect-only` valida código sem armar. `DONE` e ausência de erro de
leitura não ocultam `SCRIPT_ERROR` posterior; confira a auditoria e a limpeza.
Artefatos e comandos executados ficam privados; resumo científico em STATE/HANDOFF.
