# Spike de isolamento — input sintético ao cliente escondido (Fase 0)

> **Status:** RUNBOOK (procedimento proposto; **não executado**). Nenhuma mudança de sistema foi
> feita por esta entrega. Os passos abaixo exigem a máquina do responsável, root para `udev`/seat, e
> decisão humana. Classificação dos resultados quando executar: OBSERVADO/INFERIDO/HIPÓTESE.

## Objetivo e critério de sucesso

Um clique/keypress sintético que, **simultaneamente**: (a) chega **só** ao uaRO escondido;
(b) **não** toca o teclado/mouse reais do responsável no seat0; (c) **passa** no filtro do Gepard
(chega ao Wine como evento de hardware, sem a flag "injected").

**Sucesso =** apertar INSERT sintético faz o personagem **sentar** no uaRO isolado enquanto o
responsável usa o PC normalmente no seat0, sem interferência.

## Por que é não-trivial (confirmado neste box)

- O que **passa no Gepard** é input via **uinput (kernel)** → libinput → compositor → Wine
  (parece hardware). **XTEST** é filtrado (`xdotool`/Xvfb). Memória do projeto:
  `synthetic-movement-uaro-hybrid-input`.
- uinput é **global ao seat**: sem roteamento, o evento vai para a janela em foco do seat0 → atrapalha
  o uso real. É exatamente o que o isolamento tem de impedir.
- Inventário deste box (2026-10-16): `gamescope`, `cage`, `Xvfb`, `ydotool/ydotoold`, `xdotool`,
  `libinput`, `evtest`, `loginctl` presentes. **`seatd` NÃO instalado**; **`python-evdev` NÃO
  instalado**; `Xephyr` ausente. Sessão Wayland/KDE (KWin), `/dev/uinput` root (usuário fora do grupo
  `input`). `gamescope` tem backends `drm|sdl|openvr|headless|wayland`.
- **Caminho de input para o headless (técnica, relato 2026-10-16):** o par "gamescope headless +
  input por `/dev/uinput` virtual" é uma técnica **comprovada** — é assim que o **Sunshine** alimenta
  um gamescope headless (teclado/mouse/gamepad virtuais via uinput). **Não usamos o Sunshine**; ele é
  só a prova de que a técnica funciona. **Replicamos** o mesmo: criamos nossos próprios devices
  virtuais uinput (teclado/mouse) e rodamos o uaRO num gamescope `--backend headless` que lê esses
  devices — ver E1. Isso dá input ao compositor escondido sem tocar o seat0.

## Arquitetura alvo

Dispositivo **uinput dedicado** (teclado+mouse virtuais, nome fixo) → roteado a um **seat próprio**
→ **compositor real** (não cliente Wayland aninhado, que herda o foco do pai) lendo **só** esse
dispositivo → uaRO (Wine/Proton) dentro. Frida/relay anexam como hoje. O input sintético é escrito
nesse device; nunca toca o seat0.

## Pré-requisitos (mudanças de sistema — responsável decide)

1. Acesso ao `/dev/uinput` para criar o device (grupo `input` no usuário, ou rodar o criador como
   root). `ydotoold` já cria um uinput próprio quando iniciado.
2. Para o roteamento por seat, uma destas duas vias:
   - **logind** (presente): atribuir o device do bot a um seat via regra `udev`
     `ENV{ID_SEAT}="seat-bot"` + `loginctl attach seat-bot <syspath>`. Limite conhecido: um seat que
     roda *sessão gráfica* precisa de um device master de vídeo; em **GPU única** isso conflita com o
     seat0/KWin. Para **input-only** destinado a um compositor headless/nested, avaliar se o logind
     aceita o seat sem master de vídeo (a verificar no spike).
   - **seatd** (instalar): mais simples para wlroots (`cage`/`gamescope`). Requer instalar o pacote.

## Experimentos (ordem; cada um com gate go/no-go)

### E0 — Device dedicado + verificação de roteamento (sem compositor ainda)
1. Criar o device do bot (via `ydotoold` próprio, ou um criador uinput via `ctypes`/`libevdev` —
   `python-evdev` ausente, então não contar com ele).
2. `sudo libinput list-devices` e `evtest`: achar o device do bot e **confirmar seu `seat`**.
3. Aplicar a regra `udev` de `ID_SEAT=seat-bot` ao device do bot; re-plug/trigger; reconfirmar com
   `loginctl seat-status seat-bot` e `libinput list-devices` que **só** o device do bot está em
   `seat-bot` e os devices reais seguem em `seat0`.
- **Gate:** o device do bot aparece em `seat-bot` e os reais em `seat0`. Se o logind recusar o seat
  sem master de vídeo → instalar `seatd` (via E-alt) ou ir ao fallback VM/2ª máquina.

### E1 — Compositor isolado rodando app trivial
- **Indício (relato responsável, 2026-10-16):** setups de **gamescope headless** recebem input por
  **dispositivos virtuais `/dev/uinput`** (teclado/mouse/gamepad) — técnica comprovada pelo Sunshine.
  Replicamos a técnica com nossos próprios devices; isso **reduz** (não elimina) a incerteza do item
  1: confirmar ao vivo que o headless desta versão lê o device do bot. HIPÓTESE até observar.
- Tentar, em ordem de menor conflito com o seat0:
  1. `gamescope --backend headless` com um app Wine trivial (p.ex. `wine notepad`): confirmar que o
     headless **lê** o device do bot (device uinput próprio criado em E0). Render offscreen já
     satisfaz "fora da visão".
  2. `cage` num VT dedicado (backend DRM) com seat próprio, se E0 via seatd/logind permitir DRM
     secundário. Em GPU única, pode exigir trocar de VT — aceitável só se "fora da visão" e sem tirar
     o display do seat0.
- **Gate:** escrever um keypress no device do bot muda o app trivial no compositor isolado e **nada**
  acontece no seat0 (confirmar olhando o seat0 em uso).

### E2 — uaRO dentro + Gepard aceita o clique
1. Lançar o uaRO (Wine/Proton) dentro do compositor isolado de E1.
2. Anexar o relay/Frida como hoje (`ro-ops discover` para PID/porta).
3. Escrever um **INSERT** sintético no device do bot → o personagem deve **sentar** (0437 GID próprio
   sai e executa). Repetir algumas vezes.
- **Gate (SUCESSO DO SPIKE):** senta no uaRO isolado **e** o seat0 do responsável fica intacto durante
  os disparos. Falha → fallback.

## Fallbacks (se E0/E1 travarem em GPU única)

- **Cliente em VM/2ª máquina** (GPU passthrough ou máquina física separada): isolamento físico
  trivial; o relay/OpenKore falam com ela por rede. Custo de infra; sem conflito de seat.
- **Protótipo aceitando interferência:** uinput global + o uaRO num **desktop virtual KDE** separado,
  disparos em rajadas curtas — só para **provar a cadeia ponta-a-ponta** (Fases 2–3) antes de
  reinvestir no isolamento limpo. Não é a entrega final (atrapalha o uso durante os disparos).

## Saída do spike

Registrar em `research/action_0437_0438/STATE.md` (via skill `research-handoff`): qual via de seat
funcionou, comandos exatos, device/seat observados (`libinput list-devices`, `loginctl`), e se o
Gepard aceitou o clique isolado. Só então o módulo de input do relay (Fase 2) tem um alvo estável
para escrever.
