---
name: ro-ops
description: Kit operacional offline ro_ops (discover, sample-thread, env-check, new-artifact, scaffold-state) com saida JSON {cmd,status,data,caveats}; nao autoriza experimento.
---
1. Rode `python3 -m ro_ops <cmd>` na raiz (entry point canônico; `python3 -m ro_ops.cli <cmd>` também funciona). Leitura: `discover`, `sample-thread --pid P --tid T`, `env-check`. Escrita privada: `new-artifact --dir D [--pid P] [--probe F]`, `scaffold-state --dir research/<trilha> --role R --id ID`.
2. Exit: 0 verified, 10 unverified, 20 undetermined, 1 erro de uso. `undetermined` nunca vira positivo; leia `caveats`.
3. `env-check` nunca conclui exclusividade: so o responsavel autoriza instancia e escopo (research/COORDINATION.md).
4. Reconsulte `discover` a cada sessao; nao cache pid/tid. Nunca grave credenciais ou trafego.
5. Escrita so em research/<trilha>/ ou dir proprio fora do repo; nunca docs/, relay/, agent/, config.
