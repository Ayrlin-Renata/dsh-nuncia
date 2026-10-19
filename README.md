# dsh-nuncia

Authenticated **A2A** (Agent2Agent) server bridge plugin for
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) — named for
the Roman goddesses of contract, *"whose duty it is to announce agreements."*

Exposes a DSH agent as a standard A2A v1.0 endpoint (AgentCard + JSON-RPC +
SSE), mapping each A2A **Task** to one DSH **Session/Agent**.

## Credit

Fork of **[MicroWearld/dsh-a2a-server](https://github.com/MicroWearld/dsh-a2a-server)**
(BSD-3-Clause). The protocol mapping, task store contract, approval bridge and
metrics all originate there — thank you for a solid base. This fork differs:

| | upstream | this fork |
|---|---|---|
| build | TypeScript + `dsh-super-injector` scaffold, needs a full DSH monorepo checkout (`DSH_CHECKOUT`) to compile and bundle | **no build step** — `lib/` is hand-ported plain ESM, installed as-is |
| protocol lib | bundled into `lib/index.js` | `@a2a-js/sdk` as a normal npm dependency |
| name | `dsh-a2a-server` | `dsh-nuncia` (metrics: `nuncia_*`) |
| authority | bearer token only | bearer + **signed authority envelopes** (user intent / override) — *in development, see below* |

`src/` keeps the original TypeScript for reference; it is not compiled.

## Layout

```
index.js            bundle entry — re-exports lib/index.js for DSH patches
lib/index.js        the plugin (plain ESM)
lib/task-store.js   file-backed A2A Task store (write-chained JSON)
cordis.patch.yml    default profile patch (inserts the plugin)
test-smoke.mjs      standalone smoke test (fake ctx, real SDK)
```

## Install

The plugin needs three ambient packages that come from the DSH host, not npm:
`@deepseek-ai/dsh-llm`, `@deepseek-ai/dsh-session`, and the host's
`@deepseek-ai/schemastery` (config schema). Installable deps are tiny
(`@a2a-js/sdk` → `jose`, plus plain `schemastery` for this config schema).

```sh
# 1. put the plugin somewhere stable and install its npm deps
cd ~/.sylvia            # any location works
git clone https://github.com/Ayrlin-Renata/dsh-nuncia
cd dsh-nuncia
npm install --no-audit --no-fund --legacy-peer-deps

# 2. link the ambient DSH packages from the host tree
G="$(npm root -g)/@deepseek-ai"
mkdir -p node_modules/@deepseek-ai
ln -sfn "$G/dsh/node_modules/@deepseek-ai/dsh-llm"     node_modules/@deepseek-ai/dsh-llm
ln -sfn "$G/dsh/node_modules/@deepseek-ai/dsh-session" node_modules/@deepseek-ai/dsh-session
#    (nested layout varies by install method — point them at wherever the
#     CLI's dependency tree actually keeps dsh-llm / dsh-session)

# 3. register with the profile
cd ~/.dsh/profiles/web
ln -sfn ~/.sylvia/dsh-nuncia node_modules/dsh-nuncia
node -e 'const f="package.json",fs=require("fs"),j=JSON.parse(fs.readFileSync(f));j.dependencies??={};j.dependencies["dsh-nuncia"]="file:'"$HOME"'/.sylvia/dsh-nuncia";fs.writeFileSync(f,JSON.stringify(j,null,2)+"\n")'
```

Then add the plugin row to the profile's `cordis.patch.yml`
(`cordis.patch.yml` in this repo is a ready-made example) and restart the
harness. The standalone entry point also works without a `webServer` service:
give it `host`/`port` and it serves on its own listener.

## Configuration

```yaml
- insert:
    - id: dsh-nuncia
      name: 'dsh-nuncia'
      config:
        path: /a2a                      # JSON-RPC endpoint
        agentCardPath: /.well-known/agent.json
        host: 127.0.0.1                 # standalone listener (no webServer)
        port: 4123
        cwd: /path/to/workspace         # absolute; working dir for new agents
        agentPreset: standard           # preset used to compose agents
        provider: deepseek-official     # optional model route
        model: deepseek-v4-pro          # optional model name
        auth:
          type: bearer
          tokenEnv: NUNCIA_A2A_TOKEN    # or `token:` literal
        taskTtlMs: 3600000              # completed-task retention
        metricsPath: /metrics           # optional Prometheus text
        adminPath: /a2a/admin           # status / enable / disable
        persistTasks: true              # durable task files
        persistenceRoot: ./.sessions
        agentCard:
          name: Nuncia
          description: A DeepSeek Harness agent exposed over the agent2agent protocol
          version: 0.1.0
```

Clients may override the preset per request with
`params.metadata.agentPreset` (alias `preset`).

## Endpoints

| method | path | purpose |
|---|---|---|
| GET | `/.well-known/agent.json` | AgentCard (skills, capabilities, preset extension) |
| POST | `/a2a` | A2A JSON-RPC (`SendMessage`, `SendStreamingMessage`, `GetTask`, `CancelTask`, …) |
| GET | `/{adminPath}/status` | counters + enabled flag (bearer-guarded) |
| POST | `/{adminPath}/enable\|disable` | runtime switch |
| GET | `/{metricsPath}` | Prometheus text |

While an agent turn runs, committed assistant messages stream as artifact
updates; a turn that ends in error publishes `TASK_STATE_FAILED` **with the
reason in `status.message`** (so a remote caller can diagnose without host
logs). A DSH approval request publishes `TASK_STATE_INPUT_REQUIRED`; the
client's next message on the same task resolves it (`allow`/`approve`/`yes`
→ allowed-once, otherwise rejected).

## Smoke test

```sh
node test-smoke.mjs   # exit 0 = all pass
```

Runs the real SDK against a fake DSH context: AgentCard, bearer rejection,
admin status, a full task lifecycle (agent created → assistant message →
terminal state), and the counters.

## Roadmap — authority envelopes (DESIGN §20)

Bearer tokens authenticate *connections*; they say nothing about whether a
remote agent is speaking **for the user**. The planned layer adds signed
`metadata.authority` envelopes with four levels — `peer` (default), `intent`
(user intent, bounded by `house` rules), `house` (policy layer, never on the
wire), `override` (may contradict house, minted only via direct user
authentication) — with non-transitive grants, drift-on-expiry, and
fail-down-loud verification. Grants never enter agent-visible memory: the
plugin wraps outbound messages itself.

Status: not yet implemented in this revision.

## License

BSD-3-Clause, as upstream.
