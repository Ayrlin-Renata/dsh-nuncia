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
        authority:                      # DESIGN §20 (off by default)
          enabled: true
          nodeName: phone               # this node's name inside envelopes
          pairingSecretEnv: NUNCIA_PAIRING_SECRET   # must be EXPORTED, not just set
          peers: [desk]                 # allowed inbound origins; empty = any signed origin
          peerUrls: ['desk=http://192.168.1.20:4123']
          maxWindowMs: 600000           # hard ceiling for any grant (10 min)
          grantTtlMs: 300000            # default window when mint omits ttlMs
          persistGrants: false          # keep windows across restarts
          tools: true                   # register request_user_intent + a2a_send
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
| GET | `/{adminPath}/status` | counters, live tasks with their authority level, grants, security events (bearer-guarded) |
| POST | `/{adminPath}/enable\|disable` | runtime switch |
| POST | `/{adminPath}/mint` | mint a grant — **loopback-only** + bearer |
| POST | `/{adminPath}/revoke` | end a grant by id |
| GET | `/{adminPath}/requests` | pending approvals with the id a surface needs to decide — **loopback-only** |
| POST | `/{adminPath}/requests/decide` | `{"id":"…","decision":"allowed-once"\|"rejected"\|"cancelled"}` — **loopback-only** |
| GET | `/{metricsPath}` | Prometheus text |

While an agent turn runs, committed assistant messages stream as artifact
updates; a turn that ends in error publishes `TASK_STATE_FAILED` **with the
reason in `status.message`** (so a remote caller can diagnose without host
logs). A DSH approval request publishes `TASK_STATE_INPUT_REQUIRED`; the
client's next message on the same task resolves it (`allow`/`approve`/`yes`
→ allowed-once, otherwise rejected).

## Authority (DESIGN §20)

A bearer token authenticates a *connection*. It says nothing about whether the
remote agent is speaking **for the user**. That claim travels only in a signed
envelope under `params.metadata.authority`; message text is never authority.

### One secret, two capabilities

Paste the same `NUNCIA_PAIRING_SECRET` on both nodes. HKDF derives the bearer
token and the envelope signing key with independent info strings, so pairing is
one paste and a leaked token cannot sign.

```sh
export NUNCIA_PAIRING_SECRET="$(openssl rand -base64 32)"   # generate once, paste on both
```

`export` matters: a bare `NAME=value` line never reaches the harness process.

### Minting (the user's act)

```sh
curl -s -X POST http://127.0.0.1:4123/a2a/admin/mint \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"target":"desk","level":"intent","ttlMs":600000,"scope":"housekeeping"}'
```

The response carries the signed envelope. Minting is **loopback-only** on
purpose — a bearer token alone would let any paired peer grant itself intent.
`POST …/revoke {"id":"…"}` ends a window; `GET …/status` lists what is live.

An agent can also ask, through the `request_user_intent` tool — see
[Asking](#asking-the-agents-act) for the three surfaces it tries and why the
admin endpoint is not the only one.

### Asking (the agent's act)

`request_user_intent` never mints on its own: it asks a human first, trying up
to three surfaces in order, and **anything other than `allowed-once` is a
refusal**. Missing surfaces fail closed — never an implicit yes.

| order | surface | when it answers |
|---|---|---|
| 1 | `ctx.approval.request` | policy allows prompting (`auto` mode). Under `danger-full-access` the policy is `never`, so this returns `rejected` without asking — dead there by design |
| 2 | `ctx.userQuestions.askTimed` | a Web UI client is attached to the live root agent. **This is the one prompt surface that survives `danger-full-access`** — the `user-questions/request` waterfall is independent of the approval policy |
| 3 | ApprovalBroker | headless, no client, or the card went unanswered — the request is queued and any surface decides it (panel via `…/requests`, `approveCommand` hook) |

`authority.approval` picks the ladder: `broker` (queue), `host` (seams only,
`unavailable` if neither answers), `auto` (seam → card → `unavailable`). The
card is asked for 120 s; a `{pending:true}` answer falls through instead of
hanging the turn, which matters because `ask()` with no connected client pends
forever. Identity gates are the host's: only the live **root** agent can ask, so
a subagent cannot mint authority for itself.

`approveCommand` receives `NUNCIA_APPROVAL_ID` and `NUNCIA_APPROVAL_REASON` in
its environment — that is the hook for a Termux notification, a panel button, or
anything scriptable that POSTs the decision back. Requests expire (2 min) and
resolve `timeout`; unload resolves `cancelled`.

Whatever the outcome, the *agent* is told about windows it can use — a notice is
injected when a window opens, when it lapses, and when a claim is bounced. Those
notices carry level, peer, scope and remaining time, never grant bytes.

### Sending and verifying

`a2a_send` posts to a peer from `authority.peerUrls` and attaches the live grant
automatically; the agent never handles grant bytes. On the receiving side every
message is decided independently:

- valid → `intent` / `override`; the jti is recorded and replay on the same link
  is tolerated;
- invalid, expired, out of scope, replayed across links, or addressed elsewhere →
  processed as **`peer`**, counted in `nuncia_authority_rejected_total`, recorded
  in `/status` `securityEvents`, and emitted as `nuncia/security-event` on the
  host bus. Never silently, and never an error the caller can retry into a grant.

Rules worth knowing:

- **Per message, not per task.** A lapsed window reverts the *next* message to
  `peer`; work already issued keeps running (the drift rule).
- **Responses carry no authority.** A response that claims it is treated as
  `peer` and reported as `authority-in-response`.
- **Non-transitive.** An envelope minted *for* a peer is rejected if it comes
  back inbound (`target-mismatch`).
- **Revoke ends the local window.** It stops future attachment; a peer that
  already holds an envelope keeps it until `exp` — which is why windows are short.

### Tests

```sh
npm test     # 82 unit tests + three end-to-end harnesses (smoke, authority, tools)
```

## Smoke test

```sh
node test-smoke.mjs   # exit 0 = all pass
```

Runs the real SDK against a fake DSH context: AgentCard, bearer rejection,
admin status, a full task lifecycle (agent created → assistant message →
terminal state), and the counters.

## Remaining work (DESIGN §20.7)

The authority core (P1) is implemented: pairing derivation, envelope
sign/verify, jti ledger, grants (mint / revoke / expiry / optional persistence),
inbound fail-down with security events, admin endpoints, `request_user_intent`,
`a2a_send` with auto-attach, and the AgentCard authority extension — covered by
67 unit tests plus three end-to-end harnesses.

Still open:

- **P1 finish** — the live two-node LAN demo (desktop ↔ AVD): L2 honored, an
  expiring grant drifting back to L1 observable on the wire, revocation
  mid-conversation.
- **P2 — Chatelaine layer**: housekeeping workspace, operator handles
  (`op_<16hex>`), per-task 7-day TTL and pruning, house rules in a tiny git repo,
  security-event → notification path.
- **P3 — inter-session + Sylvia glue**: `targetSession` spike, panel
  mint/revoke/badge buttons, netgate exemption (`allowA2AOnMetered`), remembered
  peers.
- **P4 — hardening**: Noise transport, per-node keys, EN + ZH READMEs (same
  pattern as the mobile fork), arm64 physical-device run.

Design decisions still open (§20.8): the native dialog surface per platform.
The second one — how the receiving **agent** learns its request arrived with
intent — is now answered: the level is recorded on the task, exposed in
`/status`, and announced to the agent as a notice carrying level, peer, scope
and remaining time (level and expiry, never grant bytes). A grant is therefore
visible as *authority it already has*, not as a token it could replay.

## License

BSD-3-Clause, as upstream.
