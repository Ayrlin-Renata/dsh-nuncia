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
| authority | bearer token only | bearer + **signed authority envelopes** (user intent / override), asymmetric per-node keys |

`src/` keeps the original TypeScript for reference; it is not compiled.

## Layout

```
index.js            bundle entry — re-exports lib/index.js for DSH patches
lib/index.js        the plugin (plain ESM)
lib/authority.js    v2 Ed25519 envelopes + legacy v1 HMAC, canonical forms, jti ledger
lib/keys.js         per-node key pair: load / generate / 0600 storage / kid + fingerprint
lib/grants.js       grant store (mint/revoke/envelopeFor, read-time expiry)
lib/inbound.js      peer-key registry + fail-down gate + bounded security log
lib/outbound.js     peer client that attaches live grants
lib/notices.js      agent-facing authority notices (facts, never grant bytes)
lib/approvals.js    approval broker (queue for hosts with no prompt surface)
lib/task-store.js   file-backed A2A Task store (write-chained JSON)
bin/nuncia-identity.js  print this node's kid/fingerprint/public key, check a peer key
bin/nuncia-token.js     print the derived bearer (per node name)
cordis.patch.yml    default profile patch (inserts the plugin)
tests/              unit tests + end-to-end harnesses (npm test)
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
          tokenEnv: NUNCIA_A2A_TOKEN    # optional: authority derives the bearer
        taskTtlMs: 3600000              # completed-task retention
        metricsPath: /metrics           # optional Prometheus text
        adminPath: /a2a/admin           # status / enable / disable
        persistTasks: true              # durable task files
        persistenceRoot: ./.sessions
        authority:                      # DESIGN §20 (off by default)
          enabled: true
          nodeName: phone               # this node's name inside envelopes
          nodeKeyFile: ~/.dsh/nuncia/nuncia-node.key   # Ed25519 private key (0600)
          # nodeKey: '<base64url PKCS8>'  inline alternative for fixed-env hosts
          peers:                        # each peer's PUBLIC key — all verification needs
            - name: desk
              publicKey: MCowBQYDK2VwAyEA…
              kid: 7jsvWk5X142WqWk7     # optional pin; boot fails if the key disagrees
          allowV1: true                 # accept pre-v2 HMAC envelopes while migrating
          pairingSecretEnv: NUNCIA_PAIRING_SECRET   # now derives ONLY the bearer token
          peerUrls: ['desk=http://192.168.1.20:4123']
          maxWindowMs: 600000           # hard ceiling for any grant (10 min)
          grantTtlMs: 300000            # default window when mint omits ttlMs
          persistGrants: false          # keep windows across restarts
          tools: true                   # register request_user_intent + a2a_send
        chatelaine:                     # DESIGN §20.4 / §20.11 (P2)
          workspace: ~/.sylvia/housekeeping   # operators work here; house rules live here
          rulesFile: HOUSE-RULES.md
          rules: true                   # seed + version the rules in a local git repo
          stateDir: auto                # default: <workspace>/.nuncia (gitignored)
          sessionId: ''                 # pin the chatelaine to an existing session
          preset: standard              # chatelaine + operator preset; default agentPreset
          operatorTtlMs: 604800000      # operator sessions live 7 days (DESIGN §20.4)
          tools: true                   # register report_to_chatelaine + reply_to_operator
          forwardQuestions: true        # forward an operator's ask-user to the chatelaine
        agentCard:
          name: Nuncia
          description: A DeepSeek Harness agent exposed over the agent2agent protocol
          version: 0.1.0
```

**Bearer resolution.** With the authority layer on, the bearer token is derived
from the pairing secret **and the node name** (`nuncia/bearer:<nodeName>`), so two
nodes sharing one secret no longer share one literal token. `auth: {type: bearer}`
is still a complete configuration. Precedence is `auth.token` → `auth.tokenEnv` →
derived. The secret derives *only* the token: envelope signatures use the node key
(§ Pairing below).

**Where the secret comes from.** `pairingSecretEnv` wins when that variable is
exported into the harness process. `pairingSecret` is the inline fallback for
hosts whose environment is fixed at launch (a GUI app). A secret in a profile file
is only as private as that file — prefer the environment when you can export it.

Since the bearer is derived per node, a peer needs the **target's** name to compute
the token it should send. To print one locally:

```sh
node bin/nuncia-token.js --node phone              # from NUNCIA_PAIRING_SECRET
node bin/nuncia-token.js <secret> --node phone     # explicit secret
node bin/nuncia-token.js                           # pre-v2 derivation (no node name)
```

**Node identity.** `bin/nuncia-identity.js` prints this node's `kid`, fingerprint
and public key, plus a ready-to-paste `peers:` entry for the other side:

```sh
node bin/nuncia-identity.js --name phone
node bin/nuncia-identity.js --check <base64url-key> [--kid 7jsv…]   # inspect/pin a peer key
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
| GET | `/{adminPath}/rules` | house rules + git history — **loopback-only** (even with a bearer) |
| PUT | `/{adminPath}/rules` | `{"rules":"…","summary":"…"}` — written, then auto-committed — **loopback-only** |
| GET | `/{adminPath}/operators` | operator roster: handle, task, level, scope, expiry — **loopback-only** |
| POST | `/{adminPath}/operators/prune` | `{"dryRun":true}` sweeps expired operators — **loopback-only** |
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

### Pairing: exchange public keys, never a signing root

v2 authority is **asymmetric**. Each node generates one Ed25519 key pair
(`nodeKeyFile`, mode 0600) and signs with the private half; the receiver verifies
with the sender's **public** half. Pairing is therefore a public exchange:

```sh
# on each node
node bin/nuncia-identity.js --name phone     # prints kid, fingerprint, publicKey
```

Paste the printed `peers:` entry into the *other* node's config. Then compare
fingerprints over a channel you trust (out of band) — the config is the trust
anchor, not the AgentCard, which is unauthenticated.

Why it is built this way: with the earlier shared-HMAC scheme, verification and
minting needed the same key, so any peer that could *check* intent could equally
*produce* it — and, because `origin` was only a signed string, under any node's
name. v2 makes `origin` resolve to a key (`kid`), and a verifier holds no signing
capability at all. A forged envelope claiming a peer's name fails at `kid` or
signature and degrades to `peer`.

The pairing secret still exists, for two narrower jobs: deriving the bearer token,
and accepting **legacy v1** envelopes during migration (`allowV1`, on by default).
It is no longer an authority root, so losing it does not let anyone mint intent.

```sh
export NUNCIA_PAIRING_SECRET="$(openssl rand -base64 32)"   # bearer only now
```

`export` matters: a bare `NAME=value` line never reaches the harness process.

**Migration.** A node with only a pairing secret keeps minting v1 envelopes; peers
with `allowV1: true` still honour them. To move a node to v2: generate its key,
give every peer its public key, and give it theirs. Once no v1 traffic remains,
set `allowV1: false` everywhere. A version mismatch is refused explicitly, never
silently downgraded — an Ed25519 envelope is not accepted by the HMAC verifier and
vice versa.

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
  back inbound, and a node cannot speak for itself (`origin-mismatch`).
- **Revoke ends the local window.** It stops future attachment; a peer that
  already holds an envelope keeps it until `exp` — which is why windows are short.

### Tests

```sh
npm test          # everything: unit + all five end-to-end harnesses
npm run test:unit # unit only (no sockets, no fake harness)
```

| file | covers |
|---|---|
| `tests/test-authority.test.mjs` | derivation, canonical encoding, per-field tamper, expiry/skew/window, binding, jti ledger |
| `tests/test-grants.test.mjs` | mint/revoke, validation, read-time expiry, envelope preference, persistence tamper + rotation |
| `tests/test-inbound.test.mjs` | v1 fail-down reasons, allowlist, same-link replay, no signature echo |
| `tests/test-v2.test.mjs` | Ed25519 envelopes, kid binding, **cross-key forgery refused**, gate clock, legacy gating |
| `tests/test-keys.test.mjs` | key generation/0600, reload identity, refuse-to-overwrite, inline/env precedence |
| `tests/test-outbound.test.mjs` | grant attachment, unknown peer, non-200, response authority claims |
| `tests/test-notices.test.mjs` | notice wording, remaining-time, no grant material |
| `tests/test-approvals.test.mjs` | broker decisions, expiry fail-closed, cancel-on-unload |
| `tests/test-house.test.mjs` | seed-once, one-commit-per-edit, local git identity, path-traversal refusal |
| `tests/test-operators.test.mjs` | handle shape, persistence, read-time expiry, corrupt-book refusal |
| `tests/test-smoke.mjs` | the real SDK against a fake ctx: card, auth, task lifecycle |
| `tests/test-authority-http.mjs` | live HTTP with two keys: intent, **impersonation refused**, unknown origin, bounce, legacy v1, expiry notice |
| `tests/test-tools.mjs` | registration, approval ladder, auto-attach seen in the peer's body |
| `tests/test-auth.mjs` | bearer resolution, inline secret vs env precedence |
| `tests/test-p2.mjs` | operator brief, handles, chatelaine round-trip, question forwarding, abort→CANCELED, expiry prune |

## Chatelaine (DESIGN §20.11, P2)

Operators are **real sessions** in a Housekeeping workspace, and one stable
**chatelaine** session represents the human inside the node. Discipline is
prompt-level (the operator decision of 2026-10-20): no hard tool caps yet — but
the runtime is session-based so caps arrive later as config, not a rewrite.

- **First contact** creates the operator session (workspace cwd, per-request
  model/preset preserved), records a handle, attaches it to the workspace, and
  injects the *operator brief* **before** the task's first turn: requester,
  authority level, scope, remaining time, the reporting duty, and "never ask the
  human directly". The handle also rides in the A2A task's metadata.
- **The chatelaine** is adopted once (`chatelaine.json` in the state dir, or a
  pinned `sessionId`), created in the workspace if absent. It is told of
  contact, unexpected ends (`error`, `aborted`, `blocked`, `max-tokens` —
  only `completed` counts as success), and expiry prunes. Reports use
  `inject` (durable, no wake); questions use `followup`.
- **Tools** (when `chatelaine.tools` is on):
  - `report_to_chatelaine({summary, question?, urgency?})` — durable report;
    `question` wakes the chatelaine. Every operator is told to use it before
    anything consequential.
  - `reply_to_operator({handle, message, wake?})` — the chatelaine answers an
    operator by handle; unknown/expired handles are refused by name.
- **Question forwarding** (`forwardQuestions`, on by default): an operator's
  `ask_user_question` is intercepted at plugin scope, forwarded to the
  chatelaine with a wake, and answered in place with "proceed on your
  judgement" — an A2A session never hangs on a human who is not watching it.
  Any other session falls through to the real UI untouched.
- **House rules** live in `HOUSE-RULES.md` inside the workspace, versioned in a
  **local git repo** (no remote, no push). Edits only through
  `GET|PUT {adminPath}/rules` (loopback-only even with a bearer), each write
  committed; agents read the rules via the skill/notice. The seed covers the
  reporting discipline, authority handling and escalation policy.
- **Seven-day operators**: per-task `expiresAt` from `operatorTtlMs` (default
  7d, overriding the global `taskTtlMs`). The prune pass archives the session
  (the shipped surface has no session deletion — archive is the ceiling),
  drops the record and handle, and tells the chatelaine once.
  `POST {adminPath}/operators/prune` with `{"dryRun":true}` sweeps on demand.

Live on both nodes (2026-10-20): desk task completed in 4 s with the operator's
brief as its first context line; AVD adopted its chatelaine and recorded the
contact notice; both `/status` endpoints report the house, the chatelaine
session id, and the operator roster.

## Smoke test

```sh
node tests/test-smoke.mjs   # exit 0 = all pass
```

Runs the real SDK against a fake DSH context: AgentCard, bearer rejection,
admin status, a full task lifecycle (agent created → assistant message →
terminal state), and the counters.

## Remaining work (DESIGN §20.7)

The authority core is implemented: **per-node Ed25519 identities (v2)**, public-key
pairing, envelope sign/verify, jti ledger, grants (mint / revoke / expiry / optional
persistence), inbound fail-down with security events, admin endpoints,
`request_user_intent`, `a2a_send` with auto-attach, legacy v1 acceptance, and the
AgentCard authority extension — covered by 114 unit tests plus four end-to-end
harnesses.

Still open:

- **~~P1 finish~~ — done.** Live two-node demo (desktop ↔ AVD, 2026-10-20): intent
  honored both directions with the signer's `kid` recorded, a forged envelope refused
  as `signature`, legacy v1 honored, expiry drifting back to `peer`.
- **~~P2 — Chatelaine layer~~ — done.** Housekeeping workspace + house rules in a
  local git repo, operator handles (`op_<16hex>`), operator brief before the first
  turn, `report_to_chatelaine` / `reply_to_operator`, question forwarding,
  per-task 7-day TTL with archive-and-drop pruning, unexpected-end supervision,
  `/status` operator roster. Live on desk and AVD (2026-10-20).
- **P3 — inter-session + Sylvia glue**: panel mint/revoke/badge buttons,
  netgate exemption (`allowA2AOnMetered`), remembered peers, toasts.
  (The `targetSession` spike pulled forward: chatelaine↔operator reporting is
  already cross-session via `agents.resume` + `inject`, P2.0-B in the plan.)
- **P4 — hardening**: Noise transport, key rotation/revocation story, EN + ZH READMEs (same
  pattern as the mobile fork), arm64 physical-device run. *Per-node keys landed early*
  (P1.5, v2 envelopes) because the shared-HMAC design could not give verification
  without minting.

Design decisions still open (§20.8): the native dialog surface per platform.
The second one — how the receiving **agent** learns its request arrived with
intent — is now answered: the level is recorded on the task, exposed in
`/status`, and announced to the agent as a notice carrying level, peer, scope
and remaining time (level and expiry, never grant bytes). A grant is therefore
visible as *authority it already has*, not as a token it could replay.

## License

BSD-3-Clause, as upstream.


