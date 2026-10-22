/**
 * dsh-nuncia — authenticated A2A server bridge for DeepSeek Harness.
 *
 * Plain-ESM port of MicroWearld's dsh-a2a-server (TypeScript/dsh-super-injector
 * scaffold → no-build CommonJS-free library). A2A Tasks map 1:1 to DSH
 * Sessions/Agents; the A2A protocol layer comes from @a2a-js/sdk (npm).
 *
 * Authority model (DESIGN.md §20): connection auth = bearer token; user
 * intent / override travel ONLY inside signed metadata.authority envelopes
 * (planned: §20.1) — never in message text.
 *
 * @module dsh-nuncia
 */

import { execFile } from 'node:child_process'
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { hostname } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import Schema from 'schemastery'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { AgentCard, TaskState, formatSSEEvent } from '@a2a-js/sdk'
import {
  AgentEvent,
  DefaultRequestHandler,
  InMemoryTaskStore,
  JsonRpcTransportHandler,
  ServerCallContext,
} from '@a2a-js/sdk/server'
import {
  DEFAULT_MAX_WINDOW_MS,
  createSigner,
  deriveAuthorityKey,
  deriveBearerToken,
  exportPublicKey,
} from './authority.js'
import { ApprovalBroker } from './approvals.js'
import { CHATELAINE_SUBDIR, createChatelaineRuntime, noticeMessage, operatorBrief } from './chatelaine.js'
import { GrantStore } from './grants.js'
import { SecurityLog, createAuthorityGate } from './inbound.js'
import { DEFAULT_KEY_FILE, loadOrCreateNodeKey } from './keys.js'
import { authorityRejectedNotice, intentGrantedNotice, intentLapsedNotice } from './notices.js'
import { createOutboundClient, parsePeerUrls } from './outbound.js'
import { DEFAULT_RULES_FILE, DEFAULT_WORKSPACE, createHouse, expandHome } from './house.js'
import { AnnouncementStore, MAX_ANNOUNCEMENT_LENGTH, describePlatform, resolveNodeName, sanitizeNodeName } from './identity.js'
import { DEFAULT_SECRETS_KEY_ENV, readSecretsFile, recordSecretAccess, resolvePassphrase } from './secrets.js'
import { DEFAULT_OPERATOR_TTL_MS, OperatorBook } from './operators.js'

/**
 * Session-id prefixes that mark a session as A2A traffic (DESIGN §20.12 P3.1).
 *
 * The v4 session format allows only `origin: "subagent"` in the durable
 * session header, and no other header field survives a restart — so the tag
 * rides the session id, which every other surface already keys on.
 */
export const A2A_OPERATOR_PREFIX = 'a2a-op-'
export const A2A_CHATELAINE_PREFIX = 'a2a-chatelaine-'

/**
 * The brief prefixed to the FIRST message of a fresh operator task (§20,
 * operator guidance): requests from peers arrive with no shared lore, so the
 * default agent persona happily spends ten tool calls "verifying" a one-line
 * question — the deep dive the human kept having to cancel on the live AVD
 * (2026-10-21: a rename hand-shake that answered "Reply with exactly: …"
 * turned into config mining). This keeps ordinary tasks small and direct; a
 * genuinely exploratory task overrides it by saying so in its own text.
 */
export const DEFAULT_TASK_PREAMBLE = (
  'A2A task from a verified remote peer. Treat the request that follows as '
  + 'complete and self-contained: do exactly what it says, then finish. '
  + 'Answer from what you already know, plus at most one minimal check. '
  + 'Do NOT read files, explore configuration, or inspect the node unless the '
  + 'request itself explicitly requires it; do not start side tasks or ask '
  + 'the chatelaine questions about such a small task.'
)

/**
 * The task id carried by a tagged operator session id.
 *
 * `a2a-op-<level>-<taskId>` → `<taskId>`. The level may itself contain a
 * dash (`peer`, `intent` — neither does today, but a future level might), so
 * the task id is taken as the remainder after the FIRST level segment, which
 * is what the constructor wrote.
 * @param {unknown} sessionId
 * @returns {string|undefined}
 */
export function taskIdOfSessionId(sessionId) {
  if (typeof sessionId !== 'string') return undefined
  if (!sessionId.startsWith(A2A_OPERATOR_PREFIX)) return undefined
  const rest = sessionId.slice(A2A_OPERATOR_PREFIX.length)
  const dash = rest.indexOf('-')
  if (dash === -1) return undefined
  const taskId = rest.slice(dash + 1)
  return taskId === '' ? undefined : taskId
}
import { FileTaskStore } from './task-store.js'

export const name = 'dsh-nuncia'
export const inject = ['agents']

/**
 * How often the authority sweep looks for lapsed windows. Short enough that the
 * agent hears about an expiry promptly, long enough to be free: the sweep only
 * walks the live task map, and a grant is cleared the first time it is seen.
 */
const NOTICE_SWEEP_MS = 5_000

// -- config ------------------------------------------------------------------

/**
 * @typedef {object} A2aSkillConfig
 * @property {string} id
 * @property {string} name
 * @property {string} description
 * @property {string[]|undefined} tags
 * @property {string[]|undefined} examples
 * @property {string[]|undefined} inputModes
 * @property {string[]|undefined} outputModes
 */

/**
 * @typedef {object} A2aServerConfig
 * @property {string|undefined} path                    JSON-RPC endpoint path
 * @property {string|undefined} agentCardPath           AgentCard discovery path
 * @property {string|undefined} host                    standalone bind host
 * @property {number|undefined} port                    standalone bind port
 * @property {string|undefined} cwd                     working dir for agents
 * @property {string|undefined} provider                provider route
 * @property {string|undefined} model                   model name
 * @property {string|undefined} agentPreset             preset for created agents
 * @property {{type?:string, token?:string, tokenEnv?:string}|undefined} auth
 * @property {number|undefined} taskTtlMs               completed-task retention
 * @property {string|undefined} metricsPath             Prometheus endpoint path
 * @property {string|undefined} adminPath               admin endpoint prefix
 * @property {boolean|undefined} persistTasks           persist Task state to file
 * @property {string|undefined} persistenceRoot         dir for the Task file
 * @property {{enabled?:boolean, nodeName?:string, pairingSecretEnv?:string,
 *   peers?:string[], peerUrls?:string[], maxWindowMs?:number, grantTtlMs?:number,
 *   persistGrants?:boolean, tools?:boolean}|undefined} authority   DESIGN §20 authority layer
 * @property {{name?:string, description?:string, url?:string, version?:string,
 *   capabilities?:{streaming?:boolean, pushNotifications?:boolean},
 *   skills?:A2aSkillConfig[]}|undefined} agentCard     AgentCard metadata
 */

/** @type {Schema<A2aServerConfig>} */
export const Config = Schema.object({
  path: Schema.string(),
  agentCardPath: Schema.string(),
  host: Schema.string(),
  port: Schema.natural().max(65535),
  cwd: Schema.string(),
  provider: Schema.string(),
  model: Schema.string(),
  agentPreset: Schema.string(),
  auth: Schema.object({
    type: Schema.union(['bearer']).default('bearer'),
    token: Schema.string(),
    tokenEnv: Schema.string(),
    // An ADDITIONAL accepted bearer, never the primary: peers keep using the
    // derived token. This is the Sylvia daemon's proxy key — explicit keying
    // for the panel path, so nothing token-shaped is ever discoverable (the
    // card is auth-gated too; §20.12 P3.0).
    adminToken: Schema.string().role('secret'),
    adminTokenEnv: Schema.string(),
  }),
  taskTtlMs: Schema.natural().min(1),
  metricsPath: Schema.string(),
  adminPath: Schema.string().default('/a2a/admin'),
  persistTasks: Schema.boolean().default(false),
  persistenceRoot: Schema.string(),
  // auto: mount on the host web server when available (historical);
  // standalone: always bind host/port; webserver: require the host server.
  mount: Schema.union(['auto', 'webserver', 'standalone']).default('auto'),
  authority: Schema.object({
    enabled: Schema.boolean().default(false),
    nodeName: Schema.string(),
    // -- per-node identity (v2, DESIGN §20.1) --------------------------------
    // Ed25519 private key, inline base64url PKCS8, for hosts whose environment
    // is fixed at launch (containers, emulator images). `NUNCIA_NODE_KEY` is
    // the environment equivalent; the file form below is the default.
    nodeKey: Schema.string().role('secret'),
    nodeKeyFile: Schema.string(),
    // Peers: a bare name is a v1-only allowlist entry (no key ⇒ v2 envelopes
    // from that origin cannot be verified and fail down to `peer`). The object
    // form is what pairing actually produces: the peer's public key, optionally
    // pinned to the `kid` it should hash to.
    peers: Schema.array(Schema.union([
      Schema.string(),
      Schema.object({
        name: Schema.string().required(),
        publicKey: Schema.string(),
        kid: Schema.string(),
      }),
    ])),
    // Accept pre-v2 HMAC envelopes (only possible while a pairing secret is
    // configured). On by default for the migration window.
    allowV1: Schema.boolean().default(true),
    pairingSecretEnv: Schema.string().default('NUNCIA_PAIRING_SECRET'),
    // Inline alternative to the env var, for hosts whose process environment is
    // not easily changed (a GUI-launched harness). Same secret, same derivation;
    // the env var wins when both are present.
    pairingSecret: Schema.string().role('secret'),
    // Newline-delimited names (one per line, comments allowed). When `nodeName`
    // is unset, the first boot picks a random line and persists it beside the
    // node's other state — every fresh install gets a distinct identity without
    // a config step. Collisions resolve by `kid`, which is already carried in
    // cards, envelopes and the pairing `--check` flow.
    nodeNameFile: Schema.string(),
    peerUrls: Schema.array(Schema.string()),
    maxWindowMs: Schema.natural(),
    grantTtlMs: Schema.natural(),
    persistGrants: Schema.boolean().default(false),
    tools: Schema.boolean().default(true),
    notices: Schema.boolean().default(true),
    noticeSweepMs: Schema.natural(),
    approval: Schema.union(['auto', 'host', 'broker']).default('broker'),
    approvalTimeoutMs: Schema.natural(),
    approveCommand: Schema.array(Schema.string()),
  }),
  // -- chatelaine layer (DESIGN §20.4, §20.11 P2) -----------------------------
  chatelaine: Schema.object({
    // Housekeeping workspace: operators work here and the house rules live here.
    workspace: Schema.string().default(DEFAULT_WORKSPACE),
    rulesFile: Schema.string().default(DEFAULT_RULES_FILE),
    // false = a node without a house (the A2A endpoint still works).
    rules: Schema.boolean().default(true),
    // Where the adopted chatelaine session id and the operator book are kept.
    stateDir: Schema.string(),
    // Pin the chatelaine to an existing session (e.g. one the human uses).
    sessionId: Schema.string(),
    // Preset for the chatelaine + operators; defaults to agentPreset.
    preset: Schema.string(),
    // The chatelaine's OWN working directory. DSH labels a session by the
    // basename of its workspace path, so this is also its visible name; it must
    // not be the operators' directory or the human cannot tell them apart.
    home: Schema.string(),
    // false = never start the chatelaine (no brief, no workspace record).
    enabled: Schema.boolean().default(true),
    // Operator working directory; defaults to the workspace.
    cwd: Schema.string(),
    // How long an operator session stays reachable before pruning (7 days).
    operatorTtlMs: Schema.natural().min(1).default(DEFAULT_OPERATOR_TTL_MS),
    // The first message of a fresh operator task is prefixed with this brief so
    // the model answers the request directly instead of exploring the node to
    // "verify" it — the deep dives a human kept having to cancel. Empty string
    // disables the preamble.
    taskPreamble: Schema.string().default(DEFAULT_TASK_PREAMBLE),
    // Report/question tool for operators and the chatelaine.
    tools: Schema.boolean().default(true),
    // Forward an operator's ask-user question to the chatelaine instead of
    // letting it hang on a human who is not watching that session.
    forwardQuestions: Schema.boolean().default(true),
  }),
  // Encrypted secret vault (DESIGN §20.12.3). The pairing secret and the
  // admin token live in ONE AES-256-GCM file; only the passphrase is in the
  // environment. The environment still wins, so a one-off override works and
  // a node with no vault behaves exactly as before.
  secrets: Schema.object({
    file: Schema.string(),
    keyEnv: Schema.string(),
    keyFile: Schema.string(),
    // Where the tripwire log goes. The daemon reads the vault too, so the two
    // can write ONE file: a single log that answers "who opened the vault
    // and when". Defaults to the vault's own directory.
    auditFile: Schema.string(),
  }),
  agentCard: Schema.object({
    name: Schema.string(),
    description: Schema.string(),
    url: Schema.string(),
    version: Schema.string(),
    // The card is a DISCOVERY surface, so it is auth-gated by default (§20.12
    // P3.0): looking at a node should require the same bearer as speaking to
    // it. `public: true` is the explicit opt-out for nodes that accept
    // unauthenticated scanners.
    public: Schema.boolean().default(false),
    capabilities: Schema.object({
      streaming: Schema.boolean(),
      pushNotifications: Schema.boolean(),
    }),
    skills: Schema.array(Schema.object({
      id: Schema.string().required(),
      name: Schema.string().required(),
      description: Schema.string().required(),
      tags: Schema.array(Schema.string()),
      examples: Schema.array(Schema.string()),
      inputModes: Schema.array(Schema.string()),
      outputModes: Schema.array(Schema.string()),
    })),
  }),
})

// -- types (doc only) ---------------------------------------------------------

/** @typedef {'allowed-once'|'rejected'|'cancelled'} ApprovalDecision */

/** Per-task protocol state. @typedef {{taskId:string, contextId:string, agent:any, dispose:()=>Promise<void>, eventBus?:any, terminalPublished:boolean, createdAt:number, pendingApproval?:{request:any, resolve:(d:ApprovalDecision)=>void}}} TaskRecord */

/** @typedef {{register(route:{kind:'exact'|'prefix', path:string, handler:(req:any, res:any)=>void|Promise<void>}) : () => void}} WebServerLike */

// -- mount ---------------------------------------------------------------------

/**
 * Decrypt the node's secret vault into the process environment.
 *
 * Why the environment and not a returned object: the whole plugin already
 * reads its secrets from `process.env` (the bearer, the pairing secret), and
 * so does the daemon that proxies to it. Populating the environment here
 * means one vault satisfies both, and nothing downstream has to learn a new
 * mechanism.
 *
 * Failure is never fatal: a node with no vault, a wrong key, or no key at all
 * keeps whatever the environment already had. The vault is an improvement,
 * not a new way to fail at boot.
 *
 * @param {{file: string, keyEnv?: string, keyFile?: string, auditFile: string, logger?: any, env?: Record<string, string|undefined>}} options
 * @returns {{loaded: boolean, values?: Record<string, string>, reason?: string}}
 */
export function loadVaultIntoEnvironment(options) {
  const env = options.env ?? process.env
  const logger = options.logger
  const keyEnv = options.keyEnv ?? DEFAULT_SECRETS_KEY_ENV
  const { passphrase, source } = resolvePassphrase({ envName: keyEnv, keyFile: options.keyFile, env })
  if (passphrase === undefined) {
    logger?.info?.(`dsh-nuncia: no secret key in ${keyEnv} — using the environment's own secrets (no vault)`)
    return { loaded: false, reason: 'no-key' }
  }
  let values
  try {
    values = readSecretsFile(options.file, passphrase)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    logger?.warn?.(`dsh-nuncia: secret vault not opened — ${message}`)
    return { loaded: false, reason: message }
  }
  const names = Object.keys(values)
  // Never clobber a value the operator set deliberately: the environment
  // wins over the vault, so a one-off override still works.
  let applied = 0
  for (const [name, value] of Object.entries(values)) {
    if (typeof value !== 'string' || value === '') continue
    if (env[name] !== undefined && env[name] !== '') continue
    env[name] = value
    applied++
  }
  recordSecretAccess(options.auditFile, { source: `vault:${source}`, values: names, reason: 'boot' })
  logger?.info?.(`dsh-nuncia: opened the secret vault (${applied} of ${names.length} value(s) applied; the environment wins where already set)`)
  return { loaded: true, values }
}

/**
 * Mount the A2A server bridge.
 * @param {any} ctx - Cordis context carrying the agent factory.
 * @param {A2aServerConfig} config - A2A server configuration.
 */
export async function apply(ctx, config) {
  const logger = ctx.logger
  /** @type {Map<string, TaskRecord>} */
  const records = new Map()
  const path = config.path ?? '/a2a'
  const agentCardPath = config.agentCardPath ?? '/.well-known/agent.json'
  const adminPath = config.adminPath ?? '/a2a/admin'
  const adminRoutes = new Set([
    `${adminPath}/status`,
    `${adminPath}/enable`,
    `${adminPath}/disable`,
    `${adminPath}/mint`,
    `${adminPath}/revoke`,
    `${adminPath}/requests`,
    `${adminPath}/requests/decide`,
    `${adminPath}/rules`,
    `${adminPath}/chatelaine`,
    `${adminPath}/chatelaine/new`,
    `${adminPath}/operators`,
    `${adminPath}/operators/prune`,
    `${adminPath}/announcement`,
  ])
  const cwd = config.cwd ?? process.cwd()
  const metrics = createMetrics()
  let enabled = true
  // "Last downtime end" = when this process came up (the card's `since`).
  const bootedAt = Date.now()

  // The node's own state directory: the chatelaine id, the operator book, the
  // adopted name and the announcement all live here. It sits beside the house
  // by default so the house's git history stays one file.
  const stateDir = expandHome(config.chatelaine?.stateDir ?? join(expandHome(config.chatelaine?.workspace ?? DEFAULT_WORKSPACE), '.nuncia'))

  // -- secrets (P3.3) ---------------------------------------------------------
  // The pairing secret and the admin token live in ONE encrypted file; only
  // the passphrase is in the environment. Decrypting here means everything
  // downstream (config, env fallbacks) works unchanged, and every decryption
  // is recorded in the access log — the tripwire that makes "go find the
  // key" visible. A node with no vault simply keeps using the environment.
  // The audit log sits BESIDE the vault unless the operator points it
  // elsewhere — the daemon can be pointed at the same file, so one log
  // answers "who opened the vault, and when" for both processes.
  const vaultFile = expandHome(config.secrets?.file ?? join(stateDir, 'secrets.enc'))
  const auditFile = config.secrets?.auditFile === undefined
    ? join(dirname(vaultFile), 'secrets-access.log')
    : expandHome(config.secrets.auditFile)
  loadVaultIntoEnvironment({
    file: vaultFile,
    keyEnv: config.secrets?.keyEnv,
    keyFile: config.secrets?.keyFile,
    auditFile,
    logger,
  })

  // -- node name (P3.0) -------------------------------------------------------
  // A fresh install must be distinct from every other fresh install without a
  // config step: no configured name ⇒ pick one at random from the human's
  // list (or the hostname) and remember it.
  const identityStateFile = join(stateDir, 'identity.json')
  const adopted = await resolveNodeName({
    ...(config.authority?.nodeName === undefined ? {} : { nodeName: config.authority.nodeName }),
    ...(config.authority?.nodeNameFile === undefined ? {} : { nodeNameFile: config.authority.nodeNameFile }),
    stateFile: identityStateFile,
    logger,
  })
  if (adopted.source !== 'config') {
    logger.info?.(`dsh-nuncia: node name "${adopted.name}" (${adopted.source}${adopted.candidates === undefined ? '' : `, ${adopted.candidates} candidates`})`)
  }

  // -- announcement (P3.0) ---------------------------------------------------
  const announcement = new AnnouncementStore({ file: join(stateDir, 'announcement.json'), logger })
  await announcement.init()
  const platform = describePlatform()

  // Authority layer (DESIGN §20). Off unless explicitly enabled: an
  // unpaired node behaves exactly as before, peer-only. When enabled but
  // misconfigured it fails DOWN (peer) and reports the reason in /status
  // rather than refusing to boot — rule 5, notify loud, never silent.
  // The adopted name is passed in so the authority layer, the card and the
  // status all name the node the same way (P3.0: one identity per node).
  const authority = createAuthorityRuntime(config, cwd, logger, adopted.name)
  if (authority.enabled) {
    logger.info?.(`dsh-nuncia: authority enabled as "${authority.nodeName}" (max window ${authority.maxWindowMs} ms)`)
  } else if (authority.error !== undefined) {
    logger.warn(`dsh-nuncia: authority disabled — ${authority.error}`)
  }
  // Resolved after the authority runtime: a paired node derives its own bearer
  // token, so `auth: {type: bearer}` alone is a complete configuration there.
  const auth = resolveAuth(config, authority, stateDir, logger)
  const peerUrls = parsePeerUrls(config.authority?.peerUrls ?? [])
  // The house: workspace + rules history (§20.4). A node that cannot create or
  // version its house is still a usable A2A endpoint, so this degrades to a
  // reported state instead of refusing to boot — but it is never silent.
  let house
  if (config.chatelaine?.rules !== false) {
    try {
      house = createHouse({
        workspace: config.chatelaine?.workspace ?? DEFAULT_WORKSPACE,
        rulesFile: config.chatelaine?.rulesFile ?? DEFAULT_RULES_FILE,
        logger,
      })
      const ensured = await house.ensure()
      if (!ensured.git.ok) logger.warn(`dsh-nuncia: house rules are running unversioned — ${ensured.git.reason}`)
      else logger.info?.(`dsh-nuncia: house at ${ensured.workspace} (${ensured.rulesFile})`)
    } catch (error) {
      logger.warn(`dsh-nuncia: house unavailable — ${error instanceof Error ? error.message : String(error)}`)
      house = undefined
    }
  }

  // Plugin-owned approval queue: the only way an agent can ask a human for
  // intent when the host's approval policy is disabled (danger-full-access).
  const broker = authority.enabled
    ? new ApprovalBroker({
        ...config.authority?.approvalTimeoutMs === undefined ? {} : { timeoutMs: config.authority.approvalTimeoutMs },
        onCreate: (request) => announceApproval(config, request, logger),
      })
    : undefined
  // §20.12 P2.4: a rejected claim must reach BOTH the chatelaine (the human's
  // representative) and the operator's hook. The chatelaine is created below,
  // so this holder is filled in once it exists.
  const securityHooks = {
    fireHook: (kind, stored) => fireApproveCommand(config, logger, {
      NUNCIA_EVENT: kind,
      NUNCIA_REJECT_REASON: stored?.reason ?? '',
      NUNCIA_REJECT_ORIGIN: stored?.detail?.origin ?? '',
      NUNCIA_ADMIN_PATH: config.adminPath ?? '/a2a/admin',
    }),
  }
  // §20.16: the chatelaine runtime doubles as the GATE KEY for the authority
  // tools (a2a_send / ask_user_intent run only in the chatelaine session), so
  // it is created BEFORE any tool registration reads it.
  const houseWorkspace = house?.workspace ?? expandHome(config.chatelaine?.workspace ?? DEFAULT_WORKSPACE)
  /** @type {ReturnType<typeof createChatelaineRuntime> | undefined} */
  let chatelaine
  try {
    chatelaine = createChatelaineRuntime({
      ctx,
      config,
      workspace: houseWorkspace,
      stateDir,
      // The chatelaine gets its OWN directory: DSH labels a session by the
      // basename of its workspace path, so sharing the operators' directory
      // would make the human's representative an anonymous row among workers.
      // Its own path also gives it its own workspace record, which is what
      // makes it visible and openable in the UI at all (DESIGN §20.14.3).
      cwd: config.chatelaine?.home === undefined
        ? join(houseWorkspace, CHATELAINE_SUBDIR)
        : expandHome(config.chatelaine.home),
      rulesPath: join(houseWorkspace, config.chatelaine?.rulesFile ?? DEFAULT_RULES_FILE),
      nodeName: authority?.nodeName ?? adopted?.name,
      presetId: config.chatelaine?.preset ?? config.agentPreset,
      agentOptions: () => agentOptions(resolvedModel, undefined),
      logger,
    })
    securityHooks.chatelaine = chatelaine
  } catch (error) {
    logger.warn(`dsh-nuncia: the chatelaine runtime could not be created — ${error instanceof Error ? error.message : String(error)}`)
    chatelaine = undefined
  }
  const outbound = authority.enabled
    ? createOutboundClient({
        peers: peerUrls,
        token: authority.bearerToken,
        envelopeFor: (peer) => authority.grants.envelopeFor(peer),
        onSecurityEvent: (event) => recordSecurityEvent(ctx, authority, logger, event, securityHooks),
      })
    : undefined
  if (authority.enabled && config.authority?.tools !== false) {
    registerAuthorityTools(ctx, {
      grants: authority.grants,
      chatelaine,
      outbound,
      broker,
      approvalMode: config.authority?.approval ?? 'auto',
      logger,
      unknownPeers: () => [...peerUrls.keys()],
      // a2a_send defaults its exchange to the calling task's contextId so the
      // same exchange always lands on the SAME remote operator (and retries
      // stop minting fresh operators on the peer).
      recordOf: (agent) => {
        const id = agent?.id ?? agent?.session?.header?.id ?? agent?.session?.id
        if (id === undefined) return undefined
        const record = records.get(id) ?? records.get(taskIdOfSessionId(id))
        if (record === undefined && process.env.NUNCIA_DEBUG_TOOLS === '1') {
          console.error(`dsh-nuncia: recordOf MISS for "${id}" — record keys: ${[...records.keys()].slice(0, 10).join(', ')}`)
        }
        return record ?? undefined
      },
    })
  }

  /** @param {any} agent */
  const ownedRecord = (agent) => {
    // Same shape-drift guard as the session/event listener below.
    const sid = agent?.session?.header?.id ?? agent?.session?.id
    if (sid === undefined) return undefined
    const record = records.get(sid) ?? records.get(taskIdOfSessionId(sid))
    return record?.agent === agent ? record : undefined
  }

  /**
   * The A2A tag of a session, read from its ID.
   *
   * The v4 session format accepts only `origin: "subagent"` in the durable
   * header (anything else is rejected outright — the live AVD run proved it:
   * "session header origin must be \"subagent\""), and no other header field
   * survives a restart. So the tag rides the *session id* instead: operator
   * sessions are `a2a-op-<taskId>`, the chatelaine is `a2a-chatelaine-<uuid>`.
   * The id is what every other surface (records, events, the operator book,
   * `agents.get`/`resume`) already keys on, so one convention covers the lot —
   * and a restarted node can still recognise its own A2A sessions.
   * @param {unknown} id
   * @returns {{role: 'operator'|'chatelaine', level?: string}|undefined}
   */
  const a2aTagOf = (id) => {
    if (typeof id !== 'string') return undefined
    if (id.startsWith(A2A_OPERATOR_PREFIX)) {
      const level = id.slice(A2A_OPERATOR_PREFIX.length).split('-')[0]
      return { role: 'operator', ...(level === undefined ? {} : { level }) }
    }
    if (id.startsWith(A2A_CHATELAINE_PREFIX)) return { role: 'chatelaine' }
    return undefined
  }

  /** @type {any} */
  let taskStore = new InMemoryTaskStore()
  if (config.persistTasks === true) {
    if (ctx.get('sessionPersistence') === undefined) {
      throw new Error('dsh-nuncia: persistTasks requires sessionPersistence to be mounted')
    }
    const fileTaskStore = new FileTaskStore(join(config.persistenceRoot ?? cwd, 'a2a-tasks.json'))
    await fileTaskStore.init()
    taskStore = fileTaskStore
  }

  // A created agent needs a bound model: the stock `standard` preset's persona
  // prefix references {{model}}, so a model-less agent dies at system-prompt
  // assembly ("prompt variable \"{{model}}\" has no value"). Resolve it like
  // the headless runner does — explicit config first, then the host's default
  // selection service — and warn once at boot when neither exists.
  const resolvedModel = resolveModelSelection(ctx, config)
  if (resolvedModel === undefined) {
    logger.warn('dsh-nuncia: no provider/model configured and agentDefaultModel is unavailable — A2A tasks will fail at prompt assembly; set `model:` (and `provider:`) in the plugin config')
  }

  // -- chatelaine + operator book ---------------------------------------------
  // Operators are sessions, so their lifetime is ours to manage: a handle per
  // accepted task, seven days by default, pruned by archiving the session and
  // dropping the record (the shipped surface has no session deletion).
  // (houseWorkspace and the chatelaine runtime are created above, before tool
  // registration — §20.16 gate key ordering.)
  const operatorCwd = config.chatelaine?.cwd ?? houseWorkspace
  const operators = new OperatorBook({
    file: join(stateDir, 'operators.json'),
    ttlMs: config.chatelaine?.operatorTtlMs ?? DEFAULT_OPERATOR_TTL_MS,
    logger,
  })
  try {
    await operators.init()
  } catch (error) {
    logger.warn(`dsh-nuncia: operator book unusable — ${error instanceof Error ? error.message : String(error)}`)
  }
  if (chatelaine !== undefined && config.chatelaine?.enabled !== false) {
    const ready = await chatelaine.ensure().catch((error) => ({
      ok: false,
      reason: error instanceof Error ? error.message : String(error),
    }))
    if (ready.ok === false) {
      logger.warn(`dsh-nuncia: the chatelaine could not be started — ${ready.reason}`)
    } else {
      logger.info?.(
        `dsh-nuncia: chatelaine ready — ${ready.sessionId}`
        + `${ready.created === true ? ' (created)' : ''}`
        + `${ready.briefed === true ? ' briefed' : ''}`
        + `${ready.workspace === true ? '' : ' (NOT in a workspace: it will not be listed in the UI)'}`,
      )
    }
  }
  if (config.chatelaine?.tools !== false) {
    registerChatelaineTools(ctx, { chatelaine, operators, announcement, outbound, records, logger })
  }

  const agentCard = makeAgentCard(config, path, await listPresetIds(ctx), authority)
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    taskStore,
    makeExecutor(ctx, records, config, cwd, metrics, resolvedModel, authority, { chatelaine, operators, operatorCwd, fireHook: securityHooks.fireHook }),
  )
  const jsonRpc = new JsonRpcTransportHandler(requestHandler)

  /** @param {any} req @param {any} res */
  const handleHttp = async (req, res) => {
    const url = req.url ?? '/'
    metrics.requests++
    if (req.method === 'GET' && url === agentCardPath) {
      // The card is a discovery surface, so it is auth-gated by default
      // (§20.12 P3.0): looking at a node requires the same bearer as speaking
      // to it. `agentCard.public: true` is the explicit opt-out.
      if (config.agentCard?.public !== true && !isAuthorized(req, auth)) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized', detail: 'a valid bearer token is required to read the agent card' }))
        return
      }
      sendJson(res, AgentCard.toJSON(makeAgentCard(config, path, await listPresetIds(ctx), authority, { announcement, adopted, platform, since: bootedAt })))
      return
    }
    if (config.metricsPath !== undefined && req.method === 'GET' && url === config.metricsPath) {
      sendText(res, renderMetrics(metrics, records.size))
      return
    }
    if (adminRoutes.has(url)) {
      if (!isAuthorized(req, auth)) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized', detail: 'a valid bearer token is required' }))
        return
      }
      if (req.method === 'GET' && url === `${adminPath}/status`) {
        sendJson(res, {
          enabled,
          activeTasks: records.size,
          ...metrics,
          tasks: [...records.values()].map((record) => ({
            taskId: record.taskId,
            terminal: record.terminalPublished,
            authority: record.authority === undefined
              ? null
              : {
                  level: record.authority.level,
                  scope: record.authority.scope,
                  // Who claimed it and which key signed it: the two facts an
                  // operator needs to tell a real grant from a bounced one.
                  origin: record.authority.origin,
                  kid: record.authority.kid ?? null,
                  expiresAt: record.authority.exp,
                },
          })),
          authority: describeAuthority(authority),
          house: house === undefined
            ? null
            : {
                workspace: house.workspace,
                rulesFile: house.rulesFile,
                git: house.git,
              },
          // The full picture, not just the id: /status is how a human finds the
          // session they are supposed to talk to.
          chatelaine: await chatelaine.describe(),
          // Whether A2A work keeps running while the metered gate is held
          // (DESIGN §20.5). The bridge's flag decides the in-process gate; the
          // daemon's flag decides the netgate; this is what the node reports.
          a2aExempt: config.authority?.allowA2AOnMetered === true,
          identity: {
            name: adopted.name,
            nameSource: adopted.source,
            platform: platform.label,
            since: new Date(bootedAt).toISOString(),
            announcement: announcement.get(),
            kid: authority.nodeKey?.kid ?? null,
            authSource: auth.source,
            cardPublic: config.agentCard?.public === true,
          },
          operators: [...operators.list()].map((operator) => ({
            handle: operator.handle,
            taskId: operator.taskId,
            level: operator.level,
            scope: operator.scope ?? null,
            state: operator.state,
            expiresAt: operator.expiresAt,
          })),
        })
        return
      }
      if (req.method === 'POST' && (url === `${adminPath}/enable` || url === `${adminPath}/disable`)) {
        enabled = url.endsWith('/enable')
        sendJson(res, { enabled })
        return
      }
      if (req.method === 'GET' && url === `${adminPath}/requests`) {
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'approval administration is loopback-only' }))
          return
        }
        sendJson(res, {
          ok: true,
          approvalMode: config.authority?.approval ?? 'auto',
          pending: broker?.list() ?? [],
        })
        return
      }
      if (req.method === 'POST' && url === `${adminPath}/requests/decide`) {
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'approval administration is loopback-only' }))
          return
        }
        if (broker === undefined) {
          res.writeHead(409, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'authority layer is disabled' }))
          return
        }
        let payload
        try {
          payload = JSON.parse(await readBody(req, 16 * 1024))
        } catch (error) {
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: `invalid request body: ${error instanceof Error ? error.message : String(error)}` }))
          return
        }
        const decided = broker.decide(payload?.id, payload?.decision)
        // A decision that matched nothing is not an error worth a 500: the
        // request may have timed out while the human was deciding.
        sendJson(res, { ok: true, decided })
        return
      }
      if (url === `${adminPath}/chatelaine`) {
        // Who the human's representative is, where it works, and whether it has
        // seen its brief. Loopback-only: it names a private session.
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'chatelaine administration is loopback-only' }))
          return
        }
        if (req.method !== 'GET') {
          res.writeHead(405, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'method not allowed' }))
          return
        }
        sendJson(res, { ok: true, chatelaine: await chatelaine.describe() })
        return
      }
      if (req.method === 'POST' && url === `${adminPath}/chatelaine/new`) {
        // Cut over to a fresh chatelaine session. The old thread is never
        // deleted — its id is recorded as previousSessionId — and the new one is
        // briefed and woken so the human can open it and paste a handoff.
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'chatelaine administration is loopback-only' }))
          return
        }
        const moved = await chatelaine.newSession()
        if (moved.ok !== true) {
          res.writeHead(500, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: moved.reason ?? 'the chatelaine session could not be created' }))
          return
        }
        sendJson(res, {
          ok: true,
          sessionId: moved.sessionId,
          previousSessionId: moved.previousSessionId ?? null,
        })
        return
      }
      if (url === `${adminPath}/rules`) {
        // The rules are standing instructions to every operator, and they carry
        // the human's private context: reading them is loopback-only too.
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'house administration is loopback-only' }))
          return
        }
        if (house === undefined) {
          res.writeHead(409, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'house is disabled or unavailable' }))
          return
        }
        if (req.method === 'GET') {
          sendJson(res, {
            ok: true,
            workspace: house.workspace,
            rulesFile: house.rulesFile,
            rules: await house.read().catch(() => ''),
            git: house.git,
            history: await house.log({ limit: 10 }),
          })
          return
        }
        if (req.method === 'PUT') {
          let payload
          try {
            payload = JSON.parse(await readBody(req, 256 * 1024))
          } catch (error) {
            res.writeHead(400, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: `invalid request body: ${error instanceof Error ? error.message : String(error)}` }))
            return
          }
          const written = await house.write(payload?.rules, { summary: payload?.summary })
          if (!written.ok) {
            res.writeHead(500, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: written.reason ?? 'rules write failed', changed: written.changed }))
            return
          }
          sendJson(res, { ok: true, changed: written.changed, commit: written.commit ?? null, git: house.git })
          return
        }
        res.writeHead(405, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'method not allowed' }))
        return
      }
      if (url === `${adminPath}/announcement`) {
        // The announcement is the node's public signboard: what it is doing
        // right now, in one line. It is the only free text a node publishes,
        // and it is the chatelaine's to write.
        if (req.method === 'GET') {
          sendJson(res, { ok: true, announcement: announcement.get(), maxLength: MAX_ANNOUNCEMENT_LENGTH })
          return
        }
        if (req.method === 'PUT') {
          if (!isLoopbackRequest(req)) {
            res.writeHead(403, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: 'announcement administration is loopback-only' }))
            return
          }
          let payload
          try {
            payload = JSON.parse(await readBody(req, 8 * 1024))
          } catch (error) {
            res.writeHead(400, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: `invalid request body: ${error instanceof Error ? error.message : String(error)}` }))
            return
          }
          const written = await announcement.set(payload?.announcement)
          if (!written.ok) {
            res.writeHead(400, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: written.reason ?? 'announcement rejected' }))
            return
          }
          sendJson(res, { ok: true, announcement: written.value })
          return
        }
        res.writeHead(405, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'method not allowed' }))
        return
      }
      if (url === `${adminPath}/operators`) {
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'operator administration is loopback-only' }))
          return
        }
        const now = Date.now()
        sendJson(res, {
          ok: true,
          chatelaine: await chatelaine.describe(),
          ttlMs: operators.ttlMs,
          operators: operators.list().map((operator) => ({
            handle: operator.handle,
            taskId: operator.taskId,
            level: operator.level,
            scope: operator.scope ?? null,
            origin: operator.origin ?? null,
            state: operator.state,
            createdAt: operator.createdAt,
            expiresAt: operator.expiresAt,
            ageMs: now - operator.createdAt,
          })),
        })
        return
      }
      if (req.method === 'POST' && url === `${adminPath}/operators/prune`) {
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'operator administration is loopback-only' }))
          return
        }
        let dryRun = false
        try {
          dryRun = JSON.parse(await readBody(req, 16 * 1024) || '{}')?.dryRun === true
        } catch {
          // A body-less prune is a real prune; an unparseable one is refused.
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'invalid request body' }))
          return
        }
        const removed = await pruneOperators({ ctx, operators, records, chatelaine, logger, dryRun })
        sendJson(res, {
          ok: true,
          dryRun,
          pruned: removed.length,
          handles: removed.map((operator) => operator.handle),
        })
        return
      }
      if (req.method === 'POST' && (url === `${adminPath}/mint` || url === `${adminPath}/revoke`)) {
        // Minting/revoking is the user's own act: loopback-only, because a
        // bearer token alone would let any paired peer grant itself intent.
        if (!isLoopbackRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'authority administration is loopback-only' }))
          return
        }
        if (!authority.enabled) {
          res.writeHead(409, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: `authority layer unavailable: ${authority.error ?? 'disabled'}` }))
          return
        }
        let payload
        try {
          payload = JSON.parse(await readBody(req, 64 * 1024))
        } catch (error) {
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: `invalid request body: ${error instanceof Error ? error.message : String(error)}` }))
          return
        }
        if (url.endsWith('/mint')) {
          try {
            const grant = authority.grants.mint({
              ...(typeof payload?.level === 'string' ? { level: payload.level } : {}),
              ...(typeof payload?.scope === 'string' ? { scope: payload.scope } : {}),
              ...(typeof payload?.ttlMs === 'number' ? { ttlMs: payload.ttlMs } : {}),
              target: payload?.target,
            })
            // The mint response is the one place a signed envelope is handed
            // out: it goes to the local operator over loopback, never to a tool.
            sendJson(res, {
              ok: true,
              grant: {
                id: grant.id,
                level: grant.level,
                scope: grant.scope,
                origin: grant.origin,
                target: grant.target,
                issuedAt: grant.iat,
                expiresAt: grant.exp,
                envelope: grant.envelope,
              },
            }, 201)
          } catch (error) {
            res.writeHead(400, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }))
          }
          return
        }
        const revoked = authority.grants.revoke(payload?.id)
        sendJson(res, { ok: true, revoked })
        return
      }
    }
    if (req.method === 'POST' && url === path) {
      if (!isAuthorized(req, auth)) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized', detail: 'a valid bearer token is required' }))
        return
      }
      if (!enabled) {
        res.writeHead(503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'a2a is disabled' }))
        return
      }
      const body = await readBody(req, 1024 * 1024)
      const context = new ServerCallContext({
        requestedVersion: req.headers['a2a-version'] ?? '1.0',
      })
      /** @type {any} */
      let requestBody = body
      try {
        requestBody = normalizeA2ARole(JSON.parse(body))
      } catch {
        // Leave the original string to the SDK so malformed JSON still gets
        // the protocol's own JSON-RPC parse error.
      }
      const result = await jsonRpc.handle(requestBody, context)
      if (isAsyncIterable(result)) {
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
        })
        try {
          for await (const event of result) {
            res.write(formatSSEEvent(event))
          }
        } finally {
          res.end()
        }
      } else {
        sendJson(res, result)
      }
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'not found' }))
  }

  // Where the routes live. `auto` (the historical behavior) prefers the host's
  // web server when one exists; `standalone` always binds host/port. Prefer
  // standalone on a node whose peers need a stable, advertised address: mounting
  // on the harness port makes `agentCard.url` a lie and puts the A2A endpoint
  // behind whatever else that port does.
  const mount = config.mount ?? 'auto'
  const webServer = mount === 'standalone'
    ? undefined
    : /** @type {WebServerLike|undefined} */ (ctx.get('webServer'))
  if (mount === 'webserver' && webServer === undefined) {
    logger.warn('dsh-nuncia: mount "webserver" requested but no webServer service is available — falling back to a standalone listener')
  }
  if (webServer !== undefined) {
    const disposers = [
      webServer.register({ kind: 'exact', path: agentCardPath, handler: handleHttp }),
      webServer.register({ kind: 'exact', path, handler: handleHttp }),
      ...config.metricsPath === undefined ? [] : [webServer.register({ kind: 'exact', path: config.metricsPath, handler: handleHttp })],
      webServer.register({ kind: 'exact', path: `${adminPath}/status`, handler: handleHttp }),
      webServer.register({ kind: 'exact', path: `${adminPath}/enable`, handler: handleHttp }),
      webServer.register({ kind: 'exact', path: `${adminPath}/disable`, handler: handleHttp }),
      webServer.register({ kind: 'exact', path: `${adminPath}/mint`, handler: handleHttp }),
      webServer.register({ kind: 'exact', path: `${adminPath}/revoke`, handler: handleHttp }),
      webServer.register({ kind: 'exact', path: `${adminPath}/requests`, handler: handleHttp }),
      webServer.register({ kind: 'exact', path: `${adminPath}/requests/decide`, handler: handleHttp }),
    ]
    ctx.effect(() => () => {
      for (const dispose of disposers) dispose()
    }, 'dsh-nuncia.routes')
  } else {
    // Synchronous request callback captures async rejections so they cannot
    // become unhandledRejection and take down the host process.
    /** @param {any} req @param {any} res */
    const requestHandler = (req, res) => {
      void handleHttp(req, res).catch((/** @type {unknown} */ error) => {
        logger.error(`dsh-nuncia: HTTP request failed: ${String(error)}`)
        if (res.writableEnded) return
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
          res.end(JSON.stringify({ error: 'internal server error' }))
        } else {
          // Headers already sent — nothing to return but the close.
          res.end()
        }
      })
    }
    const server = createServer(requestHandler)
    server.on('error', (/** @type {unknown} */ error) => {
      logger.error(`dsh-nuncia: HTTP server error: ${String(error)}`)
    })
    server.listen(config.port ?? 4123, config.host ?? '127.0.0.1')
    ctx.effect(() => () => {
      server.close()
      server.closeAllConnections?.()
    }, 'dsh-nuncia.http')
  }

  // Stream committed assistant messages and terminal status to the owning A2A
  // task's event bus. This gives message/sendStreaming real committed-message
  // events instead of only a final snapshot.
  ctx.on('session/event', (session, event) => {
    // DSH session shape drifts across trains: some expose `session.header.id`,
    // older views a flat `session.id`. Accept both — a missing id must never
    // crash the shared event bus for other listeners.
    const sid = session?.header?.id ?? session?.id
    if (sid === undefined) return
    // The record is keyed by TASK id, but the session id now carries the A2A
    // tag (`a2a-op-<level>-<taskId>`), so the task id is the tail of the
    // session id. Resolve both ways: an exact hit, else the tagged tail.
    const record = records.get(sid) ?? records.get(taskIdOfSessionId(sid))
    if (record === undefined) return
    const eventBus = record.eventBus
    if (eventBus === undefined) return
    if (event.type === 'assistant/message') {
      const parts = contentBlocksToParts(event.data.message.content)
      if (parts.length > 0) {
        eventBus.publish(AgentEvent.artifactUpdate({
          taskId: record.taskId,
          contextId: record.contextId,
          artifact: makeArtifact(record.taskId, parts),
          append: false,
          lastChunk: true,
          metadata: undefined,
        }))
      }
    } else if (event.type === 'turn/end' && !record.terminalPublished) {
      record.terminalPublished = true
      // `turn/end.reason.kind` is one of completed | max-tokens | blocked |
      // aborted | error (dsh-agent-loop). Only `completed` is success: an
      // aborted turn (including an A2A cancel) and a blocked or truncated one
      // once all reported COMPLETED to the client, which is a lie the peer has
      // no way to detect.
      const reason = event.data.reason ?? {}
      const kind = typeof reason.kind === 'string' ? reason.kind : 'error'
      const cancelledByUser = kind === 'aborted' && reason.reason?.kind === 'user'
      const state = kind === 'completed'
        ? TaskState.TASK_STATE_COMPLETED
        : cancelledByUser ? TaskState.TASK_STATE_CANCELED : TaskState.TASK_STATE_FAILED
      // Surface the DSH turn-end reason to the A2A client: without it a
      // failed task is undiagnosable remotely (live lesson: a FAILED task
      // with no detail once cost a whole debug round). The reason payload's
      // message/error fields drift between plain strings and objects across
      // trains — stringified fallback keeps us honest either way.
      const rawDetail = reason.error?.message
        ?? reason.message
        ?? reason.error
        ?? (kind === 'aborted' ? reason.reason?.reason ?? reason.reason?.kind : undefined)
      const detail = typeof rawDetail === 'string'
        ? rawDetail
        : (rawDetail !== undefined && rawDetail !== null ? JSON.stringify(rawDetail) : '')
      const reasonText = [kind, detail].filter(s => s !== '').join(': ')
      const taskStatus = {
        state,
        message: state !== TaskState.TASK_STATE_COMPLETED && reasonText
          ? {
              messageId: `reason-${record.taskId}`,
              role: 'ROLE_AGENT',
              parts: [{ content: { $case: 'text', value: reasonText }, filename: '', mediaType: 'text/plain', metadata: undefined }],
              metadata: undefined,
            }
          : undefined,
        timestamp: new Date().toISOString(),
      }
      if (state === TaskState.TASK_STATE_COMPLETED) metrics.completedTasks++
      else if (state === TaskState.TASK_STATE_CANCELED) metrics.canceledTasks++
      else metrics.failedTasks++
      eventBus.publish(AgentEvent.statusUpdate({
        taskId: record.taskId,
        contextId: record.contextId,
        status: taskStatus,
        metadata: undefined,
      }))
      void operators?.markDone(record.taskId)
      // Supervision (§20.11 P2.4): an operator that stops for any reason other
      // than success is something the chatelaine should know about — the human
      // otherwise sees a task that simply went quiet.
      if (state !== TaskState.TASK_STATE_COMPLETED) {
        void chatelaine?.report(
          `Operator ${record.handle ?? record.taskId} ended ${state === TaskState.TASK_STATE_CANCELED ? 'cancelled' : 'without finishing'} (${reasonText || kind}).`,
        )
      }
    }
  })

  // Human-in-the-loop: when a bridge-owned agent requests approval, publish
  // INPUT_REQUIRED and wait for the A2A client to send a follow-up message on
  // the same Task. The follow-up text resolves the pending approval.
  ctx.on('approval/request', (request, next) => {
    const record = ownedRecord(request.agent)
    if (record === undefined || request.callId === undefined) return next()
    return new Promise((resolve) => {
      record.pendingApproval = { request, resolve }
      record.eventBus?.publish(AgentEvent.statusUpdate({
        taskId: record.taskId,
        contextId: record.contextId,
        status: status(TaskState.TASK_STATE_INPUT_REQUIRED),
        metadata: undefined,
      }))
    })
  })

  // Asking the human from an operator session is a dead end on an A2A node:
  // nobody is watching that session, so the ask would hang until the turn dies.
  // Forward the question to the chatelaine (which decides whether the human
  // must actually see it) and answer the asker at once — hanging would burn its
  // turn and leave the A2A task looking stuck. Every other session falls
  // through to the real UI via `next()`.
  if (config.chatelaine?.forwardQuestions !== false) {
    ctx.on('user-questions/request', async (request, next) => {
      const id = request?.agent?.id
      if (id === undefined) return next()
      const record = records.get(id) ?? records.get(taskIdOfSessionId(id))
      if (record === undefined) return next()
      const questions = request.questions ?? []
      const asked = questions.map((question) => question.question).join(' / ')
      const forwarded = await chatelaine.report(
        `Operator ${record.handle ?? record.taskId} asks: ${asked}\n(Answered in place: the human is not in that session. The operator proceeds on its judgement unless you say otherwise.)`,
        { wake: true },
      )
      return {
        answers: questions.map((question) => ({
          id: question.id,
          selected: [],
          custom: forwarded.delivered
            ? 'The human is not watching this session. Your question was forwarded to the chatelaine; proceed with your best judgement within your authority and keep it informed.'
            : 'No human is available. Proceed with your best judgement within your authority, or report to the chatelaine and stop.',
        })),
      }
    })
  }

  /** @type {any} */
  let ttlTimer
  if (config.taskTtlMs !== undefined) {
    const ttlMs = config.taskTtlMs
    ttlTimer = setInterval(() => {
      void cleanupExpired(records, ttlMs, logger).catch((/** @type {unknown} */ error) => {
        logger.error(`dsh-nuncia: TTL cleanup failed: ${String(error)}`)
      })
    }, Math.min(ttlMs, 60_000))
    // Unref: a plugin timer must never be the reason a host process refuses to
    // exit (it also keeps the win32 libuv close-during-close assertion away in
    // the standalone harnesses).
    ttlTimer.unref?.()
  }

  // Expiry sweep for authority windows. A window can lapse while the task sits
  // idle, and the agent must be told then — not only when the peer happens to
  // send another message. The notice is queued (`inject`), so it costs nothing
  // until the next turn; the exact expiry is still enforced by verification.
  /** @type {any} */
  let noticeTimer
  if (authority.enabled && config.authority?.notices !== false) {
    noticeTimer = setInterval(() => {
      const now = Date.now()
      for (const record of records.values()) {
        const grant = record.authority
        if (grant === undefined || now <= grant.exp) continue
        record.authority = undefined
        deliverNotice(record, intentLapsedNotice(grant), logger)
        // The chatelaine is the human's bookkeeper: it must learn that a window
        // lapsed even if nothing is running in that task's thread (m05102:
        // "does the chatelaine get notified when the elevated authorization of
        // a previous communication expires?"). report() fails soft.
        void chatelaine?.report?.(`[authority] The ${grant.level ?? 'peer'} window for ${record.handle ?? `task ${record.taskId}`} (peer "${grant.origin ?? 'unknown'}") expired.`)
      }
    }, config.authority?.noticeSweepMs ?? NOTICE_SWEEP_MS)
    noticeTimer.unref?.()
  }

  // Operator expiry (§20.4: seven days by default). Pruning archives the
  // session — the shipped surface has no session deletion, so archive is the
  // ceiling — drops the record and the handle with it, and tells the
  // chatelaine once. The task record is disposed in the same pass so a pruned
  // operator cannot keep a live agent around.
  /** @type {any} */
  let operatorTimer
  if (config.chatelaine?.tools !== false) {
    const sweep = Math.min(config.chatelaine?.operatorTtlMs ?? DEFAULT_OPERATOR_TTL_MS, 60_000)
    operatorTimer = setInterval(() => {
      void pruneOperators({ ctx, operators, records, chatelaine, logger }).catch((/** @type {unknown} */ error) => {
        logger.warn(`dsh-nuncia: operator prune failed — ${String(error)}`)
      })
    }, sweep)
    operatorTimer.unref?.()
  }

  ctx.effect(() => () => {
    if (ttlTimer !== undefined) clearInterval(ttlTimer)
    if (noticeTimer !== undefined) clearInterval(noticeTimer)
    if (operatorTimer !== undefined) clearInterval(operatorTimer)
    broker?.cancelAll()
    return quiesce(records, logger)
  }, 'dsh-nuncia.tasks')
}

/**
 * Archive, forget and report expired operators.
 * @param {{ctx:any, operators:OperatorBook, records:Map<string,any>, chatelaine:any, logger:any, dryRun?:boolean}} input
 */
async function pruneOperators({ ctx, operators, records, chatelaine, logger, dryRun = false }) {
  const removed = dryRun ? operators.expired() : await operators.prune()
  if (removed.length === 0) return []
  for (const operator of removed) {
    if (dryRun) continue
    try {
      await ctx.get?.('workspaceRegistry')?.archiveSession?.(SessionId(operator.sessionId), { stopActivity: true })
    } catch (error) {
      logger.warn(`dsh-nuncia: could not archive operator session ${operator.sessionId} — ${error instanceof Error ? error.message : String(error)}`)
    }
    const live = records.get(operator.taskId)
    if (live !== undefined) {
      records.delete(operator.taskId)
      try { await live.dispose?.() } catch { /* already gone */ }
    }
  }
  if (!dryRun) {
    await chatelaine?.report?.(`Pruned ${removed.length} expired operator${removed.length === 1 ? '' : 's'}: ${removed.map((operator) => operator.handle).join(', ')}.`)
  }
  return removed
}

// -- AgentCard ------------------------------------------------------------------

/**
 * Build the AgentCard served at `agentCardPath`.
 *
 * The card is deliberately minimal (§20.12 P3.0): the operator's verdict was
 * that a card is a *discovery* surface, so it should say very little — name,
 * platform, when this node last came up, and a chatelaine-managed
 * announcement. Peer address memory lives in Sylvia's registry, not here.
 *
 * Custom fields ride in `capabilities.extensions`: the SDK's `AgentCard.toJSON`
 * drops unknown top-level fields, and extensions are the protocol's own
 * place for node-specific data.
 *
 * @param {A2aServerConfig} config
 * @param {string} path
 * @param {string[]} presetIds
 * @param {AuthorityRuntime} [authority]
 * @param {{announcement?: {get: () => string}, adopted?: {name: string, source: string}, platform?: {label: string, platform: string, arch: string}, since?: number}} [identity]
 */
function makeAgentCard(config, path, presetIds = [], authority, identity = {}) {
  const host = config.host ?? '127.0.0.1'
  const port = config.port ?? 4123
  const nodeName = identity.adopted?.name ?? authority?.nodeName ?? config.authority?.nodeName ?? 'nuncia'
  const skills = (config.agentCard?.skills ?? []).map(skill => ({
    id: skill.id,
    name: skill.name,
    description: skill.description,
    tags: skill.tags ?? [],
    examples: skill.examples ?? [],
    inputModes: skill.inputModes ?? ['text/plain'],
    outputModes: skill.outputModes ?? ['text/plain'],
    securityRequirements: [],
  }))
  return {
    // The card's face is the node's adopted name: humans tell chatelaines and
    // nodes apart by the name the list gave them (m05102). A configured
    // agentCard.name still wins for deployments that want branding.
    name: config.agentCard?.name ?? nodeName,
    description: config.agentCard?.description ?? 'A DeepSeek Harness agent exposed over A2A',
    supportedInterfaces: [{
      url: config.agentCard?.url ?? `http://${host}:${port}${path}`,
      protocolBinding: 'JSONRPC',
      tenant: '',
      protocolVersion: '1.0',
    }],
    provider: undefined,
    version: config.agentCard?.version ?? '0.1.0',
    documentationUrl: undefined,
    capabilities: {
      streaming: config.agentCard?.capabilities?.streaming ?? true,
      pushNotifications: config.agentCard?.capabilities?.pushNotifications ?? false,
      extensions: [
        {
          uri: 'https://nucia.local/a2a/preset-selection',
          description: 'To select an agent preset for a task, include "agentPreset" (or "preset") in SendMessage/SendStreamingMessage params.metadata.',
          required: false,
          params: {
            metadataKey: 'agentPreset',
            aliases: ['preset'],
            default: config.agentPreset ?? null,
            presets: presetIds,
          },
        },
        ...authority?.enabled === true ? [{
          uri: 'https://nuncia.local/a2a/authority',
          description: 'User intent/override claims travel in a signed metadata.authority envelope (DESIGN §20). Message text is never authority.',
          required: false,
          params: {
            metadataKey: 'authority',
            envelopeVersion: authority.envelopeVersion,
            levels: ['intent', 'override'],
            maxWindowMs: authority.maxWindowMs,
            node: authority.nodeName,
            // Public key id of *this* node: a peer uses it to pin the key that
            // signs our grants. The key itself is distributed separately —
            // a card is unauthenticated, so it cannot be the trust anchor.
            kid: authority.nodeKey?.kid ?? null,
            peerKeys: authority.gate.describe().peers
              .filter((peer) => peer.canVerifyV2)
              .map((peer) => ({ name: peer.name, kid: peer.kid })),
          },
        }] : [],
        // The minimal node card (P3.0): who this is, what it runs on, when it
        // last came up, and what it wants to say. Nothing else — no peers, no
        // addresses, no capabilities inventory.
        {
          uri: 'https://nuncia.local/a2a/node',
          description: 'Minimal node identity: name, platform, last start, announcement.',
          required: false,
          params: {
            name: nodeName,
            platform: identity.platform?.label ?? `${process.platform}-${process.arch}`,
            since: identity.since === undefined ? undefined : new Date(identity.since).toISOString(),
            announcement: identity.announcement?.get() ?? '',
          },
        },
      ],
      extendedAgentCard: false,
    },
    securitySchemes: {},
    securityRequirements: [],
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills,
    signatures: [],
    iconUrl: undefined,
  }
}

// -- executor --------------------------------------------------------------------

/**
 * Create the A2A AgentExecutor that maps Tasks to DSH agents.
 * @param {any} ctx
 * @param {Map<string, TaskRecord>} records
 * @param {A2aServerConfig} config
 * @param {string} cwd
 * @param {Metrics} metrics
 * @param {{provider?: string, model?: string}|undefined} resolvedModel
 * @param {AuthorityRuntime} authority
 */
function makeExecutor(ctx, records, config, cwd, metrics, resolvedModel, authority, layer = {}) {
  const agents = ctx.agents
  const logger = ctx.logger
  const noticesEnabled = config.authority?.notices !== false
  const { chatelaine, operators } = layer
  /** Operator sessions work in the house, not the plugin's launch directory. */
  const operatorCwd = layer.operatorCwd ?? cwd

  return {
    async execute(requestContext, eventBus) {
      const taskId = requestContext.taskId
      const contextId = requestContext.contextId
      const presetId = resolvePreset(requestContext.request.metadata, config.agentPreset)

      // Authority is re-decided for EVERY message, never latched onto the task
      // (§20.1 rule 2). A grant that lapsed between two messages means this
      // one arrives as `peer` — the remote assists the chatelaine again until
      // it presents a fresh grant, while work already issued keeps running.
      const verdict = authority.enabled
        ? authority.gate.verify(requestContext.request.metadata)
        : { ok: true, level: 'peer', carried: false }
      if (!verdict.ok) {
        metrics.authorityRejected++
        logger.warn(`dsh-nuncia: authority rejected on task ${taskId} — ${verdict.message}`)
        recordSecurityEvent(ctx, authority, logger, {
          kind: 'authority-rejected',
          reason: verdict.reason,
          detail: { ...verdict.detail, taskId },
        }, { chatelaine, fireHook: layer.fireHook })
      }
      const claimed = verdict.ok && verdict.carried
        ? {
            level: verdict.level,
            scope: verdict.scope,
            origin: verdict.origin,
            // v2 only: which key signed it. Absent for legacy v1 grants, which
            // is exactly the fact an operator needs to tell the schemes apart.
            ...verdict.kid === undefined ? {} : { kid: verdict.kid },
            exp: verdict.exp,
            jti: verdict.jti,
          }
        : undefined

      // Routing is decided HERE and only here (§20.15). A peer addresses a
      // node; it never names an operator, a handle or a session — it cannot,
      // because nothing on the wire carries one. What the node does with a
      // request is its own business, which is also what keeps a compromised or
      // curious peer from steering someone else's conversation: continuity is
      // keyed by the exchange id below plus the verified origin of the claim.

      // §20.16: chatelaine-to-chatelaine addressing is WITHDRAWN (the plan's
      // first "stop" pill: message_peer_chatelaine is removed). Honoring
      // metadata.toChatelaine would let a remote chatelaine write directly
      // into THIS node's representative's context — the social-engineering
      // surface the authority layer exists to close. A peer reaches this node
      // as tasks; its OPERATOR works here and escalates to this node's
      // chatelaine, which never mints a grant for that purpose. The refusal is
      // explicit, not silent, so a peer still running the withdrawn tool sees
      // why its message did not deliver.
      if (requestContext.request.metadata?.toChatelaine === true) {
        const origin = claimed?.origin ?? 'an unnamed peer'
        logger.warn(`dsh-nuncia: chatelaine-addressing is withdrawn — refusing ${origin} on task ${taskId}`)
        recordSecurityEvent(ctx, authority, logger, {
          kind: 'authority-rejected',
          reason: 'chatelaine-channel-withdrawn',
          detail: { origin, taskId },
        }, { chatelaine, fireHook: layer.fireHook })
        throw new Error(
          'metadata.toChatelaine is withdrawn (DESIGN §20.16): this node routes peers to operators — '
          + 'the operator that receives your task reports to this node\'s chatelaine, and grant minting is '
          + 'refused while that channel exists',
        )
      }

      let record = records.get(taskId)
      /** The window that was in force for the *previous* message on this task. */
      const previousWindow = record?.authority
      if (record === undefined && requestContext.contextId !== undefined) {
        // Context continuity: continued A2A from the same source lands on the
        // SAME operator session by default. The SDK issues a fresh taskId per
        // SendMessage, but the caller supplies the contextId of the exchange;
        // matching the origin too keeps one peer from steering another peer's
        // operator. A terminal task keeps its history: follow-ups ride the
        // same idle session, which is what "same operator" means.
        for (const candidate of records.values()) {
          if (candidate.contextId !== requestContext.contextId) continue
          if ((candidate.authority?.origin ?? '') !== (claimed?.origin ?? '')) continue
          record = candidate
          break
        }
        if (record !== undefined) {
          // Re-key onto this request's task id: the wire caller only knows the
          // new id, and session/event publication carries record.taskId. The
          // old id stays as an ALIAS — the session id tag still carries the
          // original task id (the v4 header is immutable), and the shared
          // session/event listener resolves records through that tag.
          const previousTaskId = record.taskId
          record.taskId = taskId
          record.eventBus = eventBus
          record.terminalPublished = false
          records.set(taskId, record)
          records.set(previousTaskId, record)
          // Re-key the operator book the same way, so the handle the peer was
          // given keeps working for `message_local_session` after the turn.
          const bookRecord = record.handle === undefined ? undefined : operators?.get(record.handle)
          if (bookRecord !== undefined) {
            try {
              await operators.add({
                taskId,
                sessionId: bookRecord.sessionId ?? record.sessionId,
                level: bookRecord.level,
                ...(bookRecord.scope === undefined ? {} : { scope: bookRecord.scope }),
                ...(bookRecord.origin === undefined ? {} : { origin: bookRecord.origin }),
                ...(bookRecord.kid === undefined ? {} : { kid: bookRecord.kid }),
                cwd: bookRecord.cwd ?? operatorCwd,
              })
            } catch (error) {
              logger.warn(`dsh-nuncia: could not re-key operator ${record.handle} to task ${taskId} — ${error instanceof Error ? error.message : String(error)}`)
            }
          }
        }
      }
      // True only when this request opens a NEW operator session (the create
      // path below); continuations ride an existing session and get no preamble.
      let freshOperator = false
      if (record === undefined) {
        if (!isAbsolute(operatorCwd)) throw new Error(`cwd must be an absolute path: ${operatorCwd}`)
        // The session id carries the A2A tag (the durable header cannot: the
        // v4 format allows only `origin: "subagent"`). The task id stays the
        // record key; the session id is the tagged one.
        freshOperator = true
        const sessionId = SessionId(`${A2A_OPERATOR_PREFIX}${claimed?.level ?? 'peer'}-${taskId}`)
        const created = await agents.create({
          sessionId,
          meta: {
            cwd: operatorCwd,
            ...(presetId !== undefined ? { agentPreset: presetId } : {}),
          },
          agentOptions: agentOptions(resolvedModel, requestContext.request.metadata),
          ...(presetId !== undefined ? {
            setup: async (/** @type {any} */ agentCtx) => {
              const presets = ctx.get('agentPresets')
              if (presets === undefined) {
                throw new Error(`dsh-nuncia: agentPreset "${presetId}" configured but agentPresets service is unavailable`)
              }
              // Resolve first: mount() takes the canonical id, and resolve() is
              // what raises agent-preset/not-found with the available list
              // instead of failing deeper with a bare "requires a scope".
              const resolved = await presets.resolve(presetId)
              await presets.mount(agentCtx, resolved.id)
            },
          } : {}),
        })
        // 1. Give the operator a handle and a brief *before* its first turn, so
        //    the very first model call already knows its authority and its
        //    reporting duty. `inject` is durable and starts no turn; the
        //    followup below opens the turn with the brief already in the inbox.
        let operator
        try {
          operator = await operators?.add({
            taskId,
            sessionId: String(sessionId),
            level: claimed?.level ?? 'peer',
            ...(claimed?.scope === undefined ? {} : { scope: claimed.scope }),
            ...(claimed?.origin === undefined ? {} : { origin: claimed.origin }),
            ...(claimed?.kid === undefined ? {} : { kid: claimed.kid }),
            cwd: operatorCwd,
          })
        } catch (error) {
          logger.warn(`dsh-nuncia: could not record operator for task ${taskId} — ${error instanceof Error ? error.message : String(error)}`)
        }
        record = {
          taskId,
          contextId,
          sessionId: String(sessionId),
          agent: created.agent,
          dispose: () => created.dispose(),
          eventBus,
          terminalPublished: false,
          createdAt: Date.now(),
          authority: claimed,
          handle: operator?.handle,
        }
        records.set(taskId, record)
        metrics.totalTasks++
        if (operator !== undefined) {
          await chatelaine?.attachToWorkspace?.(String(sessionId))
          deliverNotice(record, operatorBrief({
            handle: operator.handle,
            taskId,
            nodeName: authority?.nodeName,
            // The roster the operator cannot otherwise discover (see the
            // operatorBrief comment): names with their verification state.
            peers: authority?.gate?.describe?.().peers ?? [],
            level: operator.level,
            ...(operator.scope === undefined ? {} : { scope: operator.scope }),
            ...(operator.origin === undefined ? {} : { origin: operator.origin }),
            ...(record.authority === undefined ? {} : { expiresAt: record.authority.exp }),
            workspace: operatorCwd,
          }), logger)
          void chatelaine?.report(
            `Contact: ${claimed?.origin ?? 'an unpaired peer'} opened task ${taskId} (${operator.handle}) as ${operator.level}${operator.scope === undefined ? '' : `, scope "${operator.scope}"`}. The operator is briefed and working.`,
          )
        }
      } else {
        record.contextId = contextId
        record.eventBus = eventBus
        record.authority = claimed
      }

      // Tell the agent what changed about this conversation (§20.8 revised):
      // a window opening, a window lapsing, or a claim that failed. The agent
      // gets facts and time bounds; never envelope bytes, never a signature.
      if (noticesEnabled) {
        if (record.authority !== undefined && (previousWindow === undefined || previousWindow.jti !== record.authority.jti)) {
          deliverNotice(record, intentGrantedNotice({ ...record.authority, expiresAt: record.authority.exp }), logger)
        } else if (record.authority === undefined && previousWindow !== undefined) {
          deliverNotice(record, intentLapsedNotice(previousWindow), logger)
        } else if (!verdict.ok && verdict.detail?.origin !== undefined) {
          deliverNotice(record, authorityRejectedNotice({ origin: verdict.detail.origin, reason: verdict.reason, message: verdict.message }), logger)
        }
      }

      if (record.pendingApproval !== undefined) {
        const pending = record.pendingApproval
        delete record.pendingApproval
        pending.resolve(parseApprovalDecision(requestContext.userMessage))
        await record.agent.whenIdle()
        if (!record.terminalPublished) {
          record.terminalPublished = true
          eventBus.publish(AgentEvent.statusUpdate({
            taskId,
            contextId,
            status: status(TaskState.TASK_STATE_COMPLETED),
            metadata: undefined,
          }))
        }
        return
      }

      eventBus.publish(AgentEvent.task({
        id: taskId,
        contextId,
        status: status(TaskState.TASK_STATE_SUBMITTED),
        artifacts: [],
        history: [],
        // The handle is the peer's handle on this operator: quoted later to
        // re-contact it (and by the chatelaine when it needs to answer).
        metadata: record.handle === undefined ? undefined : { handle: record.handle, level: record.authority?.level ?? 'peer' },
      }))
      eventBus.publish(AgentEvent.statusUpdate({
        taskId,
        contextId,
        status: status(TaskState.TASK_STATE_WORKING),
        metadata: undefined,
      }))

      const content = messageToContentBlocks(requestContext.userMessage)
      if (freshOperator) {
        // The first message of a fresh operator task: prepend the task brief so
        // the model answers the request instead of "verifying" it by exploring
        // the filesystem, configuration, or the network — the deep dives users
        // keep having to cancel (live finding, 2026-10-21).
        content.unshift({ type: 'text', text: operatorTaskPreamble(record, config) })
      }
      const message = createUserMessage({ content, source: { kind: 'user' } })
      record.agent.followup(message)

      await record.agent.whenIdle()
      if (!record.terminalPublished) {
        record.terminalPublished = true
        eventBus.publish(AgentEvent.statusUpdate({
          taskId,
          contextId,
          status: status(TaskState.TASK_STATE_COMPLETED),
          metadata: undefined,
        }))
      }
    },
    async cancelTask(taskId, eventBus) {
      const record = records.get(taskId)
      if (record === undefined) return
      if (record.pendingApproval !== undefined) {
        const pending = record.pendingApproval
        delete record.pendingApproval
        pending.resolve('cancelled')
      }
      record.agent.cancel({ kind: 'user' })
      await record.agent.whenIdle()
      // The turn/end that follows the cancel is `aborted:user`; mark the task
      // terminal here so the listener does not publish a second status.
      record.terminalPublished = true
      eventBus.publish(AgentEvent.statusUpdate({
        taskId,
        contextId: record.contextId,
        status: status(TaskState.TASK_STATE_CANCELED),
        metadata: undefined,
      }))
      metrics.canceledTasks++
    },
  }
}

/**
 * Dipose every bridge-owned agent and clear the task registry.
 * @param {Map<string, TaskRecord>} records
 * @param {any} logger
 */
async function quiesce(records, logger) {
  // Records may be aliased under several task ids (context continuity) — one
  // record, one teardown.
  const tasks = [...new Set(records.values())]
  records.clear()
  const results = await Promise.allSettled(tasks.map(async (record) => {
    await record.agent.whenIdle()
    await record.dispose()
  }))
  for (const result of results) {
    if (result.status === 'rejected') logger.warn(`dsh-nuncia: task teardown failed: ${String(result.reason)}`)
  }
}

// -- authority runtime -------------------------------------------------------------

/**
 * @typedef {object} AuthorityRuntime
 * @property {boolean} enabled
 * @property {string} [nodeName]
 * @property {number} [maxWindowMs]
 * @property {string} [error]      why the layer is off, for /status
 * @property {string} [bearerToken] token derived from the pairing secret (same on every paired node)
 * @property {SecurityLog} security  always present, so rejections can be recorded even when off
 * @property {{verify:(metadata:unknown)=>any}} [gate]
 * @property {GrantStore} [grants]
 */

/**
 * Build the authority layer, or an explicit "off with a reason" description.
 *
 * A missing pairing secret is a configuration mistake, not a crash: the node
 * keeps serving as a peer-only A2A endpoint and reports the misconfiguration
 * in `/status` (rule 5 — fail down, notify loud).
 *
 * @param {A2aServerConfig} config
 * @param {string} cwd
 * @param {any} logger
 * @returns {AuthorityRuntime}
 */
/**
 * The pairing secret, from the environment or the plugin config.
 *
 * Env wins: it keeps the secret out of a file that may be committed or shared,
 * so an operator who CAN export it always does. The inline form exists for
 * harnesses whose environment is fixed at launch (a GUI app), where the
 * alternative is "restart your whole session to pair a node".
 * @param {{pairingSecretEnv?: string, pairingSecret?: string}} settings
 * @returns {{secret: string|undefined, source: 'env'|'config'|'missing', envName: string}}
 */
function resolvePairingSecret(settings = {}) {
  const envName = settings.pairingSecretEnv ?? 'NUNCIA_PAIRING_SECRET'
  const fromEnv = process.env[envName]
  if (typeof fromEnv === 'string' && fromEnv !== '') return { secret: fromEnv, source: 'env', envName }
  if (typeof settings.pairingSecret === 'string' && settings.pairingSecret !== '') {
    return { secret: settings.pairingSecret, source: 'config', envName }
  }
  return { secret: undefined, source: 'missing', envName }
}

function createAuthorityRuntime(config, cwd, logger, adoptedName) {
  const security = new SecurityLog()
  const settings = config.authority
  if (settings?.enabled !== true) return { enabled: false, security }

  const nodeName = sanitizeNodeName(settings.nodeName ?? adoptedName ?? hostname())
  const maxWindowMs = settings.maxWindowMs ?? DEFAULT_MAX_WINDOW_MS
  const stateDir = config.persistenceRoot ?? cwd
  const keyFile = settings.nodeKeyFile === undefined ? join(stateDir, DEFAULT_KEY_FILE) : resolve(settings.nodeKeyFile)

  // 1. This node's identity. A key file that exists but is unreadable is fatal
  // (loadOrCreateNodeKey refuses to overwrite): replacing it silently would
  // rotate the identity and invalidate every peer's pinned key.
  let nodeKey
  try {
    nodeKey = loadOrCreateNodeKey({
      file: keyFile,
      inline: settings.nodeKey,
      onWarn: (message) => logger.warn(`dsh-nuncia: ${message}`),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    security.record({ kind: 'authority-disabled', reason: 'node-key-invalid', detail: { file: keyFile } })
    return { enabled: false, error: message, security }
  }

  let signer
  try {
    signer = createSigner({ privateKey: nodeKey.privateKey, publicKey: nodeKey.publicKey, kid: nodeKey.kid })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    security.record({ kind: 'authority-disabled', reason: 'node-key-invalid', detail: { file: keyFile } })
    return { enabled: false, error: `cannot use node key: ${message}`, security }
  }

  // 2. Legacy material. The pairing secret still derives the bearer token and,
  // while `allowV1` is on, lets pre-v2 peers interoperate — but it is no longer
  // an authority root. A node with a key pair needs no secret to verify intent.
  const resolved = resolvePairingSecret(settings)
  let legacyKey
  if (resolved.secret !== undefined) {
    try {
      legacyKey = deriveAuthorityKey(resolved.secret)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      logger.warn(`dsh-nuncia: ignoring unusable pairing secret (${message})`)
    }
  }
  if (resolved.secret === undefined) {
    logger.warn(
      `dsh-nuncia: ${resolved.envName} is not set — no bearer token can be derived, so the A2A endpoint`
      + ' needs auth.token/auth.tokenEnv; v1 envelopes are disabled (v2 needs no shared secret)',
    )
  }

  // 3. Peer registry. Configuration errors here are fatal for the authority
  // layer only: the node keeps serving peer-only traffic rather than crashing.
  let gate
  try {
    gate = createAuthorityGate({
      nodeName,
      peers: settings.peers ?? [],
      legacyKey,
      allowV1: settings.allowV1 !== false && legacyKey !== undefined,
      maxWindowMs,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    security.record({ kind: 'authority-disabled', reason: 'peer-config-invalid', detail: { nodeName } })
    return { enabled: false, error: message, security }
  }

  const grants = new GrantStore({
    signer,
    origin: nodeName,
    maxWindowMs,
    ...settings.grantTtlMs === undefined ? {} : { defaultTtlMs: settings.grantTtlMs },
    ...settings.persistGrants === true
      ? { persistPath: join(config.persistenceRoot ?? cwd, 'nuncia-grants.json') }
      : {},
    onWarn: (message) => logger.warn(`dsh-nuncia: ${message}`),
  })

  // Per-node bearer: same secret, but the derivation includes the node name, so
  // two nodes no longer share one literal token (rotation stays per name).
  const bearerToken = resolved.secret === undefined ? undefined : deriveBearerToken(resolved.secret, nodeName)

  logger.info?.(
    `dsh-nuncia: node identity "${nodeName}" kid ${nodeKey.kid} (key ${nodeKey.source})`
    + ` · v2 envelopes · ${gate.describe().peers.filter((peer) => peer.canVerifyV2).length} peer key(s)`
    + `${gate.describe().allowV1 ? ' · v1 accepted' : ''}`,
  )
  if (nodeKey.source === 'generated' && nodeKey.file !== undefined) {
    logger.info?.(`dsh-nuncia: publish this node's public key to peers — ${nodeKey.fingerprint}`)
  }

  return {
    enabled: true,
    nodeName,
    maxWindowMs,
    envelopeVersion: 2,
    nodeKey,
    keyFile,
    signer,
    legacyKey,
    bearerToken,
    grants,
    gate,
    security,
  }
}

/**
 * Node names appear in a signed canonical form, so they are restricted to a
 * token charset. A hostname is a convenience default, not a guarantee: sanitize
 * it once here rather than letting mint/verify disagree about the name.
 * @param {string} name
 * @returns {string}
 */

/**
 * Resolve the endpoint's authentication (§20.12 P3.0).
 *
 * The rule the operator set: the endpoint SERVES, but only to requests that
 * carry a valid bearer. A client without one gets an invalid-auth notice and
 * never reaches a session or an agent. A raw install with no configured token
 * used to be wide open; now it gets a *generated* bearer, persisted beside the
 * node's other state and printed once at boot, so the endpoint is closed from
 * the first second without a config step.
 *
 * Precedence for the primary token: `auth.token` → `auth.tokenEnv` → the
 * token derived from the pairing secret (a paired node needs no second
 * secret) → a generated token persisted in the state dir.
 *
 * `auth.adminToken` / `auth.adminTokenEnv` are an ADDITIONAL accepted bearer
 * (never the primary): that is the Sylvia daemon's proxy key — explicit
 * keying for the panel path.
 *
 * @param {any} config
 * @param {{enabled: boolean, bearerToken?: string}} [authority]
 * @param {string} stateDir
 * @param {any} logger
 */
function resolveAuth(config, authority, stateDir, logger) {
  const settings = config.auth
  /** @type {string|undefined} */
  let token
  let source = 'none'
  if (settings?.token !== undefined && settings.token !== '') {
    token = settings.token
    source = 'config'
  } else if (settings?.tokenEnv !== undefined) {
    const fromEnv = process.env[settings.tokenEnv]
    if (typeof fromEnv === 'string' && fromEnv !== '') {
      token = fromEnv
      source = `env:${settings.tokenEnv}`
    } else if (authority?.enabled === true && typeof authority.bearerToken === 'string') {
      token = authority.bearerToken
      source = 'derived'
    } else {
      throw new Error(
        `dsh-nuncia: auth is configured but ${settings.tokenEnv} is empty and the authority layer is off`
        + ' — export it, set auth.token, or enable authority so the bearer is derived from the pairing secret',
      )
    }
  } else if (authority?.enabled === true && typeof authority.bearerToken === 'string') {
    token = authority.bearerToken
    source = 'derived'
  } else {
    // No token anywhere: generate one, persist it, and report it. The
    // endpoint is closed either way — an open A2A port is not a default.
    const generated = loadOrCreateAdminToken({ file: join(stateDir, 'bearer.token') })
    token = generated.token
    source = 'generated'
    logger?.info?.(`dsh-nuncia: generated a bearer token for this node (${generated.file}) — share it with the peers that may talk to this node`)
  }

  /** @type {string|undefined} */
  let adminToken
  if (settings?.adminToken !== undefined && settings.adminToken !== '') adminToken = settings.adminToken
  else if (settings?.adminTokenEnv !== undefined) {
    const fromEnv = process.env[settings.adminTokenEnv]
    if (typeof fromEnv === 'string' && fromEnv !== '') adminToken = fromEnv
  }

  return { token, source, adminToken }
}

/**
 * Load (or create) a persisted bearer token. The file is 0600 and never
 * overwritten: rotating it silently would lock out every peer.
 * @param {{file: string}} options
 * @returns {{token: string, file: string, created: boolean}}
 */
function loadOrCreateAdminToken(options) {
  const file = options.file
  try {
    const existing = readFileSync(file, 'utf8').trim()
    if (existing !== '') return { token: existing, file, created: false }
  } catch {
    // Not there yet — create it below.
  }
  const token = randomBytes(32).toString('base64url')
  try {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, `${token}\n`, { encoding: 'utf8', mode: 0o600 })
  } catch (error) {
    // If the state dir is unwritable the token still works for this boot —
    // but say so, because a token nobody can read is a token nobody can
    // share, and the next boot would mint a different one.
    console.error(`dsh-nuncia: could not persist the generated bearer to ${file}: ${error instanceof Error ? error.message : String(error)}`)
  }
  return { token, file, created: true }
}

/**
 * Check a request's bearer.
 *
 * Two tokens may be accepted: the primary one (config/env/derived/generated)
 * and the optional admin token (the Sylvia daemon's proxy key). A request
 * without a valid one gets an invalid-auth notice and never reaches a
 * session or an agent — the endpoint serves, but only to authenticated peers.
 *
 * @param {any} req
 * @param {{token: string, adminToken?: string}} auth
 * @returns {boolean}
 */
function isAuthorized(req, auth) {
  const header = req?.headers?.authorization
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false
  const presented = header.slice('Bearer '.length)
  if (presented === '') return false
  if (auth.token !== undefined && timingSafeEqualStrings(presented, auth.token)) return true
  if (auth.adminToken !== undefined && timingSafeEqualStrings(presented, auth.adminToken)) return true
  return false
}

/**
 * Constant-time string comparison, without the length leak a naive `===` has.
 * @param {string} a
 * @param {string} b
 */
function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  if (left.length !== right.length) {
    // Still compare something of equal length so the branch is not a timing
    // oracle for the length.
    timingSafeEqual(Buffer.alloc(left.length), Buffer.alloc(left.length))
    return false
  }
  return timingSafeEqual(left, right)
}

/** True when the request arrived over loopback (the operator's own machine). */
export function isLoopbackRequest(req) {
  const address = req?.socket?.remoteAddress
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

/** Compact authority summary for the admin status endpoint. */
function describeAuthority(authority) {
  if (authority?.enabled !== true) {
    return {
      enabled: false,
      ...authority?.error === undefined ? {} : { error: authority.error },
      securityEvents: authority?.security?.list() ?? [],
    }
  }
  const peers = authority.gate.describe()
  return {
    enabled: true,
    envelopeVersion: authority.envelopeVersion,
    nodeName: authority.nodeName,
    maxWindowMs: authority.maxWindowMs,
    // Public material only. The private key never appears in a response, and
    // `publicKey` is exactly what a peer should paste into its own config.
    identity: {
      kid: authority.nodeKey.kid,
      fingerprint: authority.nodeKey.fingerprint,
      publicKey: exportPublicKey(authority.nodeKey.publicKey),
      keySource: authority.nodeKey.source,
      keyFile: authority.keyFile ?? null,
    },
    pairing: {
      allowV1: peers.allowV1,
      legacyKeyConfigured: peers.legacyKeyConfigured,
      bearerConfigured: typeof authority.bearerToken === 'string',
    },
    peers: peers.peers,
    grants: authority.grants.list().grants,
    securityEvents: authority.security.list(),
  }
}

/**
 * Queue an authority notice for a task's agent.
 *
 * `inject` (not `followup`) on purpose: the notice must never open a turn or
 * trigger a model call by itself. It becomes part of the conversation the next
 * time the agent actually runs — which is exactly when its behaviour matters.
 * Delivery failure is logged, never fatal: a missing notice must not break a
 * task that is otherwise fine.
 */
function deliverNotice(record, text, logger) {
	try {
		const message = createUserMessage({
			content: [{ type: 'text', text }],
			source: {
				// NOT `kind: 'plugin'` — the v4 session format refuses the retired
				// plugin wrapper ("format v4 message requires a producer-owned
				// source kind", dsh-session-format-v3-to-v4/lib/index.js) and a
				// rejected write fails the whole turn. The canonical producer kind
				// for a third-party plugin is `plugin:<package>` (its own
				// `producerKind()` fallback), which is what a v3 `plugin` source
				// rewrites to.
				kind: 'plugin:dsh-nuncia',
				form: 'notice',
				summary: boundContextSummary(text.split('\n')[0]),
			},
		})
		record.agent.inject(message)
	} catch (error) {
		logger.warn(`dsh-nuncia: could not deliver authority notice: ${String(error)}`)
	}
}

/**
 * Record a security event in the bounded log and republish it on the host bus.
 *
 * The log is local evidence for `/status`; the emitted event is what lets a
 * host plugin (Sylvia's panel, a toast, an OS dialog) react without polling.
 */
function recordSecurityEvent(ctx, authority, logger, event, hooks = {}) {
	const stored = authority?.security?.record(event) ?? event
	try {
		ctx.emit?.('nuncia/security-event', stored)
	} catch (error) {
		logger.warn(`dsh-nuncia: security-event listener threw: ${String(error)}`)
	}
	// §20.12 P2.4: a rejected claim is a supervision matter, not just a log line.
	// The chatelaine is the human's representative, so it must HEAR about it —
	// and the operator hook gets the same event so a phone notification can fire
	// without the plugin polling anything.
	if (stored?.kind === 'authority-rejected') {
		const origin = stored.detail?.origin ?? 'an unnamed peer'
		const task = stored.detail?.taskId
		void hooks.chatelaine?.report?.(
			`Security: an authority claim from ${origin} was rejected (${stored.reason ?? 'unknown reason'})`
			+ `${task === undefined ? '' : ` on task ${task}`}. The message ran as peer instead. If this was not expected, treat it as an attempt to act in your name.`,
		)?.catch?.(() => {})
		if (hooks.fireHook !== undefined) hooks.fireHook('authority-rejected', stored)
	}
	return stored
}

/**
 * Register the two agent-facing tools, but only when the host actually has a
 * tool runtime. The plugin stays loadable on a bare A2A-only node (and in the
 * smoke tests) because this runs in an injected fiber rather than adding
 * `tools` to the plugin's own `inject` list — a hard dependency there would
 * stop `apply` from ever running where no tools service exists.
 *
 * Definitions are plain objects (the shape `ctx.tools.register` validates)
 * rather than `defineTool(...)` imports: that factory lives in
 * `@deepseek-ai/dsh-tools`, which resolves from an ancestor profile tree on
 * some hosts and can therefore be a *different version* than the live tools
 * service. A plain object cannot drift.
 */
function registerAuthorityTools(ctx, { grants, outbound, broker, approvalMode, logger, unknownPeers, recordOf, chatelaine }) {
	const register = (tools) => {
		if (tools?.register === undefined) {
			logger.warn('dsh-nuncia: tools service found but register() is missing — authority tools not registered')
			return
		}
		// The authority plane is the chatelaine's to operate (§20.16, matrix row
		// 1): minting a grant on the human's behalf and sending under this
		// node's name are decisions the human's representative makes. An
		// operator asking for either must route through the chatelaine —
		// message_chatelaine — which can then call these tools itself.
		tools.register(requestUserIntentTool(ctx, grants, broker, approvalMode, chatelaine))
		if (outbound !== undefined) tools.register(a2aSendTool(chatelaine, outbound, unknownPeers, recordOf))
		logger.info?.('dsh-nuncia: registered ask_user_intent' + (outbound === undefined ? '' : ' + a2a_send'))
	}
	if (typeof ctx.inject === 'function') {
		ctx.inject(['tools'], (toolCtx) => {
			register(toolCtx.tools ?? toolCtx.get?.('tools'))
		})
	} else if (ctx.tools !== undefined) {
		register(ctx.tools)
	}
}

/**
 * Register the chatelaine tools (§20.16): `message_chatelaine` is the entry
 * point for every local session; `message_local_session` and `send_nuncia` are
 * chatelaine-only. Same plain-object definitions and injected-fiber pattern as
 * the authority tools so a node without a tools service still loads.
 */
function registerChatelaineTools(ctx, { chatelaine, operators, announcement, outbound, records, logger }) {
  const register = (tools) => {
    if (tools?.register === undefined) {
      logger.warn('dsh-nuncia: tools service found but register() is missing — chatelaine tools not registered')
      return
    }
    tools.register(messageChatelaineTool(chatelaine))
    tools.register(messageLocalSessionTool(chatelaine, operators))
    tools.register(setAnnouncementTool(chatelaine, announcement))
    tools.register(operatorAuthorityTool(chatelaine, records))
    if (outbound !== undefined) tools.register(sendNunciaTool(chatelaine, outbound, records))
    logger.info?.('dsh-nuncia: registered message_chatelaine + message_local_session + set_announcement + operator_authority'
      + (outbound === undefined ? '' : ' + send_nuncia'))
  }
  if (typeof ctx.inject === 'function') {
    ctx.inject(['tools'], (toolCtx) => {
      register(toolCtx.tools ?? toolCtx.get?.('tools'))
    })
  } else if (ctx.tools !== undefined) {
    register(ctx.tools)
  }
}

/**
 * §20.16 ownership check, shared by every tool whose use is a chatelaine act.
 *
 * Identity, not configuration — the same rule `set_announcement` already
 * used. A live chatelaine session is REQUIRED: a node that has not adopted
 * its chatelaine gets no chatelaine-tools either, instead of an unowned
 * node where the first caller wins.
 * @param {any} chatelaine
 * @param {string|undefined} me the calling session's id
 * @param {string} toolLabel for the error text
 */
async function assertChatelaine(chatelaine, me, toolLabel) {
  const chatelaineId = await chatelaine?.peekId?.()
  if (process.env.NUNCIA_DEBUG_TOOLS === '1') {
    console.error(`dsh-nuncia: assertChatelaine(${toolLabel}) me=${JSON.stringify(me)} chatelaineId=${JSON.stringify(chatelaineId)}`)
  }
  if (chatelaineId === undefined || me === undefined || me !== chatelaineId) {
    throw new Error(
      `${toolLabel} belongs to the chatelaine only — ask for it with message_chatelaine and wait for its decision`,
    )
  }
}

/**
 * `set_announcement` — the node's public signboard, one line, written by the
 * chatelaine only. The operator is told to route it through the chatelaine
 * precisely because what is worth publishing is a judgement about the human's
 * attention, not the operator's alone.
 */
function setAnnouncementTool(chatelaine, announcement) {
  return {
    name: 'set_announcement',
    description:
      'Set this node\'s public announcement — one short line saying what the node is doing right now. '
      + 'Only the chatelaine may call this. Keep it factual and brief; it is read by whoever looks the node up.',
    parameters: {
      type: 'object',
      properties: {
        announcement: { type: 'string', description: `The line to publish (max ${MAX_ANNOUNCEMENT_LENGTH} characters).` },
      },
      required: ['announcement'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: { ok: { type: 'boolean' }, announcement: { type: 'string' }, reason: { type: 'string' } },
        required: ['ok'],
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.ok ? `the node now says: ${value.announcement}` : `the announcement was rejected${value.reason === undefined ? '' : `: ${value.reason}`}`,
      }],
    },
    async execute(args, exec) {
      const me = exec?.agent?.id
      const chatelaineId = await chatelaine.peekId()
      if (chatelaineId === undefined || me !== chatelaineId) {
        throw new Error('only the chatelaine may set the announcement — report the line to it instead')
      }
      const written = await announcement.set(args.announcement)
      if (!written.ok) throw new Error(written.reason ?? 'announcement rejected')
      return { ok: true, announcement: written.value }
    },
  }
}

/**
 * `operator_authority` — the chatelaine's bookkeeping: which operator session
 * currently holds a verified user-authority window (level, peer, scope, time
 * left), so it can direct work without guessing (m05102). The chatelaine may
 * query any operator (or omit the handle for the whole board); every other
 * session may only look at its own window.
 */
function operatorAuthorityTool(chatelaine, records) {
  /** @param {any} record */
  const windowOf = (record) => {
    const grant = record.authority
    if (grant === undefined) return undefined
    return {
      level: grant.level === 'override' ? 'override' : 'intent',
      origin: grant.origin ?? 'unknown',
      ...(grant.scope === undefined ? {} : { scope: grant.scope }),
      expiresAt: grant.exp,
      remainingMs: Math.max(0, grant.exp - Date.now()),
    }
  }
  return {
    name: 'operator_authority',
    description:
      "Check what user authority (a verified intent/override window) operator sessions currently hold. "
      + 'Only the chatelaine may call it with a specific handle (or without one to list every live window); '
      + 'any other session gets its own window only. Reflects live state — windows lapse continuously.',
    parameters: {
      type: 'object',
      properties: {
        handle: { type: 'string', description: "The operator handle to inspect (e.g. op_0123456789abcdef). Omit to list all windows (chatelaine only)." },
      },
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          now: { type: 'number' },
          windows: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                handle: { type: 'string' },
                taskId: { type: 'string' },
                level: { type: 'string' },
                origin: { type: 'string' },
                scope: { type: 'string' },
                expiresAt: { type: 'number' },
                remainingMs: { type: 'number' },
              },
              required: ['handle', 'taskId', 'level', 'origin'],
            },
          },
        },
        required: ['now', 'windows'],
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.windows.length === 0
          ? 'no operator holds a verified authority window right now'
          : `${value.windows.length} live window(s): ${value.windows
              .map((row) => `${row.handle} (${row.level} via ${row.origin}${row.scope === undefined ? '' : `, scope ${row.scope}`}, ${Math.round(row.remainingMs / 60_000)} min left)`)
              .join('; ')}`,
      }],
    },
    async execute(args, exec) {
      const me = exec?.agent?.id
      const chatelaineId = await chatelaine.peekId()
      const isChatelaine = chatelaineId !== undefined && me === chatelaineId
      if (!isChatelaine && args.handle !== undefined) {
        throw new Error('only the chatelaine may look up other operators — omit the handle to see your own window')
      }
      const now = Date.now()
      const windows = []
      for (const record of records.values()) {
        // The chatelaine session itself is not an A2A task, so it never
        // appears here; records with no handle are unaccepted peer tasks and
        // still readable by the chatelaine (they can hold authority too).
        if (args?.handle !== undefined && record.handle !== args.handle) continue
        if (!isChatelaine && me !== undefined && record.agent?.id !== me) continue
        const grant = windowOf(record)
        if (grant === undefined) continue
        windows.push({
          handle: record.handle ?? 'unhandled',
          taskId: record.taskId,
          // The wire task id for tool-returned handles (continuity re-keys
          // don't preserve a matching taskId).
          wireTaskId: record.wireTaskId,
          ...grant,
        })
      }
      // Soonest-to-lapse first: what the chatelaine must count down comes
      // before what will sit quietly for hours.
      windows.sort((a, b) => a.expiresAt - b.expiresAt)
      return { now, windows }
    },
  }
}

/**
 * `message_chatelaine` — the single entry point any local session uses to
 * reach the representative (§20.16). Replaces `report_to_chatelaine`: it is not
 * an operator-only report anymore. Operators ask it for A2A sends and intent
 * grants (which they can no longer perform themselves — §20.16 row 1); local
 * sessions ask it for whatever sits in their lane-takeover column. Reports and
 * approvals flow through it too: a report on the way, a question when a
 * decision is needed, an approval of a lane-takeover when it comes back.
 */
function messageChatelaineTool(chatelaine) {
  return {
    name: 'message_chatelaine',
    description:
      "Send a message to this node's chatelaine — the session that represents the human and decides for this node. "
      + 'Use it to ask for something outside your own lane: an A2A send, an authority grant, an approval, a resource. '
      + 'Delivery is durable; set question when you need a decision (that wakes it immediately). Never put key material in a message.',
    parameters: {
      type: 'object',
      properties: {
        message: { type: 'string', description: "What you need or what happened — one or two sentences." },
        question: { type: 'string', description: 'A decision you need from the chatelaine, if any. Setting this wakes it immediately.' },
        urgency: { type: 'string', description: 'info (default), soon, or urgent.' },
      },
      required: ['message'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          delivered: { type: 'boolean' },
          sessionId: { type: 'string' },
          reason: { type: 'string' },
        },
        required: ['delivered'],
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.delivered
          ? 'the chatelaine will see this on its next turn'
          : `the chatelaine could not be reached${value.reason === undefined ? '' : `: ${value.reason}`}`,
      }],
    },
    async execute(args, exec) {
      const me = exec?.agent?.id
      if (me !== undefined && me === await chatelaine.peekId()) {
        throw new Error('you are the chatelaine; message_chatelaine is for other sessions')
      }
      const text = args.question === undefined
        ? `[message${args.urgency === undefined ? '' : ` / ${args.urgency}`}] ${args.message}`
        : `[message / question${args.urgency === undefined ? '' : ` / ${args.urgency}`}] ${args.message}\nQuestion: ${args.question}`
      const result = await chatelaine.report(text, { wake: args.question !== undefined })
      return {
        delivered: result.delivered,
        ...(result.sessionId === undefined ? {} : { sessionId: result.sessionId }),
        ...(result.reason === undefined ? {} : { reason: result.reason }),
      }
    },
  }
}

/**
 * `message_local_session` — the chatelaine's direct lane to any local session
 * on this node, by handle or session id (§20.16). Replaces
 * `reply_to_operator`, which covered only handle-booked operators: direct
 * contact with sessions not meeting the message-peer criteria (freshly spawned
 * subagents, arbitrary local sessions) is now expressible without naming a
 * session-record system. The caller IS the approver — the human's
 * representative — so no minted envelope is needed for local traffic.
 */
function messageLocalSessionTool(chatelaine, operators) {
  return {
    name: 'message_local_session',
    description:
      "Send a message into a local session on this node, by the operator handle it reported (op_…) or its session id. "
      + 'Use it to answer a question a session forwarded, or to steer work that is still running. '
      + "Only the chatelaine may call this.",
    parameters: {
      type: 'object',
      properties: {
        session: { type: 'string', description: 'Operator handle (op_…) or session id of the target session.' },
        message: { type: 'string', description: 'What to tell the session.' },
        wake: { type: 'boolean', description: 'Start a turn in the target session (default true).' },
      },
      required: ['session', 'message'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: { delivered: { type: 'boolean' }, sessionId: { type: 'string' }, taskId: { type: 'string' }, reason: { type: 'string' } },
        required: ['delivered'],
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.delivered
          ? `delivered${value.taskId !== undefined ? ` to task ${value.taskId}` : ''}`
          : `not delivered${value.reason === undefined ? '' : `: ${value.reason}`}`,
      }],
    },
    async execute(args, exec) {
      await assertChatelaine(chatelaine, exec?.agent?.id, 'message_local_session')
      // Handle first: an op_… id names an operator record, not a session. A
      // handle with no book record is one the prune removed (expired) — refuse
      // BY NAME rather than letting the string fall through as a session id,
      // where it would silently deliver to nothing.
      const operator = operators?.get(args.session)
      if (operator === undefined && typeof args.session === 'string' && /^op_[0-9a-f]{16}$/.test(args.session)) {
        throw new Error(`unknown operator handle ${args.session} — pruned or expired (operator_authority shows the live windows)`)
      }
      const sessionId = operator?.sessionId ?? args.session
      const chatelaineId = await chatelaine.peekId()
      if (chatelaineId !== undefined && sessionId === chatelaineId) {
        throw new Error('that is this chatelaine\'s own session — message it from outside or skip')
      }
      const result = await chatelaine.send(sessionId, `[chatelaine] ${args.message}`, { wake: args.wake !== false })
      return {
        delivered: result.delivered,
        ...(operator !== undefined ? { taskId: operator.taskId } : {}),
        ...(result.reason === undefined ? {} : { reason: result.reason }),
      }
    },
  }
}

/**
 * `send_nuncia` — reply to a nuncia peer on the conversation it opened with
 * this node (§20.16). The chatelaine initiates with `a2a_send` (fresh exchange
 * → the peer mints its operator); replies from a nuncia client carry the
 * exchange back, and receiver-side routing keeps them on one operator there.
 * This tool sends on the exchange the PEER'S thread is known by on this side —
 * the peer's latest open exchange to this node — so the reply lands on that
 * same remote operator instead of opening a second one. "Sending the first
 * communication and replying to a nuncia client is the same task on the
 * operator" (m06656).
 */
function sendNunciaTool(chatelaine, outbound, records) {
  return {
    name: 'send_nuncia',
    description:
      'Reply to a nuncia peer on the conversation it opened with THIS node. '
      + 'The reply is routed through the exchange that peer has been using, so the same operator session continues on the peer. '
      + "If there is no open conversation with that peer yet, use a2a_send to open one (that is the FIRST message, not a reply). "
      + 'Only the chatelaine may call this.',
    parameters: {
      type: 'object',
      properties: {
        peer: { type: 'string', description: 'Peer name as configured in authority.peerUrls.' },
        text: { type: 'string', description: 'The reply to send.' },
      },
      required: ['peer', 'text'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          peer: { type: 'string' },
          taskId: { type: 'string' },
          contextId: { type: 'string' },
          state: { type: 'string' },
          text: { type: 'string' },
        },
        required: ['peer', 'state'],
      },
      render: (_args, value) => [{
        type: 'text',
        text: `${value.peer} → ${value.state}${value.contextId !== undefined ? ` [exchange ${value.contextId.slice(0, 8)}]` : ''}${value.text ? `: ${value.text}` : ''}`,
      }],
    },
    async execute(args, exec) {
      await assertChatelaine(chatelaine, exec?.agent?.id, 'send_nuncia')
      // The exchange the PEER is using. Aliases (continuity re-keys) repeat
      // contextId, so dedupe per exchange id. An open record is the live
      // thread; a terminal one is a thread whose operator still keeps its
      // history (continuation on the wire is legal) — prefer open, fall back
      // to terminal rather than refusing.
      const seen = new Set()
      const unclaimed = new Set()
      let bestOpen
      let bestTerminal
      for (const record of records.values()) {
        const contextId = record?.contextId
        if (typeof contextId !== 'string' || contextId === '') continue
        if ((record.authority?.origin ?? '') === args.peer) {
          if (seen.has(contextId)) continue
          seen.add(contextId)
          const at = typeof record.createdAt === 'number' ? record.createdAt : 0
          if (record.terminalPublished !== true) {
            if (bestOpen === undefined || at > bestOpen.at) bestOpen = { contextId, at }
          } else if (bestTerminal === undefined || at > bestTerminal.at) {
            bestTerminal = { contextId, at }
          }
        } else if ((record.authority?.origin ?? '') === '' && !unclaimed.has(contextId)) {
          unclaimed.add(contextId)
        }
      }
      // A bearer-only client opened an exchange with no envelope: no verified
      // origin to match. Reply on that exchange ONLY when it is unambiguous —
      // routing on a guess would deliver this node's reply into the wrong
      // thread. An exchange id carries no privilege, but confusion is cost.
      const exchangeId = bestOpen?.contextId ?? bestTerminal?.contextId
        ?? (unclaimed.size === 1 ? [...unclaimed][0] : undefined)
      if (exchangeId === undefined) {
        throw new Error(`no open conversation with "${args.peer}" to reply on — a2a_send opens one (that is the FIRST message, not a reply)`)
      }
      const result = await outbound.send({ peer: args.peer, text: args.text, contextId: exchangeId })
      return {
        peer: result.peer,
        ...(result.taskId === undefined || result.taskId === '' ? {} : { taskId: result.taskId }),
        contextId: typeof result?.contextId === 'string' && result.contextId !== '' ? result.contextId : exchangeId,
        state: result.state,
        ...(result.text === undefined ? {} : { text: result.text }),
      }
    },
  }
}

// message_peer_chatelaine and reply_to_operator are removed (§20.16, first
// withdrawal): chatelaine-addressing over the wire is refused by the executor
// (it writes into the human's representative's context), and handle-only reply
// traffic is now covered by message_local_session, which reaches any local
// session by handle or session id.

/**
 * Decide an agent-requested grant.
 *
 * `broker` (the default) means the plugin asks through its own queue — the only
 * path that works when the host's approval policy is `never`, as it is under
 * `danger-full-access`. `host` uses DSH's approval dialog (the right choice
 * where the policy is `ask`); `auto` tries the host and falls back to the
 * broker only when the host reports `unavailable`, i.e. nobody answered.
 *
 * Anything other than `allowed-once` is a refusal — never an implicit yes.
 */
/**
 * Ask through the host's `userQuestions` service — the one prompt surface that
 * survives a `danger-full-access` deployment (`approval: never` short-circuits
 * to `rejected` policy-side, but the `user-questions/request` waterfall is an
 * independent event: `dsh-user-approval@0.2.1-alpha.5/lib/index.js:175` vs
 * `dsh-user-questions@0.2.1-alpha.5/lib/index.js:668-691`).
 *
 * Constraints proven from source: Identity gates require the live ROOT agent
 * (`CALLER_NOT_LIVE`/`DELEGATED_CALLER`), and an agentless ask can never reach
 * a client (`NO_PROVIDER`), so this only ever runs with `exec.agent` bound.
 * `ask()` with an agent but no connected client pends forever — `askTimed`
 * trades that for a real deadline and answers `{ pending: true, callId }`,
 * which we treat as no answer and let the next surface decide.
 *
 * Returns a decision string, or `undefined` when no question could be asked
 * (service absent, caller not live, timed out) so the caller can fall through.
 */
async function askViaUserQuestions({ ctx, exec, args = {}, reason }) {
	const questions = ctx.get?.('userQuestions')
	if (questions === undefined || typeof questions.askTimed !== 'function') return undefined
	const callId = `nuncia-intent-${randomUUID()}`
	try {
		const answer = await questions.askTimed({
			questions: [{
				id: 'nuncia-intent',
				header: 'Authority request',
				question: `Grant outbound authority to ${typeof args.target === 'string' && args.target.length > 0 ? args.target : 'the requested peer'}?`,
				detail: reason,
				options: [
					{ label: 'Allow once' },
					{ label: 'Deny' },
				],
			}],
			agent: exec.agent,
		}, callId, USER_QUESTIONS_TIMEOUT_MS)
		if (answer?.pending) return undefined
		const picked = answer?.answers?.[0]
		const allowed = Array.isArray(picked?.selected)
			? picked.selected.includes('Allow once')
			: false
		return allowed ? 'allowed-once' : 'rejected'
	} catch {
		// ASK_ABORTED / ASK_TIMED_OUT / NO_PROVIDER — fall through to the next
		// surface; the catch must never mask a hard failure of the caller.
	}
	return undefined
}

async function decideApproval({ ctx, broker, approvalMode, exec, args, reason }) {
	if (approvalMode === 'host' || approvalMode === 'auto') {
		const host = ctx.get?.('approval')
		const agent = exec?.agent
		if (host !== undefined && agent !== undefined) {
			try {
				const outcome = await host.request({
					agent,
					toolName: 'ask_user_intent',
					...(exec.callId === undefined ? {} : { callId: exec.callId }),
					reason,
					...(exec.signal === undefined ? {} : { signal: exec.signal }),
				})
				if (outcome === 'allowed-once' || outcome === 'rejected' || outcome === 'cancelled') return outcome
			} catch {
				// A host that cannot ask must not block the broker path.
			}
		}
		if (approvalMode === 'host') {
			const asked = await askViaUserQuestions({ ctx, exec, args, reason })
			if (asked !== undefined) return asked
			return 'unavailable'
		}
	}
	// Even in broker mode, a live Web UI is a better human surface than an
	// idle queue — try the host question card first and keep the broker as the
	// answer of last resort (headless / disconnected / not a live root).
	if (broker !== undefined && exec?.agent !== undefined) {
		const asked = await askViaUserQuestions({ ctx, exec, args, reason })
		if (asked !== undefined) return asked
	}
	if (broker === undefined) return 'unavailable'
	return broker.request({
		reason,
		target: args.target,
		level: args.level === 'override' ? 'override' : 'intent',
		...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
		...(typeof args.scope === 'string' ? { scope: args.scope } : {}),
		toolName: 'ask_user_intent',
	})
}

/**
 * Announce a pending approval.
 *
 * The hook is deliberately a command rather than a built-in UI: on Android the
 * native surface is Termux:API (`termux-notification`, `termux-dialog`), on a
 * desktop it may be a notification daemon, and on the phone the Sylvia panel is
 * the decision surface. The command gets the id and reason in its environment
 * and decides by POSTing to `{adminPath}/requests/decide`.
 */
function announceApproval(config, request, logger) {
	logger.info?.(`dsh-nuncia: approval requested ${request.id} — ${request.reason}`)
	fireApproveCommand(config, logger, {
		NUNCIA_EVENT: 'approval-requested',
		NUNCIA_APPROVAL_ID: request.id,
		NUNCIA_APPROVAL_REASON: request.reason,
		// The rest of the request, so a hook can show a full card (or POST it
		// to the daemon) without querying the plugin back.
		NUNCIA_APPROVAL_TARGET: request.target ?? '',
		NUNCIA_APPROVAL_LEVEL: request.level ?? '',
		NUNCIA_APPROVAL_SCOPE: request.scope ?? '',
		NUNCIA_APPROVAL_TTL_MS: String(request.ttlMs ?? ''),
		NUNCIA_APPROVAL_TOOL: request.toolName ?? '',
		NUNCIA_ADMIN_PATH: config.adminPath ?? '/a2a/admin',
	})
}

/**
 * Run the operator-configured `approveCommand` with a set of extra environment
 * variables. Shared by the approval announcement and the security-event hook so
 * ONE script can do both jobs — it reads `NUNCIA_EVENT` to tell them apart.
 *
 * @param {any} config
 * @param {any} logger
 * @param {Record<string, string>} extra
 */
function fireApproveCommand(config, logger, extra) {
	const command = config.authority?.approveCommand ?? []
	if (command.length === 0) return
	try {
		const child = execFile(command[0], command.slice(1), {
			env: { ...process.env, ...extra },
			stdio: 'ignore',
		})
		child.on?.('error', (error) => logger.warn(`dsh-nuncia: approveCommand failed: ${String(error)}`))
		child.unref?.()
	} catch (error) {
		logger.warn(`dsh-nuncia: approveCommand could not start: ${String(error)}`)
	}
}

/**
 * Deadline for a host question card. `askTimed` answers `{ pending: true }`
 * past it; we surface the broker (or `unavailable`) rather than waiting on a
 * composer nobody may ever open. The broker's own prune timeout stays longer,
 * so an admin endpoint decision can still arrive late in broker mode.
 */
const USER_QUESTIONS_TIMEOUT_MS = 120000

/**
 * `ask_user_intent` (formerly `request_user_intent`) — the agent-requested
 * path to a grant (§20.2.2), gated to the chatelaine since §20.16.
 *
 * The approval IS the authorization: nothing is minted unless the human answers
 * `allowed-once`. The default `broker` mode exists because a
 * `danger-full-access` deployment sets the host approval policy to `never`,
 * where `ctx.approval.request()` returns `rejected` without ever prompting.
 */
function requestUserIntentTool(ctx, grants, broker, approvalMode, chatelaine) {
	return {
		name: 'ask_user_intent',
		description:
			'Ask the user to grant temporary authority to act on their behalf toward a paired A2A peer, then mint it. '
			+ 'Only an explicit user approval grants authority; grant bytes are never returned to you. '
			+ 'Use POST /a2a-admin/mint instead when the user is at the panel.',
		parameters: {
			type: 'object',
			properties: {
				target: { type: 'string', description: 'Peer node name (see authority.peerUrls).' },
				level: { type: 'string', description: 'intent (default) or override. override may contradict house rules.' },
				ttlMs: { type: 'number', description: 'Requested window in milliseconds (default 5 minutes, subject to maxWindowMs).' },
				scope: { type: 'string', description: 'Free-text scope recorded inside the signed envelope.' },
			},
			required: ['target'],
		},
		output: {
			schema: {
				type: 'object',
				additionalProperties: false,
				properties: {
					granted: { type: 'boolean' },
					id: { type: 'string' },
					level: { type: 'string' },
					target: { type: 'string' },
					expiresAt: { type: 'number' },
				},
				required: ['granted'],
			},
			render: (_args, value) => [{
				type: 'text',
				text: value.granted
					? `granted ${value.level} authority to "${value.target}" until ${new Date(value.expiresAt).toISOString()} (grant ${value.id})`
					: 'no grant was minted',
			}],
		},
		async execute(args, exec) {
			// Minting is the chatelaine's act (§20.16 row 1): an operator minting
			// its own grant would be widening its own authority — exactly the
			// escalation the "ownership of authority as the property of the
			// chatelaine" pill blocks. Operators reach minting through
			// message_chatelaine; the chatelaine mints here where it is visible.
			await assertChatelaine(chatelaine, exec?.agent?.id, 'ask_user_intent')
			const level = args.level === 'override' ? 'override' : 'intent'
			const ttlMs = typeof args.ttlMs === 'number' ? args.ttlMs : grants.defaultTtlMs
			const minutes = Math.max(1, Math.round(ttlMs / 60_000))
			const reason = `Grant "${level}" authority to ${args.target} for ~${minutes} min${typeof args.scope === 'string' ? ` (scope: ${args.scope})` : ''}`
			const decision = await decideApproval({ ctx, broker, approvalMode, exec, args, reason })
			if (decision !== 'allowed-once') {
				throw new Error(
					decision === 'timeout'
						? 'no grant was minted: the approval request timed out'
						: `no grant was minted: the user did not approve (${decision})`,
				)
			}
			const grant = grants.mint({
				target: args.target,
				level,
				...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
				...(typeof args.scope === 'string' ? { scope: args.scope } : {}),
			})
			return { granted: true, id: grant.id, level: grant.level, target: grant.target, expiresAt: grant.exp }
		},
	}
}

/** `a2a_send` — contact a paired peer; the plugin attaches a live grant if one exists. Chatelaine-only (§20.16). */
function a2aSendTool(chatelaine, outbound, unknownPeers, recordOf) {
	/**
	 * Open exchange per peer, for callers that are not inside an A2A task (the
	 * chatelaine, or the human's own session).
	 *
	 * The sender must not have to remember a conversation id, and must not be
	 * able to name a remote operator — so the client library carries this
	 * itself. An exchange stays open while the remote side is still working and
	 * while a failed send is being retried; once the remote task reaches a
	 * terminal state the conversation is over and the next send opens a new one.
	 */
	const openExchanges = new Map()
	const TERMINAL_STATE = /^TASK_STATE_(COMPLETED|FAILED|CANCELED|REJECTED)$/
	const EXCHANGE_TTL_MS = 10 * 60_000

	/** @returns {string} the exchange id to send on */
	function exchangeFor(peer, record) {
		// Inside a task the task's OWN exchange is the conversation. Nothing to
		// remember, nothing to name.
		if (typeof record?.contextId === 'string' && record.contextId !== '') return record.contextId
		const open = openExchanges.get(peer)
		if (open !== undefined && !TERMINAL_STATE.test(open.state) && Date.now() - open.at < EXCHANGE_TTL_MS) {
			return open.contextId
		}
		const fresh = randomUUID()
		openExchanges.set(peer, { contextId: fresh, state: 'TASK_STATE_UNKNOWN', at: Date.now() })
		return fresh
	}

	return {
		name: 'a2a_send',
		description:
			'Send a message to a paired A2A peer and return its answer. '
			+ 'If a live authority grant exists for that peer it is attached automatically — you never handle grant bytes. '
			+ 'You address a PEER, never a person, operator or session: the peer decides how to route what you send, '
			+ 'and replies carry no authority. A message sent from inside an A2A task continues that exchange, so the '
			+ 'remote operator keeps its history across retries and follow-ups.',
		parameters: {
			type: 'object',
			properties: {
				peer: { type: 'string', description: 'Peer name as configured in authority.peerUrls.' },
				text: { type: 'string', description: 'The message to send.' },
			},
			required: ['peer', 'text'],
		},
		output: {
			schema: {
				type: 'object',
				additionalProperties: false,
				properties: {
					peer: { type: 'string' },
					taskId: { type: 'string' },
					contextId: { type: 'string' },
					state: { type: 'string' },
					text: { type: 'string' },
					carriedAuthority: { type: 'boolean' },
				},
				required: ['peer', 'state'],
			},
			render: (_args, value) => [{
				type: 'text',
				text: `${value.peer} → ${value.state}${value.carriedAuthority ? ' (with your grant)' : ''}${value.contextId ? ` [exchange ${value.contextId.slice(0, 8)}]` : ''}${value.text ? `: ${value.text}` : ''}`,
			}],
		},
		async execute(args, exec) {
			// Outbound sending is a chatelaine act (§20.16 row 1): the message
			// goes out under THIS node's name and carries whatever live grant
			// exists — both human-side decisions. An operator asks via
			// message_chatelaine instead.
			await assertChatelaine(chatelaine, exec?.agent?.id, 'a2a_send')
			const known = unknownPeers === undefined ? [] : unknownPeers()
			try {
				// The exchange is decided HERE, from this side's own state: inside
				// a task it is the task's exchange; outside one it is the open
				// exchange for that peer (see exchangeFor). The caller supplies a
				// peer and text — nothing about the remote side's structure.
				const record = recordOf?.(exec?.agent)
				const exchange = exchangeFor(args.peer, record)
				if (process.env.NUNCIA_DEBUG_TOOLS === '1') {
					console.error(`dsh-nuncia: a2a_send record=${record === undefined ? 'miss' : 'hit'} exchange=${exchange} execAgentId=${exec?.agent?.id ?? 'none'}`)
				}
				const result = await outbound.send({ peer: args.peer, text: args.text, contextId: exchange })
				// Close the exchange when the remote task is done; a failed send
				// leaves it open so the retry continues the same conversation.
				openExchanges.set(args.peer, {
					contextId: typeof result?.contextId === 'string' && result.contextId !== '' ? result.contextId : exchange,
					state: typeof result?.state === 'string' ? result.state : 'TASK_STATE_UNKNOWN',
					at: Date.now(),
				})
				return result
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error)
				if (known.length > 0 && message.includes('unknown peer')) {
					throw new Error(`${message} Known peers: ${known.join(', ')}.`)
				}
				throw error
			}
		},
	}
}

// -- helpers ----------------------------------------------------------------------

/**
 * The preamble text for a fresh operator task: the node-level brief sits in
 * the session's inbox/authority notices already — this only carries the
 * "keep it small" discipline. Config override: `chatelaine.taskPreamble`
 * (empty string disables).
 * @param {any} record
 * @param {any} config
 */
function operatorTaskPreamble(record, config) {
  const brief = config?.chatelaine?.taskPreamble
  const source = typeof brief === 'string' && brief.trim() !== '' ? brief : DEFAULT_TASK_PREAMBLE
  const origin = record?.authority?.origin
  const level = record?.authority?.level
  return `[A2A task]${origin === undefined ? '' : ` from peer "${origin}"${level === undefined ? '' : ` (${level} authority)`}`}: `
    + source
}

/** Build a timestamped A2A TaskStatus. */
function status(state) {
  return { state, message: undefined, timestamp: new Date().toISOString() }
}

/** Build one A2A artifact from text parts. */
function makeArtifact(taskId, parts) {
  return {
    artifactId: `artifact-${taskId}`,
    name: 'assistant',
    description: '',
    parts,
    metadata: undefined,
    extensions: [],
  }
}

/** Convert DSH content blocks to A2A text parts. */
function contentBlocksToParts(blocks) {
  const parts = []
  for (const block of blocks) {
    if (block.type === 'text' && block.text.length > 0) {
      parts.push({
        content: { $case: 'text', value: block.text },
        metadata: undefined,
        filename: '',
        mediaType: 'text/plain',
      })
    }
  }
  return parts
}

/** Convert an A2A user Message to DSH content blocks. */
function messageToContentBlocks(message) {
  const blocks = []
  for (const part of message.parts) {
    const value = part.content
    if (value === undefined) continue
    if (value.$case === 'text') {
      blocks.push({ type: 'text', text: value.value })
    } else if (value.$case === 'data') {
      blocks.push({ type: 'text', text: JSON.stringify(value.value) })
    } else if (value.$case === 'url') {
      blocks.push({ type: 'text', text: value.value })
    } else if (value.$case === 'raw') {
      blocks.push({ type: 'text', text: `[raw file ${part.filename || 'unnamed'}]` })
    }
  }
  return blocks
}

/**
 * Normalize A2A JSON-RPC role fields to the SDK's protobuf enum names.
 *
 * The A2A spec examples use lowercase "user"/"agent", while the official
 * SDK's JSON parser expects "ROLE_USER"/"ROLE_AGENT". Recursively rewrites
 * role fields so both wire styles are accepted.
 */
function normalizeA2ARole(value) {
  if (Array.isArray(value)) return value.map(normalizeA2ARole)
  if (typeof value === 'object' && value !== null) {
    const result = {}
    for (const [key, child] of Object.entries(value)) {
      result[key] = key === 'role' && typeof child === 'string'
        ? normalizeRoleValue(child)
        : normalizeA2ARole(child)
    }
    return result
  }
  return value
}

/** Map a lowercase A2A role to the SDK enum name; unknown values pass through. */
function normalizeRoleValue(role) {
  switch (role) {
    case 'user': return 'ROLE_USER'
    case 'agent': return 'ROLE_AGENT'
    case 'unspecified': return 'ROLE_UNSPECIFIED'
    default: return role
  }
}

/**
 * Simple Prometheus-style counters for the A2A server.
 * @typedef {{requests:number, totalTasks:number, completedTasks:number, failedTasks:number, canceledTasks:number, authorityRejected:number}} Metrics
 */

/** Create a zero-initialized metrics record. */
function createMetrics() {
  return { requests: 0, totalTasks: 0, completedTasks: 0, failedTasks: 0, canceledTasks: 0, authorityRejected: 0 }
}

/**
 * List available agent preset ids for AgentCard discovery.
 * @param {any} ctx
 * @returns {Promise<string[]>}
 */
async function listPresetIds(ctx) {
  const agentPresets = ctx.get('agentPresets')
  if (agentPresets === undefined) return []
  try {
    return (await agentPresets.list()).map(preset => preset.id)
  } catch {
    // Discovery is best-effort: an unreadable roster should not break AgentCard.
    return []
  }
}

/**
 * Resolve the agent preset id for one request: per-request metadata wins,
 * falling back to the global config.
 */
function resolvePreset(metadata, fallback) {
  const requested = metadata?.agentPreset ?? metadata?.preset
  if (typeof requested === 'string' && requested.length > 0) return requested
  return fallback
}

/**
 * Operator handles are NOT resolvable from inbound requests.
 *
 * A `metadata.operator` field and a bare `op_…` in the message text were both
 * accepted once, so a peer could address one operator by name. That is the
 * sender deciding our internal routing, and it is also a lever: an inbound
 * handle could confirm which operators exist and pin a conversation to one.
 * Routing belongs to the receiver (§20.15), so the field is ignored — the
 * exported helper is kept as the documented answer for anyone porting.
 * @returns {undefined}
 */
function handleFromRequest() {
  return undefined
}

/** Dispose terminal Tasks older than `ttlMs` and remove them from the registry. */
async function cleanupExpired(records, ttlMs, logger) {
  const now = Date.now()
  const expired = []
  for (const [id, record] of records) {
    if (record.terminalPublished && now - record.createdAt >= ttlMs) {
      records.delete(id)
      expired.push(record)
    }
  }
  const results = await Promise.allSettled(expired.map(record => record.dispose()))
  for (const result of results) {
    if (result.status === 'rejected') logger.warn(`dsh-nuncia: TTL task teardown failed: ${String(result.reason)}`)
  }
}

/** Render the metrics record as Prometheus text format. */
function renderMetrics(metrics, activeTasks) {
  return [
    '# HELP nuncia_requests_total Total HTTP requests handled by the A2A server.',
    '# TYPE nuncia_requests_total counter',
    `nuncia_requests_total ${metrics.requests}`,
    '# HELP nuncia_active_tasks Current number of live A2A tasks.',
    '# TYPE nuncia_active_tasks gauge',
    `nuncia_active_tasks ${activeTasks}`,
    '# HELP nuncia_tasks_total Total A2A tasks created.',
    '# TYPE nuncia_tasks_total counter',
    `nuncia_tasks_total ${metrics.totalTasks}`,
    '# HELP nuncia_completed_tasks_total Completed A2A tasks.',
    '# TYPE nuncia_completed_tasks_total counter',
    `nuncia_completed_tasks_total ${metrics.completedTasks}`,
    '# HELP nuncia_failed_tasks_total Failed A2A tasks.',
    '# TYPE nuncia_failed_tasks_total counter',
    `nuncia_failed_tasks_total ${metrics.failedTasks}`,
    '# HELP nuncia_canceled_tasks_total Canceled A2A tasks.',
    '# TYPE nuncia_canceled_tasks_total counter',
    `nuncia_canceled_tasks_total ${metrics.canceledTasks}`,
    '# HELP nuncia_authority_rejected_total Inbound authority envelopes that failed verification and fell back to peer.',
    '# TYPE nuncia_authority_rejected_total counter',
    `nuncia_authority_rejected_total ${metrics.authorityRejected}`,
  ].join('\n')
}

/** Send a plain-text response. */
function sendText(res, text) {
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
  res.end(text)
}

/** Parse an A2A follow-up message into an approval decision. */
function parseApprovalDecision(message) {
  const text = message.parts
    .flatMap(part => part.content?.$case === 'text' ? [part.content.value] : [])
    .join(' ')
    .toLowerCase()
  if (text.includes('allow') || text.includes('approve') || text.includes('yes')) return 'allowed-once'
  if (text.includes('reject') || text.includes('deny') || text.includes('no')) return 'rejected'
  return 'rejected'
}

/** Read a bounded JSON request body. */
async function readBody(req, limit) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buffer.length
    if (size > limit) throw new Error('request body too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/** Send a JSON response. */
function sendJson(res, value, status = 200) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(value))
}

/** Narrowing helper for the SDK's JSON-RPC streaming return. */
function isAsyncIterable(value) {
  return typeof value === 'object' && value !== null && Symbol.asyncIterator in value
}

/**
 * Resolve the model selection an A2A-created agent runs with.
 *
 * Precedence: explicit plugin config (`provider`/`model`) wins; otherwise fall
 * back to the host's `agentDefaultModel` service, exactly as `dsh-headless`
 * does. Without a bound model the stock `standard` preset cannot assemble its
 * persona prefix ({{model}}), so `undefined` here is a real misconfiguration
 * rather than a neutral default.
 *
 * @param {any} ctx
 * @param {A2aServerConfig} config
 * @returns {{provider?: string, model?: string}|undefined}
 */
function resolveModelSelection(ctx, config) {
  if (config.model !== undefined || config.provider !== undefined) {
    return {
      ...config.provider !== undefined ? { provider: config.provider } : {},
      ...config.model !== undefined ? { model: config.model } : {},
    }
  }
  const defaultModel = ctx.get('agentDefaultModel')
  if (defaultModel === undefined) return undefined
  try {
    const selection = defaultModel.currentSelection()
    if (selection === undefined || selection === null) return undefined
    const resolved = {
      ...selection.provider !== undefined ? { provider: selection.provider } : {},
      ...selection.model !== undefined ? { model: selection.model } : {},
    }
    return Object.keys(resolved).length > 0 ? resolved : undefined
  } catch {
    // A throwing selection service must not take the listener down; the boot
    // warning above already tells the operator what to configure.
    return undefined
  }
}

/**
 * Build per-agent options: the boot-resolved model, overridable per request via
 * `params.metadata.provider|model` (an A2A client may pin a different route for
 * one task). Absent fields are omitted rather than set to undefined.
 *
 * @param {{provider?: string, model?: string}|undefined} resolved
 * @param {Record<string, unknown>|undefined} metadata
 */
function agentOptions(resolved, metadata) {
  const provider = typeof metadata?.provider === 'string' && metadata.provider !== ''
    ? metadata.provider
    : resolved?.provider
  const model = typeof metadata?.model === 'string' && metadata.model !== ''
    ? metadata.model
    : resolved?.model
  return {
    ...provider !== undefined ? { provider } : {},
    ...model !== undefined ? { model } : {},
  }
}
