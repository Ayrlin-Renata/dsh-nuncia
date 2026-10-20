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

import { createServer } from 'node:http'
import { hostname } from 'node:os'
import { isAbsolute, join } from 'node:path'
import Schema from 'schemastery'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { AgentCard, TaskState, formatSSEEvent } from '@a2a-js/sdk'
import {
  AgentEvent,
  DefaultRequestHandler,
  InMemoryTaskStore,
  JsonRpcTransportHandler,
  ServerCallContext,
} from '@a2a-js/sdk/server'
import { DEFAULT_MAX_WINDOW_MS, deriveAuthorityKey, deriveBearerToken } from './authority.js'
import { GrantStore } from './grants.js'
import { SecurityLog, createAuthorityGate } from './inbound.js'
import { createOutboundClient, parsePeerUrls } from './outbound.js'
import { FileTaskStore } from './task-store.js'

export const name = 'dsh-nuncia'
export const inject = ['agents']

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
  }),
  taskTtlMs: Schema.natural().min(1),
  metricsPath: Schema.string(),
  adminPath: Schema.string().default('/a2a/admin'),
  persistTasks: Schema.boolean().default(false),
  persistenceRoot: Schema.string(),
  authority: Schema.object({
    enabled: Schema.boolean().default(false),
    nodeName: Schema.string(),
    pairingSecretEnv: Schema.string().default('NUNCIA_PAIRING_SECRET'),
    peers: Schema.array(Schema.string()),
    peerUrls: Schema.array(Schema.string()),
    maxWindowMs: Schema.natural(),
    grantTtlMs: Schema.natural(),
    persistGrants: Schema.boolean().default(false),
    tools: Schema.boolean().default(true),
  }),
  agentCard: Schema.object({
    name: Schema.string(),
    description: Schema.string(),
    url: Schema.string(),
    version: Schema.string(),
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
  ])
  const cwd = config.cwd ?? process.cwd()
  const authToken = resolveAuthToken(config)
  const metrics = createMetrics()
  let enabled = true

  // Authority layer (DESIGN §20). Off unless explicitly enabled: an
  // unpaired node behaves exactly as before, peer-only. When enabled but
  // misconfigured it fails DOWN (peer) and reports the reason in /status
  // rather than refusing to boot — rule 5, notify loud, never silent.
  const authority = createAuthorityRuntime(config, cwd, logger)
  if (authority.enabled) {
    logger.info?.(`dsh-nuncia: authority enabled as "${authority.nodeName}" (max window ${authority.maxWindowMs} ms)`)
  } else if (authority.error !== undefined) {
    logger.warn(`dsh-nuncia: authority disabled — ${authority.error}`)
  }
  const peerUrls = parsePeerUrls(config.authority?.peerUrls ?? [])
  const outbound = authority.enabled
    ? createOutboundClient({
        peers: peerUrls,
        token: authority.bearerToken,
        envelopeFor: (peer) => authority.grants.envelopeFor(peer),
        onSecurityEvent: (event) => recordSecurityEvent(ctx, authority, logger, event),
      })
    : undefined
  if (authority.enabled && config.authority?.tools !== false) {
    registerAuthorityTools(ctx, {
      grants: authority.grants,
      outbound,
      logger,
      unknownPeers: () => [...peerUrls.keys()],
    })
  }

  /** @param {any} agent */
  const ownedRecord = (agent) => {
    // Same shape-drift guard as the session/event listener below.
    const sid = agent?.session?.header?.id ?? agent?.session?.id
    if (sid === undefined) return undefined
    const record = records.get(sid)
    return record?.agent === agent ? record : undefined
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

  const agentCard = makeAgentCard(config, path, await listPresetIds(ctx), authority)
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    taskStore,
    makeExecutor(ctx, records, config, cwd, metrics, resolvedModel, authority),
  )
  const jsonRpc = new JsonRpcTransportHandler(requestHandler)

  /** @param {any} req @param {any} res */
  const handleHttp = async (req, res) => {
    const url = req.url ?? '/'
    metrics.requests++
    if (req.method === 'GET' && url === agentCardPath) {
      sendJson(res, AgentCard.toJSON(makeAgentCard(config, path, await listPresetIds(ctx), authority)))
      return
    }
    if (config.metricsPath !== undefined && req.method === 'GET' && url === config.metricsPath) {
      sendText(res, renderMetrics(metrics, records.size))
      return
    }
    if (adminRoutes.has(url)) {
      if (authToken !== undefined && req.headers.authorization !== `Bearer ${authToken}`) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized' }))
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
              : { level: record.authority.level, scope: record.authority.scope, expiresAt: record.authority.exp },
          })),
          authority: describeAuthority(authority),
        })
        return
      }
      if (req.method === 'POST' && (url === `${adminPath}/enable` || url === `${adminPath}/disable`)) {
        enabled = url.endsWith('/enable')
        sendJson(res, { enabled })
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
      if (authToken !== undefined && req.headers.authorization !== `Bearer ${authToken}`) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized' }))
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

  const webServer = /** @type {WebServerLike|undefined} */ (ctx.get('webServer'))
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
    const record = records.get(sid)
    if (record === undefined || record.agent.session !== session) return
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
      const failed = event.data.reason.kind === 'error'
      // Surface the DSH turn-end reason to the A2A client: without it a
      // failed task is undiagnosable remotely (live lesson: a FAILED task
      // with no detail once cost a whole debug round). The reason payload's
      // message/error fields drift between plain strings and objects across
      // trains — stringified fallback keeps us honest either way.
      const rawDetail = event.data.reason.message ?? event.data.reason.error
      const detail = typeof rawDetail === 'string'
        ? rawDetail
        : (rawDetail !== undefined && rawDetail !== null ? JSON.stringify(rawDetail) : '')
      const reasonText = [event.data.reason.kind, detail].filter(s => s !== '').join(': ')
      const taskStatus = {
        state: failed ? TaskState.TASK_STATE_FAILED : TaskState.TASK_STATE_COMPLETED,
        message: failed && reasonText
          ? {
              messageId: `reason-${record.taskId}`,
              role: 'ROLE_AGENT',
              parts: [{ content: { $case: 'text', value: reasonText }, filename: '', mediaType: 'text/plain', metadata: undefined }],
              metadata: undefined,
            }
          : undefined,
        timestamp: new Date().toISOString(),
      }
      if (failed) metrics.failedTasks++
      else metrics.completedTasks++
      eventBus.publish(AgentEvent.statusUpdate({
        taskId: record.taskId,
        contextId: record.contextId,
        status: taskStatus,
        metadata: undefined,
      }))
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

  /** @type {any} */
  let ttlTimer
  if (config.taskTtlMs !== undefined) {
    const ttlMs = config.taskTtlMs
    ttlTimer = setInterval(() => {
      void cleanupExpired(records, ttlMs, logger).catch((/** @type {unknown} */ error) => {
        logger.error(`dsh-nuncia: TTL cleanup failed: ${String(error)}`)
      })
    }, Math.min(ttlMs, 60_000))
  }

  ctx.effect(() => () => {
    if (ttlTimer !== undefined) clearInterval(ttlTimer)
    return quiesce(records, logger)
  }, 'dsh-nuncia.tasks')
}

// -- AgentCard ------------------------------------------------------------------

/**
 * Build the AgentCard served at `agentCardPath`.
 * @param {A2aServerConfig} config
 * @param {string} path
 * @param {string[]} presetIds
 * @param {AuthorityRuntime} [authority]
 */
function makeAgentCard(config, path, presetIds = [], authority) {
  const host = config.host ?? '127.0.0.1'
  const port = config.port ?? 4123
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
    name: config.agentCard?.name ?? 'DeepSeek Harness Agent',
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
      extensions: [{
        uri: 'https://nucia.local/a2a/preset-selection',
        description: 'To select an agent preset for a task, include "agentPreset" (or "preset") in SendMessage/SendStreamingMessage params.metadata.',
        required: false,
        params: {
          metadataKey: 'agentPreset',
          aliases: ['preset'],
          default: config.agentPreset ?? null,
          presets: presetIds,
        },
        ...authority?.enabled === true ? [{
          uri: 'https://nuncia.local/a2a/authority',
          description: 'User intent/override claims travel in a signed metadata.authority envelope (DESIGN §20). Message text is never authority.',
          required: false,
          params: {
            metadataKey: 'authority',
            levels: ['intent', 'override'],
            maxWindowMs: authority.maxWindowMs,
            node: authority.nodeName,
          },
        }] : [],
      }],
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
function makeExecutor(ctx, records, config, cwd, metrics, resolvedModel, authority) {
  const agents = ctx.agents
  const logger = ctx.logger

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
        })
      }
      const claimed = verdict.ok && verdict.carried
        ? { level: verdict.level, scope: verdict.scope, origin: verdict.origin, exp: verdict.exp, jti: verdict.jti }
        : undefined

      let record = records.get(taskId)
      if (record === undefined) {
        if (!isAbsolute(cwd)) throw new Error(`cwd must be an absolute path: ${cwd}`)
        const sessionId = SessionId(taskId)
        const handle = await agents.create({
          sessionId,
          meta: {
            cwd,
            ...(presetId !== undefined ? { agentPreset: presetId } : {}),
          },
          agentOptions: agentOptions(resolvedModel, requestContext.request.metadata),
          ...(presetId !== undefined ? {
            setup: async (/** @type {any} */ agentCtx) => {
              const presets = ctx.get('agentPresets')
              if (presets === undefined) {
                throw new Error(`dsh-nuncia: agentPreset "${presetId}" configured but agentPresets service is unavailable`)
              }
              await presets.mount(agentCtx, presetId)
            },
          } : {}),
        })
        record = {
          taskId,
          contextId,
          agent: handle.agent,
          dispose: () => handle.dispose(),
          eventBus,
          terminalPublished: false,
          createdAt: Date.now(),
          authority: claimed,
        }
        records.set(taskId, record)
        metrics.totalTasks++
      } else {
        record.contextId = contextId
        record.eventBus = eventBus
        record.authority = claimed
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
        metadata: undefined,
      }))
      eventBus.publish(AgentEvent.statusUpdate({
        taskId,
        contextId,
        status: status(TaskState.TASK_STATE_WORKING),
        metadata: undefined,
      }))

      const content = messageToContentBlocks(requestContext.userMessage)
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
  const tasks = [...records.values()]
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
function createAuthorityRuntime(config, cwd, logger) {
  const security = new SecurityLog()
  const settings = config.authority
  if (settings?.enabled !== true) return { enabled: false, security }

  const secretEnv = settings.pairingSecretEnv ?? 'NUNCIA_PAIRING_SECRET'
  const secret = process.env[secretEnv]
  if (secret === undefined || secret === '') {
    const error = `pairing secret ${secretEnv} is not set (it must be exported into the harness process)`
    security.record({ kind: 'authority-disabled', reason: 'pairing-secret-missing', detail: { env: secretEnv } })
    return { enabled: false, error, security }
  }

  let key
  try {
    key = deriveAuthorityKey(secret)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    security.record({ kind: 'authority-disabled', reason: 'pairing-secret-invalid', detail: { env: secretEnv } })
    return { enabled: false, error: `cannot derive authority key: ${message}`, security }
  }

  const nodeName = sanitizeNodeName(settings.nodeName ?? hostname())
  const maxWindowMs = settings.maxWindowMs ?? DEFAULT_MAX_WINDOW_MS
  const grants = new GrantStore({
    key,
    origin: nodeName,
    maxWindowMs,
    ...settings.grantTtlMs === undefined ? {} : { defaultTtlMs: settings.grantTtlMs },
    ...settings.persistGrants === true
      ? { persistPath: join(config.persistenceRoot ?? cwd, 'nuncia-grants.json') }
      : {},
    onWarn: (message) => logger.warn(`dsh-nuncia: ${message}`),
  })
  const gate = createAuthorityGate({
    key,
    nodeName,
    peers: settings.peers ?? [],
    maxWindowMs,
  })
  return { enabled: true, nodeName, maxWindowMs, key, bearerToken: deriveBearerToken(secret), grants, gate, security }
}

/**
 * Node names appear in a signed canonical form, so they are restricted to a
 * token charset. A hostname is a convenience default, not a guarantee: sanitize
 * it once here rather than letting mint/verify disagree about the name.
 * @param {string} name
 * @returns {string}
 */
function sanitizeNodeName(name) {
  const cleaned = String(name)
    .toLowerCase()
    .replace(/[^a-z0-9._:-]/g, '-')
    .replace(/^[-._:]+/, '')
  return cleaned.length > 0 ? cleaned.slice(0, 64) : 'nuncia'
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
  return {
    enabled: true,
    nodeName: authority.nodeName,
    maxWindowMs: authority.maxWindowMs,
    grants: authority.grants.list().grants,
    securityEvents: authority.security.list(),
  }
}

/**
 * Record a security event in the bounded log and republish it on the host bus.
 *
 * The log is local evidence for `/status`; the emitted event is what lets a
 * host plugin (Sylvia's panel, a toast, an OS dialog) react without polling.
 */
function recordSecurityEvent(ctx, authority, logger, event) {
	const stored = authority?.security?.record(event) ?? event
	try {
		ctx.emit?.('nuncia/security-event', stored)
	} catch (error) {
		logger.warn(`dsh-nuncia: security-event listener threw: ${String(error)}`)
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
function registerAuthorityTools(ctx, { grants, outbound, logger, unknownPeers }) {
	const register = (tools) => {
		if (tools?.register === undefined) {
			logger.warn('dsh-nuncia: tools service found but register() is missing — authority tools not registered')
			return
		}
		tools.register(requestUserIntentTool(ctx, grants))
		if (outbound !== undefined) tools.register(a2aSendTool(outbound, unknownPeers))
		logger.info?.('dsh-nuncia: registered request_user_intent' + (outbound === undefined ? '' : ' + a2a_send'))
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
 * `request_user_intent` — the agent-requested path to a grant (§20.2.2).
 *
 * The approval IS the authorization: nothing is minted unless the user answers
 * `allowed-once`. On hosts where approvals are policy-disabled (this session
 * runs danger-full-access, where the base bundle sets `policy: 'never'`) the
 * service answers `rejected` immediately, and the tool says so instead of
 * pretending — the admin endpoint remains the working path there.
 */
function requestUserIntentTool(ctx, grants) {
	return {
		name: 'request_user_intent',
		description:
			'Ask the user to grant temporary authority to act on their behalf toward a paired A2A peer, then mint it. '
			+ 'Only an explicit user approval grants authority; grant bytes are never returned to you. '
			+ 'Use POST /a2a-admin/mint instead when the user is at the panel.',
		parameters: {
			target: { type: 'string', required: true, description: 'Peer node name (see authority.peerUrls).' },
			level: { type: 'string', description: 'intent (default) or override. override may contradict house rules.' },
			ttlMs: { type: 'number', description: 'Requested window in milliseconds (default 5 minutes, subject to maxWindowMs).' },
			scope: { type: 'string', description: 'Free-text scope recorded inside the signed envelope.' },
		},
		output: {
			schema: {
				type: 'object',
				additionalProperties: false,
				properties: {
					granted: { type: 'boolean', required: true },
					id: { type: 'string' },
					level: { type: 'string' },
					target: { type: 'string' },
					expiresAt: { type: 'number' },
				},
			},
			render: (_args, value) => [{
				type: 'text',
				text: value.granted
					? `granted ${value.level} authority to "${value.target}" until ${new Date(value.expiresAt).toISOString()} (grant ${value.id})`
					: 'no grant was minted',
			}],
		},
		async execute(args, exec) {
			const approval = ctx.get?.('approval')
			const agent = exec?.agent
			if (approval === undefined || agent === undefined) {
				throw new Error('user approval is unavailable on this host — mint through POST /a2a/admin/mint instead')
			}
			const level = args.level === 'override' ? 'override' : 'intent'
			const ttlMs = typeof args.ttlMs === 'number' ? args.ttlMs : grants.defaultTtlMs
			const minutes = Math.max(1, Math.round(ttlMs / 60_000))
			const outcome = await approval.request({
				agent,
				toolName: 'request_user_intent',
				...(exec.callId === undefined ? {} : { callId: exec.callId }),
				reason: `Grant "${level}" authority to ${args.target} for ~${minutes} min${typeof args.scope === 'string' ? ` (scope: ${args.scope})` : ''}`,
				...(exec.signal === undefined ? {} : { signal: exec.signal }),
			})
			if (outcome !== 'allowed-once') {
				throw new Error(`the user did not approve (${outcome}); no grant was minted`)
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

/** `a2a_send` — contact a paired peer; the plugin attaches a live grant if one exists. */
function a2aSendTool(outbound, unknownPeers) {
	return {
		name: 'a2a_send',
		description:
			'Send a message to a paired A2A peer and return its answer. '
			+ 'If a live authority grant exists for that peer it is attached automatically — you never handle grant bytes.',
		parameters: {
			peer: { type: 'string', required: true, description: 'Peer name as configured in authority.peerUrls.' },
			text: { type: 'string', required: true, description: 'The message to send.' },
		},
		output: {
			schema: {
				type: 'object',
				additionalProperties: false,
				properties: {
					peer: { type: 'string', required: true },
					taskId: { type: 'string' },
					state: { type: 'string', required: true },
					text: { type: 'string' },
					carriedAuthority: { type: 'boolean' },
				},
			},
			render: (_args, value) => [{
				type: 'text',
				text: `${value.peer} → ${value.state}${value.carriedAuthority ? ' (with your grant)' : ''}${value.text ? `: ${value.text}` : ''}`,
			}],
		},
		async execute(args) {
			const known = unknownPeers === undefined ? [] : unknownPeers()
			try {
				return await outbound.send({ peer: args.peer, text: args.text })
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

/** Resolve the configured bearer token from a literal or environment variable. */
function resolveAuthToken(config) {
  const auth = config.auth
  if (auth === undefined || (auth.token === undefined && auth.tokenEnv === undefined)) return undefined
  const token = auth.tokenEnv !== undefined ? process.env[auth.tokenEnv] : auth.token
  if (token === undefined || token === '') {
    throw new Error('dsh-nuncia: auth is configured but no bearer token is available')
  }
  return token
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
