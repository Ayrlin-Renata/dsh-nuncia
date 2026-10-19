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
  const cwd = config.cwd ?? process.cwd()
  const authToken = resolveAuthToken(config)
  const metrics = createMetrics()
  let enabled = true

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

  const agentCard = makeAgentCard(config, path, await listPresetIds(ctx))
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    taskStore,
    makeExecutor(ctx, records, config, cwd, metrics, resolvedModel),
  )
  const jsonRpc = new JsonRpcTransportHandler(requestHandler)

  /** @param {any} req @param {any} res */
  const handleHttp = async (req, res) => {
    const url = req.url ?? '/'
    metrics.requests++
    if (req.method === 'GET' && url === agentCardPath) {
      sendJson(res, AgentCard.toJSON(makeAgentCard(config, path, await listPresetIds(ctx))))
      return
    }
    if (config.metricsPath !== undefined && req.method === 'GET' && url === config.metricsPath) {
      sendText(res, renderMetrics(metrics, records.size))
      return
    }
    if (url === `${adminPath}/status` || url === `${adminPath}/enable` || url === `${adminPath}/disable`) {
      if (authToken !== undefined && req.headers.authorization !== `Bearer ${authToken}`) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      if (req.method === 'GET' && url === `${adminPath}/status`) {
        sendJson(res, { enabled, activeTasks: records.size, ...metrics })
        return
      }
      if (req.method === 'POST' && (url === `${adminPath}/enable` || url === `${adminPath}/disable`)) {
        enabled = url.endsWith('/enable')
        sendJson(res, { enabled })
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
 */
function makeAgentCard(config, path, presetIds = []) {
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
 */
function makeExecutor(ctx, records, config, cwd, metrics, resolvedModel) {
  const agents = ctx.agents

  return {
    async execute(requestContext, eventBus) {
      const taskId = requestContext.taskId
      const contextId = requestContext.contextId
      const presetId = resolvePreset(requestContext.request.metadata, config.agentPreset)
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
        }
        records.set(taskId, record)
        metrics.totalTasks++
      } else {
        record.contextId = contextId
        record.eventBus = eventBus
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
 * @typedef {{requests:number, totalTasks:number, completedTasks:number, failedTasks:number, canceledTasks:number}} Metrics
 */

/** Create a zero-initialized metrics record. */
function createMetrics() {
  return { requests: 0, totalTasks: 0, completedTasks: 0, failedTasks: 0, canceledTasks: 0 }
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
function sendJson(res, value) {
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
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
