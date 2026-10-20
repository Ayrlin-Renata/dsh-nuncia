/**
 * The chatelaine: a stable session that represents the human inside this node.
 *
 * Operators are ordinary sessions; this module gives the plugin the two things
 * a session-based operator runtime needs and subagents would have provided for
 * free (DESIGN §20.11):
 *
 *  - **a way to reach a session it does not own** — `agents.get(id)` is live-only
 *    and process-local, so the cold path is `agents.resume(...)`, exactly the
 *    pattern the shipped session controller uses. Handles are *fiber-owned*: a
 *    plugin reload disposes every agent this plugin created or resumed, so we
 *    hold session **ids** and re-resolve on every delivery. Never cache an Agent.
 *  - **a durable, quiet channel** — `inject()` splices into the inbox projection
 *    (survives restarts, starts no turn); `followup()` wakes the session. A
 *    report is `inject`; a question is `followup`.
 *
 * Everything here fails soft: a chatelaine that cannot be reached must never
 * break the task that was trying to report to it.
 *
 * @module dsh-nuncia/chatelaine
 */
import { randomUUID } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { hostname } from 'node:os'
import { join } from 'node:path'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { expandHome } from './house.js'

/**
 * The chatelaine's session-id prefix. The v4 session format accepts only
 * `origin: "subagent"` in the durable header, so the A2A tag rides the
 * session id instead (DESIGN §20.12 P3.1).
 */
export const A2A_CHATELAINE_PREFIX = 'a2a-chatelaine-'

/** Default state directory: beside the node's other private state. */
export const DEFAULT_STATE_DIR = '~/.sylvia/nuncia'

/**
 * Build the durable plugin message used for every operator/chatelaine report.
 * The producer kind must be `plugin:<package>`: the v4 session format refuses a
 * bare `plugin` source and a rejected write fails the whole turn.
 * @param {string} text
 * @param {{summary?: string}} [options]
 */
export function noticeMessage(text, options = {}) {
  return createUserMessage({
    content: [{ type: 'text', text }],
    source: {
      kind: 'plugin:dsh-nuncia',
      form: 'notice',
      summary: boundContextSummary(options.summary ?? text.split('\n')[0]),
    },
  })
}

/**
 * Describe the level in one lowercase word for a brief.
 * @param {string} level
 */
function levelWord(level) {
  if (level === 'override') return 'user override'
  if (level === 'intent') return 'user intent'
  return 'peer (no user intent)'
}

/**
 * @param {number|undefined} expiresAt
 * @param {number} now
 */
function remainingWords(expiresAt, now) {
  if (typeof expiresAt !== 'number') return 'no expiry'
  const ms = expiresAt - now
  if (ms <= 0) return 'expired'
  const minutes = Math.round(ms / 60_000)
  if (minutes < 60) return `~${Math.max(1, minutes)} min`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `~${hours} h`
  return `~${Math.round(hours / 24)} days`
}

/**
 * The brief every operator receives before its first turn. It is prompt-level
 * discipline, not a sandbox (DESIGN §20.11, operator decision 2026-10-20): the
 * point is that the model knows who asked, how much authority came with the
 * ask, and where to take a doubt.
 * @param {{handle: string, taskId: string, level: string, scope?: string, origin?: string, expiresAt?: number, workspace: string, now?: number}} facts
 * @returns {string}
 */
export function operatorBrief(facts) {
  const now = facts.now ?? Date.now()
  const lines = [
    `[operator brief] You are an A2A operator on node "${hostname()}". Task ${facts.taskId}, handle ${facts.handle}.`,
    `The requester is ${facts.origin === undefined ? 'an unpaired peer' : `peer "${facts.origin}"`}; their authority is ${levelWord(facts.level)}${facts.scope === undefined ? '' : `, scope: ${facts.scope}`}${facts.expiresAt === undefined ? '' : `, ${remainingWords(facts.expiresAt, now)} left`}.`,
    `Your workspace is ${facts.workspace}. House rules are in HOUSE-RULES.md (skill: housekeeping) — they win over your own judgement about process.`,
    'Discipline: restate the request in one line first. Report to the chatelaine with report_to_chatelaine before anything consequential (files outside the workspace, long jobs, third parties) and again when you finish. Never ask the human directly — a human is not watching this session; ask the chatelaine, which decides what is worth the human\'s attention.',
    facts.level === 'peer'
      ? 'Without user intent, do not start work that outlives a short answer: answer from the house rules, or say in one line what you would need.'
      : 'The grant covers the scope above; stay inside it. If the work needs more, stop and ask the chatelaine rather than widening it yourself.',
  ]
  return lines.join('\n')
}

/**
 * @typedef {object} ChatelaineOptions
 * @property {any} ctx
 * @property {any} config
 * @property {string} workspace
 * @property {() => any} agentOptions - live agent options for a re-resumed session
 * @property {string|undefined} presetId
 * @property {string} [stateDir] - resolved state directory (shared with the operator book)
 * @property {any} logger
 */

/**
 * Create the chatelaine runtime. Nothing is created at construction: the
 * session is resolved (or created once) the first time something reports.
 * @param {ChatelaineOptions} options
 */
export function createChatelaineRuntime(options) {
  const { ctx, config, workspace, presetId, logger } = options
  const agentOptions = options.agentOptions ?? (() => ({}))
  const stateDir = expandHome(options.stateDir ?? config.chatelaine?.stateDir ?? DEFAULT_STATE_DIR)
  const stateFile = join(stateDir, 'chatelaine.json')
  /** @type {string|undefined} */
  let cachedId = config.chatelaine?.sessionId
  let resolving
  let warned = false

  /** Persist the adopted session id so a restart keeps the same chatelaine. */
  async function remember(id) {
    try {
      await mkdir(stateDir, { recursive: true })
      await writeFile(stateFile, JSON.stringify({ version: 1, sessionId: id, adoptedAt: new Date().toISOString() }, null, 2), { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      logger?.warn?.(`dsh-nuncia: could not record the chatelaine session id — ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  /** @returns {Promise<string|undefined>} */
  async function storedId() {
    try {
      const parsed = JSON.parse(await readFile(stateFile, 'utf8'))
      return typeof parsed?.sessionId === 'string' ? parsed.sessionId : undefined
    } catch {
      return undefined
    }
  }

  /**
   * Re-resolve a live agent. `get` is the fast path; `resume` is the cold one
   * and throws if the session is already live, hence the order.
   * @param {string} sessionId
   * @returns {Promise<any|undefined>}
   */
  async function resolveAgent(sessionId) {
    const agents = ctx.agents
    if (agents === undefined) return undefined
    const live = typeof agents.get === 'function' ? agents.get(SessionId(sessionId)) : undefined
    if (live !== undefined) return live
    if (typeof agents.resume !== 'function') return undefined
    try {
      const resumed = await agents.resume({ resumeSessionId: SessionId(sessionId), agentOptions: agentOptions() })
      return resumed?.agent
    } catch (error) {
      if (!warned) {
        warned = true
        logger?.warn?.(`dsh-nuncia: could not resume session ${sessionId} — ${error instanceof Error ? error.message : String(error)}`)
      }
      return undefined
    }
  }

  /**
   * Adopt (or create) the chatelaine session. A configured id always wins; an
   * id adopted in an earlier life is reused so the human keeps one thread.
   * @returns {Promise<string|undefined>}
   */
  async function resolveId() {
    if (cachedId !== undefined) return cachedId
    if (resolving !== undefined) return resolving
    resolving = (async () => {
      const stored = await storedId()
      if (stored !== undefined) {
        // A stored id from before the A2A tagging (P3.1) is still a valid
        // session — but it is not *recognisable* to the metered gate, and a
        // chatelaine that is not recognisable loses its exemption. Migrate the
        // id to the tagged form: the old session keeps its history, the new
        // one is what the node runs on from now on.
        if (!String(stored).startsWith(A2A_CHATELAINE_PREFIX)) {
          const migrated = `${A2A_CHATELAINE_PREFIX}${String(stored).replace(/^session-/, '')}`
          cachedId = migrated
          await remember(migrated)
          logger?.info?.(`dsh-nuncia: migrated the chatelaine session id to ${migrated} (the old thread is kept)`)
          return cachedId
        }
        cachedId = stored
        return cachedId
      }
      const agents = ctx.agents
      if (agents === undefined || typeof agents.create !== 'function') return undefined
      const id = `${A2A_CHATELAINE_PREFIX}${randomUUID()}`
      try {
        const handle = await agents.create({
          sessionId: SessionId(id),
          meta: {
            cwd: workspace,
            ...(presetId === undefined ? {} : { agentPreset: presetId }),
          },
          agentOptions: agentOptions(),
          ...(presetId === undefined ? {} : {
            setup: async (/** @type {any} */ agentCtx) => {
              const presets = ctx.get?.('agentPresets')
              if (presets === undefined) return
              await presets.mount(agentCtx, presetId)
            },
          }),
        })
        // The handle is fiber-owned: dispose it and keep the id. The session
        // exists on disk from here on and is resumed on first delivery.
        await handle.dispose?.()
        cachedId = id
        await remember(id)
        logger?.info?.(`dsh-nuncia: adopted chatelaine session ${id}`)
        return id
      } catch (error) {
        logger?.warn?.(`dsh-nuncia: could not create the chatelaine session — ${error instanceof Error ? error.message : String(error)}`)
        return undefined
      }
    })()
    try {
      return await resolving
    } finally {
      resolving = undefined
    }
  }

  /**
   * Attach a session to the Housekeeping workspace (best effort: the registry
   * validates the session's stored cwd, which must be the workspace path).
   * @param {string} sessionId
   */
  async function attachToWorkspace(sessionId) {
    const registry = ctx.get?.('workspaceRegistry')
    if (registry === undefined) return false
    try {
      const entity = await registry.create(workspace, 'Housekeeping')
      await entity?.attachSession?.(SessionId(sessionId))
      return true
    } catch (error) {
      logger?.debug?.(`dsh-nuncia: could not attach ${sessionId} to the housekeeping workspace — ${error instanceof Error ? error.message : String(error)}`)
      return false
    }
  }

  /**
   * Deliver a report to the chatelaine. `wake` is for questions that need an
   * answer; a report is silent and durable.
   * @param {string} text
   * @param {{wake?: boolean}} [mode]
   * @returns {Promise<{delivered: boolean, sessionId?: string, reason?: string}>}
   */
  async function report(text, mode = {}) {
    const sessionId = await resolveId()
    if (sessionId === undefined) return { delivered: false, reason: 'no chatelaine session (agents service unavailable)' }
    const agent = await resolveAgent(sessionId)
    if (agent === undefined) return { delivered: false, sessionId, reason: 'chatelaine session is not reachable' }
    try {
      if (mode.wake === true && typeof agent.followup === 'function') agent.followup(noticeMessage(text))
      else agent.inject(noticeMessage(text))
      return { delivered: true, sessionId }
    } catch (error) {
      return { delivered: false, sessionId, reason: error instanceof Error ? error.message : String(error) }
    }
  }

  /**
   * Deliver a message into an arbitrary session (an operator, by id).
   * @param {string} sessionId
   * @param {string} text
   * @param {{wake?: boolean}} [mode]
   */
  async function send(sessionId, text, mode = {}) {
    const agent = await resolveAgent(sessionId)
    if (agent === undefined) return { delivered: false, reason: 'session is not reachable' }
    try {
      if (mode.wake === true && typeof agent.followup === 'function') agent.followup(noticeMessage(text))
      else agent.inject(noticeMessage(text))
      return { delivered: true, sessionId }
    } catch (error) {
      return { delivered: false, sessionId, reason: error instanceof Error ? error.message : String(error) }
    }
  }

  return {
    resolveId,
    peekId: async () => cachedId ?? await storedId(),
    resolveAgent,
    attachToWorkspace,
    report,
    send,
    get stateFile() { return stateFile },
  }
}
