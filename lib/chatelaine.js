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

  /**
   * Persist the adopted session id so a restart keeps the same chatelaine.
   *
   * `previousSessionId` is kept when the id changes: the old session still
   * exists on disk, and its id is the only way to find that thread again.
   *
   * @param {string} id
   * @param {string} [previous]
   */
  async function remember(id, previous) {
    try {
      await mkdir(stateDir, { recursive: true })
      const record = { version: 1, sessionId: id, adoptedAt: new Date().toISOString() }
      if (previous !== undefined && previous !== id) record.previousSessionId = previous
      await writeFile(stateFile, JSON.stringify(record, null, 2), { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      logger?.warn?.(`dsh-nuncia: could not record the chatelaine session id — ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  /**
   * The stored state: the current session id and, if it was ever changed, the
   * one it replaced. The previous id matters: an id migration (P3.1) or a
   * wiped store can leave the current id pointing at nothing, and the old
   * thread is then the only session that can still be resumed.
   * @returns {Promise<{sessionId?: string, previousSessionId?: string}>}
   */
  async function storedState() {
    try {
      const parsed = JSON.parse(await readFile(stateFile, 'utf8'))
      return {
        ...(typeof parsed?.sessionId === 'string' ? { sessionId: parsed.sessionId } : {}),
        ...(typeof parsed?.previousSessionId === 'string' ? { previousSessionId: parsed.previousSessionId } : {}),
      }
    } catch {
      return {}
    }
  }

  /** @returns {Promise<string|undefined>} */
  async function storedId() {
    return (await storedState()).sessionId
  }

  /**
   * The stored id in its recognisable form.
   *
   * A chatelaine session created before the A2A tagging (P3.1) is a valid
   * session but an INVISIBLE one: the metered gate recognises A2A sessions by
   * their id prefix, so an untagged chatelaine loses its exemption. The old
   * thread stays on disk; the node runs on the tagged id from now on.
   *
   * This used to live only in resolveId(), so a node that had never delivered
   * a report kept publishing the untagged id in /status — and never migrated.
   * peekId() is the path /status uses, so it migrates too.
   *
   * @returns {Promise<string|undefined>}
   */
  async function taggedId() {
    const stored = await storedId()
    if (stored === undefined) return undefined
    if (String(stored).startsWith(A2A_CHATELAINE_PREFIX)) return stored
    const migrated = `${A2A_CHATELAINE_PREFIX}${String(stored).replace(/^session-/, '')}`
    await remember(migrated, stored)
    logger?.info?.(`dsh-nuncia: migrated the chatelaine session id to ${migrated} (the old thread is kept)`)
    return migrated
  }

  /**
   * Re-resolve a live agent. `get` is the fast path; `resume` is the cold one
   * and throws if the session is already live, hence the order.
   *
   * A session id can point at nothing: the store was wiped, or the id was
   * migrated to a tagged form whose directory does not exist. The caller
   * passes the candidates in order and this returns the first that resolves.
   *
   * @param {string[]} candidates
   * @returns {Promise<{agent?: any, tried: string[]}>}
   */
  async function resolveAgentFrom(candidates) {
    const agents = ctx.agents
    const tried = []
    if (agents === undefined) return { tried }
    for (const sessionId of candidates) {
      if (typeof sessionId !== 'string' || sessionId === '') continue
      tried.push(sessionId)
      const live = typeof agents.get === 'function' ? agents.get(SessionId(sessionId)) : undefined
      if (live !== undefined) return { agent: live, tried }
      if (typeof agents.resume !== 'function') continue
      try {
        const resumed = await agents.resume({ resumeSessionId: SessionId(sessionId), agentOptions: agentOptions() })
        if (resumed?.agent !== undefined) return { agent: resumed.agent, tried }
      } catch (error) {
        if (!warned) {
          warned = true
          logger?.warn?.(`dsh-nuncia: could not resume session ${sessionId} — ${error instanceof Error ? error.message : String(error)}`)
        }
      }
    }
    return { tried }
  }

  /**
   * Re-resolve a live agent by one id (the old single-id contract).
   * @param {string} sessionId
   * @returns {Promise<any|undefined>}
   */
  async function resolveAgent(sessionId) {
    const { agent } = await resolveAgentFrom([sessionId])
    return agent
  }

  /**
   * Create a chatelaine session and adopt it.
   *
   * `requestedId` lets the caller MATERIALISE an id that was migrated but never
   * created (see `ensureTagged`). That distinction matters: DSH cannot rename a
   * session (the v4 header carries its own id and `validateSessionHeader`
   * rejects a mismatch), so an id migration can only ever produce a NEW session.
   * Creating it on demand is what makes the tagged id true instead of a claim.
   *
   * @param {string} [previous] the id this one replaces, kept for fallback
   * @param {string} [requestedId] create with this exact id
   * @returns {Promise<string|undefined>}
   */
  async function createSession(previous, requestedId) {
    const agents = ctx.agents
    if (agents === undefined || typeof agents.create !== 'function') return undefined
    const id = requestedId ?? `${A2A_CHATELAINE_PREFIX}${randomUUID()}`
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
      await remember(id, previous)
      logger?.info?.(`dsh-nuncia: adopted chatelaine session ${id}`)
      return id
    } catch (error) {
      logger?.warn?.(`dsh-nuncia: could not create the chatelaine session — ${error instanceof Error ? error.message : String(error)}`)
      return undefined
    }
  }

  /**
   * Make the stored (tagged) chatelaine id REAL.
   *
   * The id migration renamed the pointer without moving the session — and it
   * cannot move it, because a v4 session's id is inside its own header. So a
   * node that migrated carries a tagged id with no session behind it: `/status`
   * advertises it, the metered gate matches its prefix, and nothing answers to
   * it. This creates the session under that exact id, so the tag stops being a
   * claim. Returns undefined when the id is not a tagged one or creation fails.
   *
   * @returns {Promise<string|undefined>}
   */
  async function ensureTagged() {
    const id = await taggedId()
    if (id === undefined || !String(id).startsWith(A2A_CHATELAINE_PREFIX)) return undefined
    const { agent } = await resolveAgentFrom([id])
    if (agent !== undefined) return id
    const state = await storedState()
    logger?.info?.(`dsh-nuncia: the chatelaine id ${id} has no session yet — creating it`)
    return await createSession(state.previousSessionId, id)
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
      const stored = await taggedId()
      if (stored !== undefined) {
        // A migrated id may have no session behind it (DSH cannot rename one),
        // so make it real before anything tries to resume it.
        const materialised = await ensureTagged()
        cachedId = materialised ?? stored
        return cachedId
      }
      return await createSession()
    })()
    try {
      return await resolving
    } finally {
      resolving = undefined
    }
  }

  /**
   * The ids that might hold the chatelaine thread, in the order they are
   * tried: the current id, then the one it replaced, then the configured one.
   * @returns {Promise<string[]>}
   */
  async function candidateIds() {
    const state = await storedState()
    const ids = []
    const current = state.sessionId === undefined ? undefined : await taggedId()
    if (current !== undefined) ids.push(current)
    if (state.previousSessionId !== undefined && !ids.includes(state.previousSessionId)) {
      ids.push(state.previousSessionId)
    }
    if (config.chatelaine?.sessionId !== undefined && !ids.includes(config.chatelaine.sessionId)) {
      ids.push(config.chatelaine.sessionId)
    }
    return ids
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
    // resolveId() is authoritative: it materialises a migrated-but-missing
    // tagged session, and creates one when nothing was ever stored. The old
    // thread stays available as a FALLBACK candidate, never as the destination
    // we would rather use — a chatelaine that lives under an untagged id is
    // invisible to the metered gate, which is exactly when it matters most.
    const primary = await resolveId()
    if (primary === undefined) {
      return { delivered: false, reason: 'no chatelaine session (the agents service is unavailable)' }
    }
    const candidates = [primary, ...(await candidateIds()).filter((id) => id !== primary)]
    const { agent, tried } = await resolveAgentFrom(candidates)
    if (agent !== undefined) {
      const sessionId = tried[tried.length - 1]
      try {
        if (mode.wake === true && typeof agent.followup === 'function') agent.followup(noticeMessage(text))
        else agent.inject(noticeMessage(text))
        return { delivered: true, sessionId }
      } catch (error) {
        return { delivered: false, sessionId, reason: error instanceof Error ? error.message : String(error) }
      }
    }
    // Nothing resolved: the stored id points at a session that is GONE (the
    // store was wiped, or the id was migrated and the new directory was never
    // created). Adopting a NEW session is better than losing every report
    // from here on — the human gets one fresh thread instead of silence.
    const fresh = await createSession(candidates[0])
    if (fresh === undefined) {
      return {
        delivered: false,
        ...(candidates[0] === undefined ? {} : { sessionId: candidates[0] }),
        reason: `the chatelaine session is not reachable (tried ${tried.length} id(s)) and a new one could not be created`,
      }
    }
    try {
      const resolved = await resolveAgentFrom([fresh])
      if (resolved.agent === undefined) {
        return { delivered: false, sessionId: fresh, reason: 'the new chatelaine session could not be reached either' }
      }
      if (mode.wake === true && typeof resolved.agent.followup === 'function') resolved.agent.followup(noticeMessage(text))
      else resolved.agent.inject(noticeMessage(text))
      return { delivered: true, sessionId: fresh, replaced: true }
    } catch (error) {
      return { delivered: false, sessionId: fresh, reason: error instanceof Error ? error.message : String(error) }
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
    peekId: async () => cachedId ?? await taggedId(),
    resolveAgent,
    attachToWorkspace,
    report,
    send,
    get stateFile() { return stateFile },
  }
}
