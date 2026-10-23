/**
 * Standing directives — the chatelaine's short, time-boxed policy for every
 * operator on this node (DESIGN §20.19).
 *
 * The problem this solves is the one that makes operators worth having: an
 * operator that forwards every decision to the chatelaine is a text
 * transformer, but an operator that decides everything alone is unsupervised.
 * A directive is the middle ground. The chatelaine states a policy once ("the
 * printer is booked for the next five hours — refuse requests for printer
 * usage"), every operator in force obeys it without asking, and it lapses on
 * its own so nobody has to remember to withdraw it.
 *
 * Rules that live here:
 *  - a directive is TEXT, not a rule engine. The operator is a model; it reads
 *    the sentence and applies it. Structured matching was rejected: the useful
 *    directives are the ones with judgement in them ("unless it is the
 *    maintenance node").
 *  - a directive always has an expiry. There is no permanent directive: an
 *    unbounded policy that nobody remembers writing is how a node quietly
 *    stops working. The cap is MAX_DIRECTIVE_MS (30 days).
 *  - expiry is noticed by the chatelaine WITHOUT a wake (inject, not
 *    followup): a lapsed directive is bookkeeping, not an emergency.
 *  - user intent overrides a directive. Enforcement of that is the operator's
 *    brief and `refuse_request`'s guard, not this file: a request that carries
 *    a verified intent window is escalated, never refused.
 */
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { dirname } from 'node:path'

/** File name inside the nuncia state directory. */
export const DIRECTIVES_FILE = 'directives.json'
/** `dir_` + 12 hex, short enough to quote in a report. */
export const DIRECTIVE_ID_PATTERN = /^dir_[0-9a-f]{12}$/
export const MIN_DIRECTIVE_MS = 60_000
export const MAX_DIRECTIVE_MS = 30 * 24 * 60 * 60 * 1000
export const MAX_DIRECTIVE_TEXT = 500

/**
 * One directive as stored.
 * @typedef {{
 *   id: string,
 *   text: string,
 *   scope?: string,
 *   createdAt: number,
 *   expiresAt: number,
 *   expiredAt?: number,
 *   postedBy?: string,
 * }} Directive
 */

/**
 * @param {unknown} value
 * @returns {value is Directive}
 */
function isDirective(value) {
  if (typeof value !== 'object' || value === null) return false
  const entry = /** @type {Record<string, unknown>} */ (value)
  return typeof entry.id === 'string'
    && DIRECTIVE_ID_PATTERN.test(entry.id)
    && typeof entry.text === 'string'
    && entry.text !== ''
    && typeof entry.createdAt === 'number'
    && typeof entry.expiresAt === 'number'
}

/** @returns {string} */
function newId() {
  return `dir_${randomBytes(6).toString('hex')}`
}

/**
 * A single JSON file of directives, written atomically at 0600.
 *
 * The book is deliberately not an OperatorBook-style service with TTLs of its
 * own: a directive's lifetime is the directive, and the only clock is the one
 * the chatelaine set. `expire()` is idempotent so a sweep can call it every few
 * seconds and report each lapse exactly once.
 */
export class DirectiveBook {
  /** @type {Map<string, Directive>} */
  #items = new Map()
  /** @type {Promise<void>} */
  #writeChain = Promise.resolve()
  /** @type {string} */
  #file

  /** @param {string} file */
  constructor(file) {
    this.#file = file
  }

  /** @returns {string} */
  get file() {
    return this.#file
  }

  /**
   * Load the book. A missing file is an empty book; a malformed one throws,
   * because silently starting empty would lose a policy the human is relying
   * on (the same reasoning as the operator book).
   * @returns {Promise<void>}
   */
  async init() {
    let raw
    try {
      raw = await readFile(this.#file, 'utf8')
    } catch (error) {
      if (/** @type {any} */ (error)?.code === 'ENOENT') return
      throw error
    }
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch {
      throw new Error(`dsh-nuncia: directive book is not valid JSON: ${this.#file}`)
    }
    const list = Array.isArray(parsed) ? parsed : parsed?.directives
    if (!Array.isArray(list)) {
      throw new Error(`dsh-nuncia: directive book has no directives array: ${this.#file}`)
    }
    for (const entry of list) {
      if (!isDirective(entry)) {
        throw new Error(`dsh-nuncia: directive book contains a malformed directive: ${this.#file}`)
      }
      this.#items.set(entry.id, entry)
    }
  }

  /**
   * Record a directive. The caller has already decided the text and the
   * lifetime; this only stamps and stores it.
   * @param {{text: string, ttlMs: number, scope?: string, postedBy?: string, now?: number}} input
   * @returns {Promise<Directive>}
   */
  async add(input) {
    const now = input.now ?? Date.now()
    const text = typeof input.text === 'string' ? input.text.trim() : ''
    if (text === '') throw new Error('a directive needs text')
    if (text.length > MAX_DIRECTIVE_TEXT) {
      throw new Error(`a directive is at most ${MAX_DIRECTIVE_TEXT} characters`)
    }
    if (!Number.isFinite(input.ttlMs) || input.ttlMs < MIN_DIRECTIVE_MS || input.ttlMs > MAX_DIRECTIVE_MS) {
      throw new Error(`a directive lasts between ${MIN_DIRECTIVE_MS / 60_000} minute and ${MAX_DIRECTIVE_MS / 86_400_000} days`)
    }
    /** @type {Directive} */
    const entry = {
      id: newId(),
      text,
      createdAt: now,
      expiresAt: now + Math.round(input.ttlMs),
      ...(input.scope === undefined || input.scope === '' ? {} : { scope: input.scope }),
      ...(input.postedBy === undefined ? {} : { postedBy: input.postedBy }),
    }
    this.#items.set(entry.id, entry)
    await this.save()
    return entry
  }

  /**
   * Every directive, oldest first, annotated against `now`.
   * @param {number} [now]
   * @returns {Array<Directive & {active: boolean, remainingMs: number}>}
   */
  list(now = Date.now()) {
    return [...this.#items.values()]
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((entry) => ({
        ...entry,
        active: entry.expiredAt === undefined && entry.expiresAt > now,
        remainingMs: Math.max(0, entry.expiresAt - now),
      }))
  }

  /**
   * The directives an operator must obey right now. Expired-but-unswept
   * entries are excluded by the clock, not by the sweep, so a late sweep can
   * never leave a lapsed policy in force.
   * @param {number} [now]
   * @returns {Array<Directive & {active: true, remainingMs: number}>}
   */
  active(now = Date.now()) {
    return /** @type {any} */ (this.list(now).filter((entry) => entry.active))
  }

  /**
   * Mark newly lapsed directives and return them — each exactly once, which is
   * what makes the expiry notice idempotent across sweeps.
   * @param {number} [now]
   * @returns {Promise<Directive[]>}
   */
  async expire(now = Date.now()) {
    const lapsed = [...this.#items.values()].filter(
      (entry) => entry.expiredAt === undefined && entry.expiresAt <= now,
    )
    if (lapsed.length === 0) return []
    for (const entry of lapsed) entry.expiredAt = now
    await this.save()
    return lapsed
  }

  /**
   * Withdraw a directive early.
   * @param {string} id
   * @returns {Promise<boolean>}
   */
  async remove(id) {
    if (!this.#items.delete(id)) return false
    await this.save()
    return true
  }

  /**
   * Drop directives that lapsed longer than `keepMs` ago. Kept entries are the
   * audit trail of what operators were told.
   * @param {{now?: number, keepMs?: number}} [options]
   * @returns {Promise<number>}
   */
  async prune(options = {}) {
    const now = options.now ?? Date.now()
    const keepMs = options.keepMs ?? 7 * 24 * 60 * 60 * 1000
    let removed = 0
    for (const [id, entry] of this.#items) {
      if (entry.expiredAt !== undefined && now - entry.expiredAt >= keepMs) {
        this.#items.delete(id)
        removed++
      }
    }
    if (removed > 0) await this.save()
    return removed
  }

  /** @returns {Promise<void>} */
  async save() {
    const payload = JSON.stringify({ version: 1, directives: [...this.#items.values()] }, null, 2)
    this.#writeChain = this.#writeChain.then(async () => {
      await mkdir(dirname(this.#file), { recursive: true })
      const tmp = `${this.#file}.${process.pid}.tmp`
      await writeFile(tmp, payload, { mode: 0o600 })
      await chmod(tmp, 0o600).catch(() => {})
      await rename(tmp, this.#file)
    })
    return this.#writeChain
  }
}

/**
 * Render the active directives as brief lines. Kept next to the book so the
 * operator brief and the expiry notice cannot drift apart in wording.
 * @param {Array<{text: string, remainingMs: number, scope?: string}>} directives
 * @returns {string[]}
 */
export function directiveBriefLines(directives) {
  if (directives.length === 0) return ['No standing directives are in force.']
  return [
    'Standing directives from the chatelaine — obey them while they last:',
    ...directives.map((entry) => `  · ${entry.text}${entry.scope === undefined ? '' : ` [scope: ${entry.scope}]`} — ${directiveRemaining(entry.remainingMs)} left`),
    'A directive is policy, not authority: if a request carries verified user intent it overrides the directive — escalate it to the chatelaine instead of refusing.',
  ]
}

/**
 * @param {number} ms
 * @returns {string}
 */
export function directiveRemaining(ms) {
  const minutes = Math.round(ms / 60_000)
  if (minutes < 60) return `~${Math.max(1, minutes)} min`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `~${hours} h`
  return `~${Math.round(hours / 24)} days`
}
