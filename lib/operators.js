/**
 * The operator book: one record per A2A task that has become an operator
 * session, keyed by a short handle the peer (and the chatelaine) can quote.
 *
 * The handle is a *lookup*, never a capability: re-contacting with `op_…` finds
 * the session, but the authority level of the new message is decided by its
 * envelope alone (DESIGN §20.1 rule 2). The book exists so a task survives
 * beyond the process (records are one small JSON file) and so expiry is a
 * property of the task rather than of the global task TTL.
 *
 * @module dsh-nuncia/operators
 */
import { randomBytes } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

/** Handle shape: `op_` + 16 lowercase hex characters. */
export const HANDLE_PATTERN = /^op_[0-9a-f]{16}$/

/** Seven days, the default operator lifetime (DESIGN §20.4). */
export const DEFAULT_OPERATOR_TTL_MS = 7 * 24 * 60 * 60 * 1000

/** Mint a fresh handle. 64 bits: collision-free at any human scale. */
export function mintHandle() {
  return `op_${randomBytes(8).toString('hex')}`
}

/**
 * Recognise a handle inside free text (a peer may quote it in a sentence).
 * @param {string} text
 * @returns {string|undefined}
 */
export function findHandle(text) {
  if (typeof text !== 'string') return undefined
  const match = text.match(/op_[0-9a-f]{16}/)
  return match === null ? undefined : match[0]
}

/**
 * @typedef {object} OperatorRecord
 * @property {string} handle
 * @property {string} taskId
 * @property {string} sessionId
 * @property {string} level - authority level in force when the task was accepted
 * @property {string|undefined} scope
 * @property {string|undefined} origin - the peer that opened it
 * @property {string|undefined} kid - signing key of that peer, v2 only
 * @property {number} createdAt
 * @property {number} expiresAt
 * @property {string} state - 'active' | 'done'
 * @property {string} cwd
 */

/**
 * Bounded, persistent book of operator records.
 */
export class OperatorBook {
  #file
  #ttlMs
  #now
  #logger
  /** @type {Map<string, OperatorRecord>} */
  #records = new Map()
  #writeChain = Promise.resolve()

  /**
   * @param {{file: string, ttlMs?: number, now?: () => number, logger?: any}} options
   */
  constructor(options) {
    this.#file = options.file
    this.#ttlMs = options.ttlMs ?? DEFAULT_OPERATOR_TTL_MS
    this.#now = options.now ?? (() => Date.now())
    this.#logger = options.logger
  }

  get file() { return this.#file }
  get ttlMs() { return this.#ttlMs }

  /**
   * Load the book from disk. A missing file is an empty book; a corrupt one is
   * refused loudly (silently discarding handles would orphan live sessions).
   * @returns {Promise<void>}
   */
  async init() {
    let raw
    try {
      raw = await readFile(this.#file, 'utf8')
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch {
      throw new Error(`dsh-nuncia: operator book is not valid JSON: ${this.#file}`)
    }
    const records = parsed?.operators
    if (records === null || typeof records !== 'object' || Array.isArray(records)) {
      throw new Error(`dsh-nuncia: operator book has an unexpected shape: ${this.#file}`)
    }
    for (const [handle, record] of Object.entries(records)) {
      if (!HANDLE_PATTERN.test(handle) || typeof record?.taskId !== 'string') {
        this.#logger?.warn?.(`dsh-nuncia: ignoring malformed operator record "${handle}"`)
        continue
      }
      this.#records.set(handle, { ...record, handle })
    }
  }

  /**
   * Record a newly accepted task. Also returns the record it replaced, if a
   * session with the same id was re-accepted (re-contact).
   * @param {{taskId: string, sessionId?: string, level: string, scope?: string, origin?: string, kid?: string, cwd: string, ttlMs?: number}} input
   * @returns {Promise<OperatorRecord>}
   */
  async add(input) {
    const existing = this.byTask(input.taskId)
    const record = {
      handle: existing?.handle ?? mintHandle(),
      taskId: input.taskId,
      sessionId: input.sessionId ?? input.taskId,
      level: input.level,
      ...(input.scope === undefined ? {} : { scope: input.scope }),
      ...(input.origin === undefined ? {} : { origin: input.origin }),
      ...(input.kid === undefined ? {} : { kid: input.kid }),
      createdAt: existing?.createdAt ?? this.#now(),
      expiresAt: input.ttlMs === undefined ? this.#now() + this.#ttlMs : this.#now() + input.ttlMs,
      state: 'active',
      cwd: input.cwd,
    }
    this.#records.set(record.handle, record)
    await this.save()
    return record
  }

  /** @param {string} handle @returns {OperatorRecord|undefined} */
  get(handle) {
    if (typeof handle !== 'string') return undefined
    const record = this.#records.get(handle)
    if (record === undefined) return undefined
    if (this.isExpired(record)) return undefined
    return record
  }

  /** @param {string} taskId @returns {OperatorRecord|undefined} */
  byTask(taskId) {
    for (const record of this.#records.values()) {
      if (record.taskId === taskId && !this.isExpired(record)) return record
    }
    return undefined
  }

  /** @returns {OperatorRecord[]} */
  list() {
    return [...this.#records.values()].filter((record) => !this.isExpired(record))
  }

  /** Records past their expiry, without removing them (dry-run / prune input). */
  expired() {
    return [...this.#records.values()].filter((record) => this.isExpired(record))
  }

  /** @param {OperatorRecord} record */
  isExpired(record) {
    return typeof record.expiresAt === 'number' && record.expiresAt <= this.#now()
  }

  /**
   * Mark a task done (its session stays reachable until expiry).
   * @param {string} taskId
   */
  async markDone(taskId) {
    const record = this.byTask(taskId)
    if (record === undefined || record.state === 'done') return
    record.state = 'done'
    await this.save()
  }

  /**
   * Drop expired records.
   * @returns {Promise<OperatorRecord[]>} the removed records
   */
  async prune() {
    const removed = []
    for (const [handle, record] of this.#records) {
      if (this.isExpired(record)) {
        removed.push(record)
        this.#records.delete(handle)
      }
    }
    if (removed.length > 0) await this.save()
    return removed
  }

  /**
   * Forget one record (used when its session is archived).
   * @param {string} handle
   * @returns {Promise<boolean>}
   */
  async remove(handle) {
    const existed = this.#records.delete(handle)
    if (existed) await this.save()
    return existed
  }

  /** Persist atomically: a half-written book would lose handles. */
  async save() {
    const payload = JSON.stringify({
      version: 1,
      savedAt: new Date(this.#now()).toISOString(),
      operators: Object.fromEntries(this.#records),
    }, null, 2)
    this.#writeChain = this.#writeChain.then(async () => {
      await mkdir(dirname(this.#file), { recursive: true })
      const temporary = `${this.#file}.${process.pid}.tmp`
      await writeFile(temporary, payload, { encoding: 'utf8', mode: 0o600 })
      await rename(temporary, this.#file)
    }).catch((error) => {
      this.#logger?.warn?.(`dsh-nuncia: could not persist operator book — ${error instanceof Error ? error.message : String(error)}`)
    })
    await this.#writeChain
  }
}
