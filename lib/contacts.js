/**
 * Local-contact approvals (§20.20, P4.4).
 *
 * An operator may only message a *local* session on a path the chatelaine
 * approved for that exact (operator handle, session) pair. Without the record
 * an operator could reach any session on this node — including the chatelaine's
 * own, or a human's working session — which is precisely the reach §20.16 took
 * away from it.
 *
 * The book is small, boring, and on disk next to the operator book: the
 * approval must survive a plugin reload, because an approval the operator loses
 * on restart is an approval the human has to grant again by hand.
 *
 * @module dsh-nuncia/contacts
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

/** Default file name inside the nuncia state directory. */
export const CONTACTS_FILE = 'contacts.json'

/** A local note is for the human, not a document. */
export const MAX_CONTACT_NOTE = 200

/** Operator handles are minted by `operators.js`; anything else is a typo. */
export const HANDLE_PATTERN = /^op_[0-9a-f]{16}$/

/**
 * @typedef {object} ContactRecord
 * @property {string} operator  the operator handle the path belongs to
 * @property {string} session   the local session id it may message
 * @property {string} [note]    why the chatelaine approved it
 * @property {number} approvedAt
 * @property {number} [expiresAt]
 */

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Read a stored entry, or throw with the file name — never silently drop one. */
function readContact(raw, file) {
  if (!isRecord(raw) || typeof raw.operator !== 'string' || typeof raw.session !== 'string') {
    throw new Error(`dsh-nuncia: contact book entry is malformed: ${file}`)
  }
  return {
    operator: raw.operator,
    session: raw.session,
    ...(typeof raw.note === 'string' && raw.note !== '' ? { note: raw.note.slice(0, MAX_CONTACT_NOTE) } : {}),
    approvedAt: Number.isFinite(raw.approvedAt) ? raw.approvedAt : Date.now(),
    ...(Number.isFinite(raw.expiresAt) ? { expiresAt: raw.expiresAt } : {}),
  }
}

export class ContactBook {
  /** @param {string} file absolute path of the JSON file */
  constructor(file) {
    this.file = file
    /** @type {ContactRecord[]} */
    this.contacts = []
    this.writeChain = Promise.resolve()
  }

  /** Load from disk. A missing file is an empty book; a malformed one throws. */
  async init() {
    let raw
    try {
      raw = await readFile(this.file, 'utf8')
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch {
      throw new Error(`dsh-nuncia: contact book is not valid JSON: ${this.file}`)
    }
    if (!isRecord(parsed) || !Array.isArray(parsed.contacts)) {
      throw new Error(`dsh-nuncia: contact book is not valid JSON: ${this.file}`)
    }
    this.contacts = parsed.contacts.map((entry) => readContact(entry, this.file))
  }

  /**
   * Approve (or re-approve) a path. Re-approving refreshes the expiry instead of
   * appending a duplicate, so a chatelaine that repeats itself does not grow the
   * book without bound.
   *
   * @param {{operator: string, session: string, note?: string, ttlMs?: number, now?: number}} entry
   * @returns {Promise<ContactRecord>}
   */
  async add(entry) {
    const operator = String(entry?.operator ?? '')
    if (!HANDLE_PATTERN.test(operator)) {
      throw new Error(`dsh-nuncia: an operator handle looks like op_<16 hex>: ${operator === '' ? '(empty)' : operator}`)
    }
    const session = String(entry?.session ?? '').trim()
    if (session === '') throw new Error('dsh-nuncia: a contact approval needs a session id')
    const now = entry?.now ?? Date.now()
    if (entry?.ttlMs !== undefined && (!Number.isFinite(entry.ttlMs) || entry.ttlMs < 60_000)) {
      throw new Error('dsh-nuncia: a contact approval lasts at least one minute')
    }
    const note = typeof entry?.note === 'string' && entry.note.trim() !== ''
      ? entry.note.trim().slice(0, MAX_CONTACT_NOTE)
      : undefined
    /** @type {ContactRecord} */
    const record = {
      operator,
      session,
      ...(note === undefined ? {} : { note }),
      approvedAt: now,
      ...(entry?.ttlMs === undefined ? {} : { expiresAt: now + entry.ttlMs }),
    }
    this.contacts = this.contacts.filter((row) => !(row.operator === operator && row.session === session))
    this.contacts.push(record)
    await this.save()
    return record
  }

  /** Revoke a path. Returns the number of rows removed. */
  async revoke({ operator, session } = {}) {
    const before = this.contacts.length
    this.contacts = this.contacts.filter((row) => {
      if (operator !== undefined && row.operator !== operator) return true
      if (session !== undefined && row.session !== session) return true
      return false
    })
    const removed = before - this.contacts.length
    if (removed > 0) await this.save()
    return removed
  }

  /** Is this exact path approved right now? Expiry is read-time, never sweep-time. */
  has(operator, session, now = Date.now()) {
    return this.contacts.some((row) =>
      row.operator === operator
      && row.session === session
      && (row.expiresAt === undefined || row.expiresAt > now))
  }

  /** @returns {Array<ContactRecord & {active: boolean, remainingMs: number | null}>} */
  list(now = Date.now()) {
    return this.contacts.map((row) => ({
      ...row,
      active: row.expiresAt === undefined || row.expiresAt > now,
      remainingMs: row.expiresAt === undefined ? null : Math.max(0, row.expiresAt - now),
    }))
  }

  /** Drop paths that lapsed more than `keepMs` ago. */
  async prune({ now = Date.now(), keepMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
    const before = this.contacts.length
    this.contacts = this.contacts.filter((row) => row.expiresAt === undefined || row.expiresAt + keepMs > now)
    const removed = before - this.contacts.length
    if (removed > 0) await this.save()
    return removed
  }

  /** Atomic write: a half-written book is a lost approval. */
  save() {
    this.writeChain = this.writeChain.then(async () => {
      await mkdir(dirname(this.file), { recursive: true })
      const temporary = `${this.file}.${process.pid}.${Date.now()}.tmp`
      await writeFile(temporary, `${JSON.stringify({ version: 1, contacts: this.contacts }, null, 2)}\n`, { mode: 0o600 })
      await rename(temporary, this.file)
    })
    return this.writeChain
  }
}
