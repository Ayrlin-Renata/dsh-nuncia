/**
 * Node identity surfaces (DESIGN §20.12, P3.0).
 *
 * Two things live here:
 *
 *  - **The node name.** A fresh install should not need a config step to be
 *    distinct from every other fresh install, so a node without a configured
 *    name picks one at random from a newline-delimited list the human supplies
 *    and persists it beside its other state. Names are cosmetic — collisions
 *    resolve by `kid`, which is already carried in cards, envelopes and the
 *    pairing `--check` flow.
 *
 *  - **The announcement.** A short, human-facing signboard ("what this node is
 *    doing right now") that the chatelaine manages. It is the only free-text
 *    the node publishes, and it is bounded on purpose: this is a signboard,
 *    not a mailbox.
 *
 * @module dsh-nuncia/identity
 */
import { randomInt } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { hostname } from 'node:os'
import { dirname, join } from 'node:path'
import { expandHome } from './house.js'

/** Announcement length ceiling — a signboard, not a message. */
export const MAX_ANNOUNCEMENT_LENGTH = 280

/**
 * Sanitize a candidate node name to the envelope-safe pattern
 * (`/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/`, the same one the authority layer
 * enforces): lowercase, dash for anything else, bounded.
 * @param {unknown} name
 * @returns {string}
 */
export function sanitizeNodeName(name) {
  const cleaned = String(name)
    .toLowerCase()
    .replace(/[^a-z0-9._:-]/g, '-')
    .replace(/^[-._:]+/, '')
  return cleaned.length > 0 ? cleaned.slice(0, 64) : 'nuncia'
}

/**
 * Read a names file: one name per line, blank lines and `#` comments ignored.
 * @param {string} file
 * @returns {Promise<string[]>}
 */
export async function readNamesFile(file) {
  let raw
  try {
    raw = await readFile(file, 'utf8')
  } catch {
    return []
  }
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map(sanitizeNodeName)
    .filter((line) => line !== '' && line !== 'nuncia')
}

/**
 * Choose and persist this node's name.
 *
 * Precedence: an explicitly configured name wins (the operator chose it); then
 * a name adopted in an earlier life (persisted beside the node state); then a
 * random pick from the names file; then the hostname.
 *
 * @param {{nodeName?: string, nodeNameFile?: string, stateFile: string, logger?: any}} options
 * @returns {Promise<{name: string, source: 'config'|'persisted'|'file'|'hostname', candidates?: number}>}
 */
export async function resolveNodeName(options) {
  if (typeof options.nodeName === 'string' && options.nodeName.trim() !== '') {
    return { name: sanitizeNodeName(options.nodeName), source: 'config' }
  }

  // 1. A name adopted before (this file is written once and never changed).
  try {
    const stored = JSON.parse(await readFile(options.stateFile, 'utf8'))
    if (typeof stored?.nodeName === 'string' && stored.nodeName !== '') {
      return { name: sanitizeNodeName(stored.nodeName), source: 'persisted' }
    }
  } catch {
    // No adopted name yet (or an unreadable file): fall through.
  }

  // 2. A random pick from the human's list.
  if (options.nodeNameFile !== undefined) {
    const file = expandHome(options.nodeNameFile)
    const candidates = await readNamesFile(file)
    if (candidates.length > 0) {
      const name = candidates[randomInt(candidates.length)]
      await persistNodeName(options.stateFile, name)
      options.logger?.info?.(`dsh-nuncia: node named "${name}" (picked from ${candidates.length} names in ${file})`)
      return { name, source: 'file', candidates: candidates.length }
    }
    options.logger?.warn(`dsh-nuncia: node name file ${file} has no usable names — falling back to the hostname`)
  }

  // 3. The hostname, sanitized. Not pretty, but unique per machine.
  const name = sanitizeNodeName(hostname())
  await persistNodeName(options.stateFile, name)
  return { name, source: 'hostname' }
}

/**
 * Persist the adopted node name.
 * @param {string} stateFile
 * @param {string} name
 */
export async function persistNodeName(stateFile, name) {
  try {
    await mkdir(dirname(stateFile), { recursive: true })
    const existing = await readFile(stateFile, 'utf8').then((raw) => JSON.parse(raw)).catch(() => ({}))
    await writeFile(stateFile, JSON.stringify({ ...existing, nodeName: name }, null, 2), { encoding: 'utf8', mode: 0o600 })
  } catch {
    // A node that cannot remember its name just re-picks next boot — not fatal.
  }
}

/**
 * Describe the platform this node runs on. The card carries it so a human (or
 * another node's operator) can tell a phone from a desktop without asking.
 * @param {{platform?: string, arch?: string}} [override]
 */
export function describePlatform(override = {}) {
  const platform = override.platform ?? process.platform
  const arch = override.arch ?? process.arch
  return { platform, arch, label: `${platform}-${arch}` }
}

/**
 * The announcement store: one bounded string, written only through the
 * loopback admin endpoint (or the chatelaine's tool).
 */
export class AnnouncementStore {
  #file
  #logger
  #value = ''

  /**
   * @param {{file: string, logger?: any}} options
   */
  constructor(options) {
    this.#file = options.file
    this.#logger = options.logger
  }

  get file() { return this.#file }

  /** Load a persisted announcement (missing file = none). */
  async init() {
    try {
      const parsed = JSON.parse(await readFile(this.#file, 'utf8'))
      this.#value = typeof parsed?.announcement === 'string' ? parsed.announcement : ''
    } catch {
      this.#value = ''
    }
    return this.#value
  }

  /** @returns {string} */
  get() { return this.#value }

  /**
   * Set the announcement. Bounded and single-line: a signboard that grows
   * paragraphs is a mailbox, and mailboxes on a public surface are a hazard.
   * @param {unknown} value
   * @returns {{ok: boolean, value: string, reason?: string}}
   */
  async set(value) {
    if (typeof value !== 'string') return { ok: false, value: this.#value, reason: 'announcement must be a string' }
    const flattened = value.replace(/\s+/g, ' ').trim()
    if (flattened.length > MAX_ANNOUNCEMENT_LENGTH) {
      return { ok: false, value: this.#value, reason: `announcement is longer than ${MAX_ANNOUNCEMENT_LENGTH} characters` }
    }
    this.#value = flattened
    try {
      await mkdir(dirname(this.#file), { recursive: true })
      await writeFile(this.#file, JSON.stringify({ announcement: flattened, updatedAt: new Date().toISOString() }, null, 2), { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      this.#logger?.warn?.(`dsh-nuncia: could not persist the announcement — ${error instanceof Error ? error.message : String(error)}`)
    }
    return { ok: true, value: flattened }
  }
}
