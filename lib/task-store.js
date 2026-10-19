/**
 * File-backed A2A Task store — durable, single-writer implementation of the
 * SDK TaskStore contract on top of one JSON file (write-chained, cloned).
 *
 * @module dsh-nuncia/task-store
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

/**
 * Any task that is not terminal gets a synthetic status bump; every stored
 * task is a structural clone, so in-memory mutation cannot alias the file.
 */
export class FileTaskStore {
  /** @type {Map<string, any>} */
  #tasks = new Map()
  #writeChain = Promise.resolve()

  /** @param {string} file */
  constructor(file) {
    this.#file = file
  }

  /** @type {string} */
  #file

  /** Load persisted tasks. ENOENT starts empty. */
  async init() {
    let raw
    try {
      raw = await readFile(this.#file, 'utf-8')
    } catch (e) {
      if (e && e.code === 'ENOENT') return
      throw e
    }
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) throw new Error('Malformed task file.')
    for (const record of parsed) this.#tasks.set(record.id, record)
  }

  async save(task, _context) {
    this.#tasks.set(task.id, structuredClone(task))
    await this.#persist()
  }

  async load(taskId, _context) {
    return this.#tasks.get(taskId)
  }

  async list(params, _context) {
    const {
      contextId = '',
      status: status,
      pageToken = '',
      pageSize = 50,
    } = params

    const tasks = []
    for (const task of this.#tasks.values()) {
      if (contextId !== '' && task.contextId !== contextId) continue
      if (typeof status === 'number' && task.status.state !== status) continue
      tasks.push(task)
    }

    let startIndex = 0
    if (pageToken !== '') {
      startIndex = parseInt(pageToken, 10)
      if (isNaN(startIndex)) {
        throw new Error('Invalid page token.')
      }
    }

    const endIndex = Math.min(startIndex + pageSize, tasks.length)
    const hasMore = endIndex < tasks.length

    return {
      tasks: tasks.slice(startIndex, endIndex),
      nextPageToken: hasMore ? endIndex.toString() : '',
      pageSize,
      totalSize: tasks.length,
    }
  }

  async #persist() {
    await this.#writeChain.then(async () => {
      await mkdir(dirname(this.#file), { recursive: true })
      await writeFile(this.#file, JSON.stringify(Array.from(this.#tasks.values()), null, 2))
    })
  }
}
