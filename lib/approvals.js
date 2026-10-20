/**
 * Approval broker for dsh-nuncia — DESIGN.md §20.2 (agent-requested grants).
 *
 * Why this exists at all: `ctx.approval.request(...)` is gated by the session's
 * approval policy, and a `danger-full-access` deployment sets that policy to
 * `never` — the request returns `rejected` without ever reaching a human. An
 * agent that needs user intent in that configuration has no way to ask.
 *
 * So the plugin owns a small, transport-agnostic queue:
 *
 *   - the tool creates a pending request and awaits a promise;
 *   - any surface can list pending requests and decide one — the Sylvia panel
 *     over HTTP, a shell script invoked as an announce hook, or a native
 *     notification that posts the decision back;
 *   - the queue is closed by default: unknown ids are rejected, requests
 *     expire (fail closed), and shutdown cancels everything still waiting.
 *
 * Requests carry what the human needs to decide (peer, level, scope, expiry)
 * and nothing that could be replayed as authority.
 *
 * @module dsh-nuncia/approvals
 */

import { randomUUID } from 'node:crypto'

/** Decisions a pending request can settle to. */
export const APPROVAL_DECISIONS = Object.freeze(['allowed-once', 'rejected', 'cancelled', 'timeout'])

/** Default time a request waits for a human before failing closed. */
export const DEFAULT_APPROVAL_TIMEOUT_MS = 2 * 60 * 1000

/**
 * @typedef {object} PendingApproval
 * @property {string} id
 * @property {string} reason      human-readable ask
 * @property {string} [target]    peer the grant is for
 * @property {string} [level]     intent | override
 * @property {number} [ttlMs]     requested window
 * @property {string} [scope]
 * @property {string} [toolName]
 * @property {number} createdAt
 * @property {number} expiresAt
 */

export class ApprovalBroker {
	/** @type {Map<string, {request: PendingApproval, resolve:(d:string)=>void}>} */
	#pending = new Map()
	#now
	#timeoutMs
	#idFactory
	#onCreate

	/**
	 * @param {object} [options]
	 * @param {()=>number} [options.now]
	 * @param {number} [options.timeoutMs]        how long a request waits
	 * @param {()=>string} [options.idFactory]
	 * @param {(request:PendingApproval)=>void} [options.onCreate]  announce hook
	 */
	constructor(options = {}) {
		this.#now = options.now ?? Date.now
		this.#timeoutMs = options.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS
		this.#idFactory = options.idFactory ?? (() => randomUUID())
		this.#onCreate = options.onCreate
	}

	/**
	 * Create a pending request and wait for a decision.
	 *
	 * Always resolves — to a decision string. A caller that gets anything other
	 * than `allowed-once` must treat it as refusal (fail closed, never silent).
	 *
	 * @param {Omit<PendingApproval, 'id'|'createdAt'|'expiresAt'>} request
	 * @returns {Promise<string>} one of APPROVAL_DECISIONS
	 */
	request(request) {
		const now = this.#now()
		const pending = {
			id: this.#idFactory(),
			createdAt: now,
			expiresAt: now + this.#timeoutMs,
			...request,
		}
		return new Promise((resolve) => {
			let settled = false
			const settle = (decision) => {
				if (settled) return
				settled = true
				this.#pending.delete(pending.id)
				resolve(decision)
			}
			this.#pending.set(pending.id, { request: pending, resolve: settle })
			try {
				this.#onCreate?.(pending)
			} catch {
				// An announce hook that throws must not strand the request;
				// another surface (panel) can still see it and decide.
			}
		})
	}

	/**
	 * Decide a pending request.
	 * @param {string} id
	 * @param {string} decision
	 * @returns {boolean} whether a request with that id was waiting
	 */
	decide(id, decision) {
		if (!APPROVAL_DECISIONS.includes(decision) || decision === 'timeout') return false
		const entry = this.#pending.get(id)
		if (entry === undefined) return false
		entry.resolve(decision)
		return true
	}

	/**
	 * Pending requests, oldest first, with the id a surface needs to decide.
	 * Expired entries are resolved as `timeout` before listing.
	 * @returns {PendingApproval[]}
	 */
	list() {
		this.prune()
		return [...this.#pending.values()].map((entry) => ({ ...entry.request }))
	}

	/**
	 * Expire overdue requests (fail closed).
	 * @returns {number} how many expired
	 */
	prune() {
		const now = this.#now()
		let expired = 0
		for (const [id, entry] of [...this.#pending]) {
			if (now <= entry.request.expiresAt) continue
			this.#pending.delete(id)
			entry.resolve('timeout')
			expired++
		}
		return expired
	}

	/** Close the queue (plugin unload): every waiter is cancelled. */
	cancelAll() {
		for (const [id, entry] of [...this.#pending]) {
			this.#pending.delete(id)
			entry.resolve('cancelled')
		}
	}

	get size() {
		return this.#pending.size
	}
}
