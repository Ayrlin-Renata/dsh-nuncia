/**
 * Grant store for dsh-nuncia — DESIGN.md §20.2.
 *
 * A *grant* is a signed authority envelope plus the bookkeeping needed to
 * manage its lifetime. The store owns three jobs:
 *
 *  1. **Mint** a window (`intent` by default, `override` only when the user
 *     has authenticated directly), bounded by `maxWindowMs`.
 *  2. **Hold** the signed envelope — outbound messages are wrapped plugin-side
 *     while a window is live, so the agent never receives grant bytes (§20.2
 *     "structural non-acquisition").
 *  3. **Revoke / expire / enumerate** — expiry is evaluated at read time, so a
 *     lapsed grant drifts back to `peer` on the next message without any timer
 *     firing (§20.1 rule 2).
 *
 * Persistence is optional and off by default: a standalone node may want
 * grants to survive a restart, while a short-lived harness usually does not.
 * The file is written atomically (tmp + rename) and every record is
 * re-verified against the node's own key material on load, so a tampered file
 * cannot resurrect authority.
 *
 * Signing goes through a *signer* (lib/authority.js `createSigner`), which is
 * what keeps the scheme out of this file: a v2 node signs Ed25519 envelopes it
 * cannot itself verify for anyone else, and a legacy node signs v1 HMAC ones.
 * Either way the store never holds a peer's key.
 *
 * @module dsh-nuncia/grants
 */

import { randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

import { DEFAULT_MAX_WINDOW_MS, hmacSigner } from './authority.js'

/** Default window for an interactive grant (short by design, §20.1 rule 4). */
export const DEFAULT_TTL_MS = 5 * 60 * 1000

const STORE_VERSION = 1

/**
 * @typedef {object} Grant
 * @property {string} id            jti; the handle used by revoke and status
 * @property {string} level         "intent" | "override"
 * @property {string|undefined} scope free-text scope chosen at mint
 * @property {string} origin        this node's name (envelope origin)
 * @property {string} target        peer node name
 * @property {number} iat
 * @property {number} exp
 * @property {number} createdAt     local clock at mint (for diagnostics)
 * @property {object} envelope      the signed wire object (held, never handed to tools)
 */

/**
 * Mint or manage authority windows.
 */
export class GrantStore {
	/** @type {Map<string, Grant>} */
	#grants = new Map()
	#signer
	#origin
	#maxWindowMs
	#defaultTtlMs
	#now
	#persistPath
	#onWarn

	/**
	 * @param {object} options
	 * @param {object} options.signer               authority signer (createSigner / hmacSigner)
	 * @param {Buffer|string} [options.key]         legacy shortcut: an HMAC key (wrapped in hmacSigner)
	 * @param {string} options.origin               this node's name
	 * @param {number} [options.maxWindowMs]
	 * @param {number} [options.defaultTtlMs]
	 * @param {()=>number} [options.now]
	 * @param {string} [options.persistPath]        optional JSON file
	 * @param {(message:string)=>void} [options.onWarn]
	 */
	constructor(options) {
		if (!options || typeof options.origin !== 'string' || options.origin.length === 0) {
			throw new TypeError('GrantStore requires an origin')
		}
		this.#signer = options.signer ?? hmacSigner(options.key)
		this.#origin = options.origin
		this.#maxWindowMs = options.maxWindowMs ?? DEFAULT_MAX_WINDOW_MS
		this.#defaultTtlMs = Math.min(options.defaultTtlMs ?? DEFAULT_TTL_MS, this.#maxWindowMs)
		this.#now = options.now ?? Date.now
		this.#persistPath = options.persistPath
		this.#onWarn = options.onWarn ?? (() => {})
		if (this.#persistPath !== undefined) this.#load()
	}

	/** This node's name (envelope `origin`). */
	get origin() {
		return this.#origin
	}

	/** Maximum window this store will mint. */
	get maxWindowMs() {
		return this.#maxWindowMs
	}

	/** Window used when a mint omits `ttlMs`. */
	get defaultTtlMs() {
		return this.#defaultTtlMs
	}

	/**
	 * Mint a window for `target`.
	 *
	 * `ttlMs` is required to be positive and no longer than `maxWindowMs`: a
	 * caller asking for an hour gets an error, not a silent 10-minute grant,
	 * because the returned expiry is what the user believes they granted.
	 *
	 * @param {{level?:string, ttlMs?:number, scope?:string, target:string}} request
	 * @returns {Grant}
	 */
	mint(request) {
		const level = request.level ?? 'intent'
		if (level !== 'intent' && level !== 'override') {
			throw new Error(`cannot mint level "${level}" (expected intent or override)`)
		}
		if (typeof request.target !== 'string' || request.target.length === 0) {
			throw new Error('mint requires a target node name')
		}

		const ttlMs = request.ttlMs ?? this.#defaultTtlMs
		if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
			throw new Error('ttlMs must be a positive integer')
		}
		if (ttlMs > this.#maxWindowMs) {
			throw new Error(`ttlMs ${ttlMs} exceeds the maximum window ${this.#maxWindowMs}`)
		}

		const now = this.#now()
		const scope = request.scope
		const envelope = this.#signer.createEnvelope({
			level,
			...(scope === undefined ? {} : { scope }),
			origin: this.#origin,
			target: request.target,
			iat: now,
			exp: now + ttlMs,
			jti: randomBytes(18).toString('base64url'),
		})

		const grant = {
			id: envelope.jti,
			level: envelope.level,
			scope: envelope.scope,
			origin: envelope.origin,
			target: envelope.target,
			iat: envelope.iat,
			exp: envelope.exp,
			createdAt: now,
			envelope,
		}
		this.#grants.set(grant.id, grant)
		this.#save()
		return { ...grant }
	}

	/**
	 * End a window immediately.
	 * @param {string} id
	 * @returns {boolean} whether a grant was actually removed
	 */
	revoke(id) {
		const removed = this.#grants.delete(id)
		if (removed) this.#save()
		return removed
	}

	/**
	 * Live grants, optionally filtered by target. Expired entries are dropped.
	 * @param {{target?:string}} [filter]
	 * @returns {Grant[]}
	 */
	active(filter = {}) {
		this.prune()
		const all = [...this.#grants.values()]
		const filtered = filter.target === undefined ? all : all.filter((g) => g.target === filter.target)
		return filtered.map((g) => ({ ...g }))
	}

	/**
	 * The envelope to attach to an outbound message for `target`, if any.
	 *
	 * Preference: higher level first (`override` beats `intent`), then the
	 * later expiry. That is the most permissive live window the user actually
	 * granted — never a synthesis of several.
	 *
	 * @param {string} target
	 * @returns {object|undefined}
	 */
	envelopeFor(target) {
		this.prune()
		let best
		for (const grant of this.#grants.values()) {
			if (grant.target !== target) continue
			if (best === undefined) {
				best = grant
				continue
			}
			const rank = (level) => (level === 'override' ? 1 : 0)
			if (rank(grant.level) > rank(best.level)) best = grant
			else if (rank(grant.level) === rank(best.level) && grant.exp > best.exp) best = grant
		}
		return best === undefined ? undefined : { ...best.envelope }
	}

	/**
	 * Look up a grant by id (live only).
	 * @param {string} id
	 * @returns {Grant|undefined}
	 */
	get(id) {
		this.prune()
		const grant = this.#grants.get(id)
		return grant === undefined ? undefined : { ...grant }
	}

	/**
	 * Drop expired grants. Returns the number removed.
	 * @returns {number}
	 */
	prune() {
		const now = this.#now()
		let removed = 0
		for (const [id, grant] of this.#grants) {
			if (now > grant.exp) {
				this.#grants.delete(id)
				removed += 1
			}
		}
		if (removed > 0) this.#save()
		return removed
	}

	/**
	 * Serializable summaries for the admin status endpoint. Deliberately omits
	 * `sig`: status is for humans, and nothing in an operator response needs to
	 * be a usable grant.
	 * @returns {{origin:string, grants:Array<{id:string, level:string, scope:string|undefined, target:string, issuedAt:number, expiresAt:number, remainingMs:number}>}}
	 */
	list() {
		this.prune()
		const now = this.#now()
		return {
			origin: this.#origin,
			grants: [...this.#grants.values()].map((grant) => ({
				id: grant.id,
				level: grant.level,
				scope: grant.scope,
				target: grant.target,
				issuedAt: grant.iat,
				expiresAt: grant.exp,
				remainingMs: Math.max(0, grant.exp - now),
			})),
		}
	}

	#save() {
		if (this.#persistPath === undefined) return
		try {
			const payload = {
				version: STORE_VERSION,
				origin: this.#origin,
				grants: [...this.#grants.values()].map((grant) => ({
					envelope: grant.envelope,
					createdAt: grant.createdAt,
				})),
			}
			mkdirSync(dirname(this.#persistPath), { recursive: true })
			const temporary = `${this.#persistPath}.tmp`
			writeFileSync(temporary, JSON.stringify(payload, null, 2), { mode: 0o600 })
			renameSync(temporary, this.#persistPath)
		} catch (error) {
			// Persistence is a convenience; losing it must never take down a turn.
			this.#onWarn(`grant persistence failed: ${error instanceof Error ? error.message : String(error)}`)
		}
	}

	#load() {
		let text
		try {
			text = readFileSync(this.#persistPath, 'utf8')
		} catch {
			return // no file yet
		}
		try {
			const payload = JSON.parse(text)
			if (!payload || payload.version !== STORE_VERSION || !Array.isArray(payload.grants)) {
				throw new Error('unexpected file shape')
			}
			const now = this.#now()
			let dropped = 0
			for (const record of payload.grants) {
				const envelope = record?.envelope
				// Re-verify against this node's own key material: a tampered
				// file must not resurrect authority, and a rotated node key
				// must invalidate everything minted under the old one.
				const check = this.#signer.verify(envelope, {
					now,
					maxWindowMs: this.#maxWindowMs,
					expectOrigin: this.#origin,
				})
				if (!check.ok || now > check.exp) {
					dropped += 1
					continue
				}
				this.#grants.set(check.jti, {
					id: check.jti,
					level: check.level,
					scope: check.scope,
					origin: check.origin,
					target: check.target,
					iat: check.iat,
					exp: check.exp,
					createdAt: typeof record.createdAt === 'number' ? record.createdAt : check.iat,
					envelope,
				})
			}
			if (dropped > 0) {
				this.#onWarn(`grant store: dropped ${dropped} unverifiable or expired record(s) on load`)
			}
		} catch (error) {
			this.#onWarn(
				`grant store: ignoring unreadable ${this.#persistPath} (${error instanceof Error ? error.message : String(error)})`,
			)
			this.#grants.clear()
		}
	}
}
