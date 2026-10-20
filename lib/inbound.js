/**
 * Inbound authority gate for dsh-nuncia — DESIGN.md §20.1 rule 5.
 *
 * Everything an A2A request claims about authority passes through here before
 * a turn is created. The gate's contract is small and total:
 *
 *  - No envelope at all  → `peer` (the default; this is the normal case).
 *  - Valid envelope      → `intent` / `override`, and the jti is recorded.
 *  - Anything invalid    → **`peer`** plus a security event. Never an error,
 *                          never a silent upgrade: "fail down, notify loud".
 *
 * The gate holds no DSH imports, so the whole policy is testable in isolation.
 * The caller (lib/index.js) owns logging and the wire-level consequences.
 *
 * @module dsh-nuncia/inbound
 */

import {
	DEFAULT_MAX_WINDOW_MS,
	JtiLedger,
	describeReason,
	envelopeFromMetadata,
	verifyEnvelope,
} from './authority.js'

/**
 * Bounded in-memory security event log.
 *
 * Security events are evidence, not a queue: the panel and the logger read the
 * same ring, and old entries fall off rather than growing without limit. A
 * restart clears them — that is acceptable for v1 because the events are also
 * written to the host log at the moment they occur.
 */
export class SecurityLog {
	#events = []
	#limit
	#now

	/**
	 * @param {{limit?:number, now?:()=>number}} [options]
	 */
	constructor(options = {}) {
		this.#limit = options.limit ?? 50
		this.#now = options.now ?? Date.now
	}

	/**
	 * @param {{kind:string, reason:string, detail?:object}} event
	 * @returns {object} the stored event
	 */
	record(event) {
		const stored = {
			at: this.#now(),
			kind: event.kind,
			reason: event.reason,
			detail: event.detail ?? {},
		}
		this.#events.push(stored)
		if (this.#events.length > this.#limit) this.#events.splice(0, this.#events.length - this.#limit)
		return stored
	}

	/** Newest-first copy. */
	list() {
		return [...this.#events].reverse()
	}

	get size() {
		return this.#events.length
	}
}

/**
 * Create the inbound gate.
 *
 * @param {object} options
 * @param {Buffer|string} options.key               signing key (deriveAuthorityKey)
 * @param {string} options.nodeName                 this node's envelope `target`
 * @param {string[]} [options.peers]                allowed `origin` names; empty = accept any origin that targets us
 * @param {number} [options.maxWindowMs]
 * @param {number} [options.skewMs]
 * @param {JtiLedger} [options.ledger]
 * @param {()=>number} [options.now]
 * @returns {{verify:(metadata:unknown)=>
 *   {ok:true, level:'peer'|'intent'|'override', carried:boolean, scope?:string, origin?:string, exp?:number, jti?:string, replay?:string}
 *   |{ok:false, level:'peer', reason:string, message:string, detail:object}}}
 */
export function createAuthorityGate(options) {
	const {
		key,
		nodeName,
		peers = [],
		maxWindowMs = DEFAULT_MAX_WINDOW_MS,
		skewMs,
		now = Date.now,
	} = options
	const ledger = options.ledger ?? new JtiLedger({ now })

	if (typeof nodeName !== 'string' || nodeName.length === 0) {
		throw new TypeError('authority gate requires a nodeName')
	}

	const allowed = new Set(peers)

	/**
	 * @param {unknown} metadata A2A request metadata
	 */
	function verify(metadata) {
		const raw = envelopeFromMetadata(metadata)
		if (raw === undefined) {
			// The overwhelmingly common case: a plain request from a peer node.
			return { ok: true, level: 'peer', carried: false }
		}

		const detail = {
			// Never echo `sig` back into logs or events: it is a credential-like
			// artifact, and detail objects get rendered in the panel.
			level: typeof raw === 'object' && raw !== null ? raw.level : undefined,
			origin: typeof raw === 'object' && raw !== null ? raw.origin : undefined,
			jti: typeof raw === 'object' && raw !== null ? raw.jti : undefined,
		}

		const result = verifyEnvelope(raw, {
			key,
			now: now(),
			maxWindowMs,
			...(skewMs === undefined ? {} : { skewMs }),
			expectTarget: nodeName,
		})
		if (!result.ok) {
			return {
				ok: false,
				level: 'peer',
				reason: result.reason,
				message: describeReason(result.reason),
				detail,
			}
		}

		// Signature and target are proven at this point; only then is it safe to
		// trust `origin` enough to check it against the allowlist.
		if (allowed.size > 0 && !allowed.has(result.origin)) {
			return {
				ok: false,
				level: 'peer',
				reason: 'origin-mismatch',
				message: describeReason('origin-mismatch'),
				detail,
			}
		}

		const replay = ledger.check(result)
		if (!replay.ok) {
			return {
				ok: false,
				level: 'peer',
				reason: replay.reason,
				message: describeReason(replay.reason),
				detail,
			}
		}

		return {
			ok: true,
			level: /** @type {'intent'|'override'} */ (result.level),
			carried: true,
			scope: result.scope,
			origin: result.origin,
			exp: result.exp,
			jti: result.jti,
			replay: replay.replay,
		}
	}

	return { verify }
}

/**
 * Read the authority level carried by metadata without verifying it.
 *
 * For status/diagnostics only — never for a decision.
 * @param {unknown} metadata
 * @returns {string|undefined}
 */
export function claimedLevel(metadata) {
	const envelope = envelopeFromMetadata(metadata)
	if (envelope === null || typeof envelope !== 'object') return undefined
	const level = /** @type {Record<string, any>} */ (envelope).level
	return typeof level === 'string' ? level : undefined
}
