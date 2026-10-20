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
 * Identity resolution is the security-relevant part. The envelope's `origin`
 * is a *claim*; the gate looks that claim up in its peer registry and verifies
 * with the public key it finds there. There is deliberately no fallback: an
 * origin with no configured key cannot be verified, so it fails down to
 * `peer`. (In v1 the gate shared an HMAC key with every peer, which made this
 * check nominal — any peer could sign any origin. See lib/authority.js.)
 *
 * The gate holds no DSH imports, so the whole policy is testable in isolation.
 * The caller (lib/index.js) owns logging and the wire-level consequences.
 *
 * @module dsh-nuncia/inbound
 */

import {
	DEFAULT_MAX_WINDOW_MS,
	JtiLedger,
	LEGACY_ENVELOPE_VERSION,
	describeReason,
	envelopeFromMetadata,
	keyIdOf,
	parsePublicKey,
	validateEnvelope,
	verifyEnvelope,
	verifyEnvelopeV2,
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
 * Normalize one peer entry into verifier material.
 *
 * A bare string is a v1-era name-only allowlist entry: it can never verify a
 * v2 envelope (there is no key), which is why migrating means adding the
 * object form, not just renaming.
 *
 * @param {string|{name?:string, publicKey?:string, kid?:string}} entry
 * @returns {{name:string, publicKey:import('node:crypto').KeyObject|undefined, kid:string|undefined}}
 */
function normalizePeer(entry) {
	if (typeof entry === 'string') {
		if (entry.length === 0) throw new TypeError('authority gate: peer name must not be empty')
		return { name: entry, publicKey: undefined, kid: undefined }
	}
	if (entry === null || typeof entry !== 'object') {
		throw new TypeError('authority gate: each peer must be a name or an object with name + publicKey')
	}
	const name = entry.name
	if (typeof name !== 'string' || name.length === 0) {
		throw new TypeError('authority gate: peer entry is missing "name"')
	}
	if (entry.publicKey === undefined) {
		return { name, publicKey: undefined, kid: undefined }
	}
	const publicKey = parsePublicKey(entry.publicKey)
	if (publicKey === undefined) {
		throw new TypeError(`authority gate: peer "${name}" has an unreadable Ed25519 public key`)
	}
	const kid = keyIdOf(publicKey)
	// Pinning the kid in config catches a mistyped/rewritten key at boot rather
	// than at first use, when it would look like the peer misbehaving.
	if (entry.kid !== undefined && entry.kid !== kid) {
		throw new TypeError(`authority gate: peer "${name}" is pinned to kid ${entry.kid} but its key is ${kid}`)
	}
	return { name, publicKey, kid }
}

/**
 * Create the inbound gate.
 *
 * @param {object} options
 * @param {string} options.nodeName                 this node's envelope `target`
 * @param {(string|{name:string, publicKey?:string, kid?:string})[]} [options.peers]
 *        peer registry: names (± their Ed25519 public key)
 * @param {Buffer|string} [options.legacyKey]       HMAC key for pre-v2 envelopes
 * @param {boolean} [options.allowV1]               accept legacy envelopes at all
 * @param {number} [options.maxWindowMs]
 * @param {number} [options.skewMs]
 * @param {JtiLedger} [options.ledger]
 * @param {()=>number} [options.now]
 * @returns {{verify:(metadata:unknown)=>
 *   {ok:true, level:'peer'|'intent'|'override', carried:boolean, scope?:string, origin?:string, exp?:number, jti?:string, kid?:string, replay?:string, version?:number}
 *   |{ok:false, level:'peer', reason:string, message:string, detail:object}},
 *   describe:()=>object}
 */
export function createAuthorityGate(options) {
	const {
		nodeName,
		peers = [],
		legacyKey,
		allowV1 = true,
		maxWindowMs = DEFAULT_MAX_WINDOW_MS,
		skewMs,
		now = Date.now,
	} = options
	const ledger = options.ledger ?? new JtiLedger({ now })

	if (typeof nodeName !== 'string' || nodeName.length === 0) {
		throw new TypeError('authority gate requires a nodeName')
	}

	/** @type {Map<string, {name:string, publicKey:any, kid:string|undefined}>} */
	const registry = new Map()
	for (const entry of peers) {
		const peer = normalizePeer(entry)
		if (registry.has(peer.name)) throw new TypeError(`authority gate: duplicate peer "${peer.name}"`)
		registry.set(peer.name, peer)
	}

	// Evaluated per verification, never once at construction: a gate that
	// freezes its clock at boot rejects every grant minted more than the skew
	// window later ("not-yet-valid"), which is exactly what a long-running
	// harness would see.
	const timing = () => ({
		now: now(),
		maxWindowMs,
		...(skewMs === undefined ? {} : { skewMs }),
	})

	/**
	 * @param {string} reason
	 * @param {object} detail
	 */
	function fail(reason, detail) {
		return { ok: false, level: /** @type {'peer'} */ ('peer'), reason, message: describeReason(reason), detail }
	}

	/**
	 * @param {object} result verified envelope claims
	 * @param {number} version
	 * @param {object} detail
	 */
	function accept(result, version, detail) {
		// A node cannot speak for itself. An envelope naming *us* as origin is
		// either a grant of ours bounced back (no transitivity) or an attempt at
		// self-authority; neither is user intent, so both fail down.
		if (result.origin === nodeName) return fail('origin-mismatch', detail)
		const replay = ledger.check(result)
		if (!replay.ok) return fail(replay.reason, detail)
		return {
			ok: true,
			level: /** @type {'intent'|'override'} */ (result.level),
			carried: true,
			scope: result.scope,
			origin: result.origin,
			exp: result.exp,
			jti: result.jti,
			...(result.kid === undefined ? {} : { kid: result.kid }),
			version,
			replay: replay.replay,
		}
	}

	/**
	 * @param {unknown} metadata A2A request metadata
	 */
	function verify(metadata) {
		const raw = envelopeFromMetadata(metadata)
		if (raw === undefined) {
			// The overwhelmingly common case: a plain request from a peer node.
			return { ok: true, level: /** @type {'peer'} */ ('peer'), carried: false }
		}

		const record = /** @type {Record<string, any>} */ (raw)
		const detail = {
			// Never echo `sig` back into logs or events: it is a credential-like
			// artifact, and detail objects get rendered in the panel.
			version: typeof record === 'object' && record !== null ? record.v : undefined,
			level: typeof record === 'object' && record !== null ? record.level : undefined,
			origin: typeof record === 'object' && record !== null ? record.origin : undefined,
			kid: typeof record === 'object' && record !== null ? record.kid : undefined,
			jti: typeof record === 'object' && record !== null ? record.jti : undefined,
		}

		// Structure first, so a garbage envelope is reported as malformed rather
		// than as an unknown origin.
		const structural = validateEnvelope(raw)
		if (!structural.ok) return fail(structural.reason, detail)

		if (record.v === LEGACY_ENVELOPE_VERSION) {
			if (!allowV1) return fail('legacy-disabled', detail)
			if (legacyKey === undefined) return fail('legacy-disabled', detail)
			const result = verifyEnvelope(raw, {
				key: legacyKey,
				...timing(),
				expectTarget: nodeName,
			})
			if (!result.ok) return fail(result.reason, detail)
			// Signature and target are proven at this point; only then is it safe
			// to trust `origin` enough to check the allowlist.
			if (registry.size > 0 && !registry.has(result.origin)) return fail('origin-mismatch', detail)
			return accept(result, LEGACY_ENVELOPE_VERSION, detail)
		}

		// v2: the claimed origin selects the key. No key ⇒ nothing to verify.
		const origin = detail.origin
		if (origin === nodeName) return fail('origin-mismatch', detail)
		const peer = typeof origin === 'string' ? registry.get(origin) : undefined
		if (peer === undefined) return fail('unknown-origin', detail)
		if (peer.publicKey === undefined) return fail('unknown-origin', detail)

		const result = verifyEnvelopeV2(raw, {
			publicKey: peer.publicKey,
			...(peer.kid === undefined ? {} : { expectKid: peer.kid }),
			expectOrigin: peer.name,
			expectTarget: nodeName,
			...timing(),
		})
		if (!result.ok) return fail(result.reason, detail)
		return accept(result, 2, detail)
	}

	/** Operator-facing summary for /status. */
	function describe() {
		return {
			nodeName,
			allowV1,
			legacyKeyConfigured: legacyKey !== undefined,
			peers: [...registry.values()].map((peer) => ({
				name: peer.name,
				kid: peer.kid ?? null,
				canVerifyV2: peer.publicKey !== undefined,
			})),
			ledgerSize: ledger.size,
		}
	}

	return { verify, describe }
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
