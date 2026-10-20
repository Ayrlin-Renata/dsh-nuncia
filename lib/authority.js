/**
 * Authority envelopes for dsh-nuncia — DESIGN.md §20.1.
 *
 * A bearer token authenticates a *connection*. It says nothing about whether
 * the remote agent is speaking for the user. That claim travels in a signed
 * envelope under `metadata.authority`:
 *
 *   { v: 1, level: "intent" | "override", scope?, origin, target, iat, exp, jti, sig }
 *
 * Normative rules implemented here (each one has a test):
 *
 *  - **Envelope-only authority.** Nothing in message text is authority; the
 *    plugin reads this object and nothing else.
 *  - **Canonical encoding is fixed-order and injection-proof.** Node names are
 *    restricted to a token charset that excludes newlines and `=`; scope is
 *    restricted to printable characters. Without that, a crafted name could
 *    forge field boundaries and sign one payload while declaring another.
 *  - **Freshness.** `iat` may not be in the future beyond a small skew, `now`
 *    may not exceed `exp`, and a single grant may not span more than
 *    `maxWindow` (default 10 min) — a long window is how "temporary" quietly
 *    becomes permanent.
 *  - **Binding.** A grant is bound to `(origin, target, jti)`. The receiver
 *    checks origin and target against what it knows; the jti ledger catches
 *    replay across links.
 *  - **Key separation.** The pairing secret derives *independent* keys for the
 *    bearer token and for envelope signatures (HKDF with distinct info
 *    strings), so a leaked token does not yield signing ability.
 *
 * This module is deliberately dependency-free: `node:crypto` only, no DSH
 * imports, no I/O. Everything here is unit-testable on a plain Node process,
 * which is also why the plugin can stay a no-build plain-ESM package.
 *
 * @module dsh-nuncia/authority
 */

import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto'

/** Wire version of the envelope. Bump only with a migration path. */
export const ENVELOPE_VERSION = 1

/** Levels that may appear *on the wire*. `house` is a policy layer, not a level. */
export const WIRE_LEVELS = Object.freeze(['intent', 'override'])

/** Key under `metadata` that carries the envelope. */
export const AUTHORITY_METADATA_KEY = 'authority'

/** Longest grant any node will honour by default. */
export const DEFAULT_MAX_WINDOW_MS = 10 * 60 * 1000

/** Tolerated clock skew for `iat` in the future. */
export const DEFAULT_SKEW_MS = 60 * 1000

/**
 * Node names (`origin`/`target`): a conservative token charset. Excluding
 * whitespace, `=`, and newlines is what makes the canonical form unambiguous,
 * so this is a security constraint, not cosmetics.
 */
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/

/** Scope text: printable, bounded, no control characters (newlines included). */
const SCOPE_MAX_LENGTH = 256
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/

/** jti: base64url or hex-ish token, bounded. */
const JTI_PATTERN = /^[A-Za-z0-9_-]{8,64}$/

const DERIVE_SALT = Buffer.from('nuncia-pairing-v1', 'utf8')

/**
 * HKDF-SHA256. `info` separates the uses of one pairing secret.
 * @param {string|Buffer} secret
 * @param {string} info
 * @param {number} [length]
 * @returns {Buffer}
 */
function deriveKey(secret, info, length = 32) {
	if (typeof secret !== 'string' && !Buffer.isBuffer(secret)) {
		throw new TypeError('pairing secret must be a string or Buffer')
	}
	const ikm = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8')
	if (ikm.length === 0) throw new TypeError('pairing secret must not be empty')
	return Buffer.from(hkdfSync('sha256', ikm, DERIVE_SALT, Buffer.from(info, 'utf8'), length))
}

/**
 * Envelope signing key derived from the pairing secret.
 * @param {string|Buffer} pairingSecret
 * @returns {Buffer} 32-byte HMAC key
 */
export function deriveAuthorityKey(pairingSecret) {
	return deriveKey(pairingSecret, 'nuncia/authority/hmac')
}

/**
 * Bearer token derived from the same secret, with an independent key.
 * Pairing therefore needs one paste, not two, without coupling the two
 * capabilities cryptographically.
 * @param {string|Buffer} pairingSecret
 * @returns {string} base64url token (43 chars)
 */
export function deriveBearerToken(pairingSecret) {
	return deriveKey(pairingSecret, 'nuncia/bearer').toString('base64url')
}

/**
 * Fixed-order canonical payload. Fields are newline separated and every
 * interpolated value is charset-restricted by `validateEnvelope`, so no value
 * can introduce a line break or an `=` and shift a boundary.
 * @param {{level:string, scope?:string, origin:string, target:string, iat:number, exp:number, jti:string}} envelope
 * @returns {string}
 */
export function canonicalPayload(envelope) {
	return [
		`nuncia-authority-v${ENVELOPE_VERSION}`,
		`level=${envelope.level}`,
		`scope=${envelope.scope ?? ''}`,
		`origin=${envelope.origin}`,
		`target=${envelope.target}`,
		`iat=${envelope.iat}`,
		`exp=${envelope.exp}`,
		`jti=${envelope.jti}`,
	].join('\n')
}

/**
 * HMAC-SHA256 over the canonical payload.
 * @param {object} envelope envelope fields except `sig`
 * @param {Buffer|string} key
 * @returns {string} base64url signature
 */
export function signEnvelope(envelope, key) {
	return createHmac('sha256', key).update(canonicalPayload(envelope)).digest('base64url')
}

/**
 * Structural validation shared by sign and verify. Returns a reason string on
 * failure so callers can fail down *and* say why.
 * @param {unknown} envelope
 * @returns {{ok:true} | {ok:false, reason:string}}
 */
export function validateEnvelope(envelope) {
	if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
		return { ok: false, reason: 'malformed' }
	}
	const e = /** @type {Record<string, any>} */ (envelope)
	if (e.v !== ENVELOPE_VERSION) return { ok: false, reason: 'version' }
	if (!WIRE_LEVELS.includes(e.level)) return { ok: false, reason: 'level' }
	if (typeof e.origin !== 'string' || !NAME_PATTERN.test(e.origin)) return { ok: false, reason: 'malformed' }
	if (typeof e.target !== 'string' || !NAME_PATTERN.test(e.target)) return { ok: false, reason: 'malformed' }
	if (e.scope !== undefined) {
		if (typeof e.scope !== 'string') return { ok: false, reason: 'malformed' }
		if (e.scope.length > SCOPE_MAX_LENGTH) return { ok: false, reason: 'scope-too-long' }
		if (CONTROL_CHARACTERS.test(e.scope)) return { ok: false, reason: 'malformed' }
	}
	if (!Number.isSafeInteger(e.iat) || !Number.isSafeInteger(e.exp)) return { ok: false, reason: 'malformed' }
	if (e.exp <= e.iat) return { ok: false, reason: 'malformed' }
	if (typeof e.jti !== 'string' || !JTI_PATTERN.test(e.jti)) return { ok: false, reason: 'malformed' }
	if (typeof e.sig !== 'string' || e.sig.length === 0) return { ok: false, reason: 'signature' }
	return { ok: true }
}

/**
 * Create a signed envelope.
 * @param {{level:string, scope?:string, origin:string, target:string, iat:number, exp:number, jti:string}} fields
 * @param {Buffer|string} key
 * @returns {object} envelope including `sig`
 */
export function createEnvelope(fields, key) {
	const envelope = { v: ENVELOPE_VERSION, ...fields }
	const structural = validateEnvelope({ ...envelope, sig: 'pending' })
	if (!structural.ok) throw new Error(`invalid authority envelope: ${structural.reason}`)
	envelope.sig = signEnvelope(envelope, key)
	return envelope
}

/**
 * Verify an envelope and apply freshness + binding rules.
 *
 * Check order is deliberate: structure, then signature (integrity of untrusted
 * input), then time, then binding. Each failure is reported as a machine
 * reason so the caller can fail down to `peer` and raise one security event
 * with a precise cause.
 *
 * @param {unknown} envelope
 * @param {object} options
 * @param {Buffer|string} options.key
 * @param {number} [options.now]
 * @param {number} [options.maxWindowMs]
 * @param {number} [options.skewMs]
 * @param {string} [options.expectOrigin] required origin, usually the peer name
 * @param {string} [options.expectTarget] required target, usually this node
 * @returns {{ok:true, level:string, scope:string|undefined, origin:string, target:string, iat:number, exp:number, jti:string} | {ok:false, reason:string}}
 */
export function verifyEnvelope(envelope, options) {
	const {
		key,
		now = Date.now(),
		maxWindowMs = DEFAULT_MAX_WINDOW_MS,
		skewMs = DEFAULT_SKEW_MS,
		expectOrigin,
		expectTarget,
	} = options ?? {}

	const structural = validateEnvelope(envelope)
	if (!structural.ok) return { ok: false, reason: structural.reason }
	const e = /** @type {Record<string, any>} */ (envelope)

	const expected = signEnvelope(e, key)
	const provided = Buffer.from(e.sig, 'utf8')
	const wanted = Buffer.from(expected, 'utf8')
	if (provided.length !== wanted.length || !timingSafeEqual(provided, wanted)) {
		return { ok: false, reason: 'signature' }
	}

	if (e.exp - e.iat > maxWindowMs) return { ok: false, reason: 'window-too-long' }
	if (e.iat > now + skewMs) return { ok: false, reason: 'not-yet-valid' }
	if (now > e.exp) return { ok: false, reason: 'expired' }

	if (expectOrigin !== undefined && e.origin !== expectOrigin) return { ok: false, reason: 'origin-mismatch' }
	if (expectTarget !== undefined && e.target !== expectTarget) return { ok: false, reason: 'target-mismatch' }

	return {
		ok: true,
		level: e.level,
		scope: e.scope,
		origin: e.origin,
		target: e.target,
		iat: e.iat,
		exp: e.exp,
		jti: e.jti,
	}
}

/**
 * Human-readable reason text for security events / logs.
 * @param {string} reason
 * @returns {string}
 */
export function describeReason(reason) {
	switch (reason) {
		case 'malformed': return 'envelope is malformed'
		case 'version': return 'unsupported envelope version'
		case 'level': return 'unknown authority level'
		case 'scope-too-long': return 'scope exceeds the maximum length'
		case 'signature': return 'signature does not verify'
		case 'window-too-long': return 'grant window exceeds the configured maximum'
		case 'not-yet-valid': return 'grant was issued in the future'
		case 'expired': return 'grant has expired'
		case 'origin-mismatch': return 'grant origin does not match the sender'
		case 'target-mismatch': return 'grant target does not match this node'
		case 'jti-reuse': return 'jti was already used on a different link'
		default: return `authority rejected (${reason})`
	}
}

/**
 * Replay ledger for `jti`.
 *
 * Design rule (§20.1): a jti recorded per link; reuse *within* the same link
 * and window is tolerated (a retrying transport is not an attack), while the
 * same jti appearing on a different origin/target pair — or after its window —
 * is a security event.
 *
 * Entries are pruned by expiry, so the ledger stays bounded by the number of
 * live grants, not by traffic.
 */
export class JtiLedger {
	/** @type {Map<string, {origin:string, target:string, exp:number, uses:number, firstSeen:number}>} */
	#entries = new Map()
	#now
	#maxEntries

	/**
	 * @param {{now?:()=>number, maxEntries?:number}} [options]
	 */
	constructor(options = {}) {
		this.#now = options.now ?? Date.now
		this.#maxEntries = options.maxEntries ?? 10_000
	}

	/**
	 * Record a verified envelope's jti.
	 * @param {{jti:string, origin:string, target:string, exp:number}} envelope
	 * @returns {{ok:true, replay:'fresh'|'same-link'} | {ok:false, reason:'jti-reuse'}}
	 */
	check(envelope) {
		const now = this.#now()
		this.prune(now)

		const existing = this.#entries.get(envelope.jti)
		if (existing !== undefined) {
			if (existing.origin === envelope.origin && existing.target === envelope.target && now <= existing.exp) {
				existing.uses += 1
				return { ok: true, replay: 'same-link' }
			}
			return { ok: false, reason: 'jti-reuse' }
		}

		if (this.#entries.size >= this.#maxEntries) this.#evictOldest()
		this.#entries.set(envelope.jti, {
			origin: envelope.origin,
			target: envelope.target,
			exp: envelope.exp,
			uses: 1,
			firstSeen: now,
		})
		return { ok: true, replay: 'fresh' }
	}

	/**
	 * Drop expired entries.
	 * @param {number} [now]
	 */
	prune(now = this.#now()) {
		for (const [jti, entry] of this.#entries) {
			if (now > entry.exp) this.#entries.delete(jti)
		}
	}

	/** @returns {number} number of live entries */
	get size() {
		return this.#entries.size
	}

	#evictOldest() {
		let oldestJti
		let oldest = Infinity
		for (const [jti, entry] of this.#entries) {
			if (entry.firstSeen < oldest) {
				oldest = entry.firstSeen
				oldestJti = jti
			}
		}
		if (oldestJti !== undefined) this.#entries.delete(oldestJti)
	}
}

/**
 * Pull an envelope out of A2A request metadata without trusting it.
 * @param {unknown} metadata
 * @returns {unknown} the raw envelope (verification is the caller's job)
 */
export function envelopeFromMetadata(metadata) {
	if (metadata === null || typeof metadata !== 'object') return undefined
	return /** @type {Record<string, any>} */ (metadata)[AUTHORITY_METADATA_KEY]
}
