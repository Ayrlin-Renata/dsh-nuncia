/**
 * Authority envelopes for dsh-nuncia — DESIGN.md §20.1.
 *
 * A bearer token authenticates a *connection*. It says nothing about whether
 * the remote agent is speaking for the user. That claim travels in a signed
 * envelope under `metadata.authority`:
 *
 *   v2 (current): { v: 2, level: "intent"|"override", scope?, origin, target,
 *                   kid, iat, exp, jti, sig }
 *   v1 (legacy):  { v: 1, level, scope?, origin, target, iat, exp, jti, sig }
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
 *  - **Asymmetric authority (v2).** Each node holds an Ed25519 key pair and
 *    signs with its *private* key; a receiver verifies with the sender's
 *    *public* key. This is the property the earlier shared-HMAC design could
 *    not express: HMAC has no verify-only mode, so every node able to check
 *    intent was equally able to mint it — and, because `origin` is only a
 *    string the signature covers, to mint it under *any* name. Now `origin` is
 *    bound to `kid` (a hash of the public key), and a verifying node holds no
 *    signing capability at all.
 *  - **Legacy v1.** HMAC envelopes derived from a pairing secret remain
 *    verifiable while a `legacyKey` is configured, and only when the caller
 *    opts in (`allowV1`). Nothing new is minted as v1 unless the node has no
 *    key pair.
 *  - **Key separation.** The pairing secret still derives the bearer token
 *    (HKDF, its own info string). It is no longer an authority root.
 *
 * This module is deliberately dependency-free: `node:crypto` only, no DSH
 * imports, no I/O. Everything here is unit-testable on a plain Node process,
 * which is also why the plugin can stay a no-build plain-ESM package.
 *
 * @module dsh-nuncia/authority
 */

import { createHash, createHmac, createPublicKey, hkdfSync, sign, timingSafeEqual, verify } from 'node:crypto'

/** Wire version this module mints. */
export const ENVELOPE_VERSION = 2

/** Pre-v2 HMAC envelope, verifiable only through an explicit legacy key. */
export const LEGACY_ENVELOPE_VERSION = 1

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

/** Key id: truncated digest of the public key. Not secret, so exact shape only. */
const KID_PATTERN = /^[A-Za-z0-9_-]{8,32}$/

/** Ed25519 signatures are 64 bytes ⇒ 86 base64url characters. */
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/

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
 * Bearer token derived from the pairing secret, with an independent key.
 *
 * With a node name the derivation is per node (`nuncia/bearer:<name>`), so two
 * nodes sharing one secret no longer share one literal token: a token leak
 * identifies and revokes a single endpoint, and rotation can happen per name.
 * Peers compute a target's token the same way (they hold the secret), so the
 * "one paste" property is unchanged. Omitting the name keeps the historical
 * derivation for existing configs.
 *
 * @param {string|Buffer} pairingSecret
 * @param {string} [nodeName]
 * @returns {string} base64url token (43 chars)
 */
export function deriveBearerToken(pairingSecret, nodeName) {
	const info = nodeName === undefined || nodeName === '' ? 'nuncia/bearer' : `nuncia/bearer:${nodeName}`
	return deriveKey(pairingSecret, info).toString('base64url')
}

/**
 * Fixed-order canonical payload for the LEGACY (v1) HMAC envelope. Fields are
 * newline separated and every interpolated value is charset-restricted by
 * `validateEnvelope`, so no value can introduce a line break or an `=` and
 * shift a boundary.
 * @param {{level:string, scope?:string, origin:string, target:string, iat:number, exp:number, jti:string}} envelope
 * @returns {string}
 */
export function canonicalPayload(envelope) {
	return [
		`nuncia-authority-v${LEGACY_ENVELOPE_VERSION}`,
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
 * Fixed-order canonical payload for v2. `kid` is covered by the signature so a
 * peer cannot claim someone else's identity with its own key: the verifier
 * looks the key up by `origin`, checks `kid` against that key, and only then
 * verifies — a mismatch never reaches the expensive path.
 * @param {{level:string, scope?:string, origin:string, target:string, kid:string, iat:number, exp:number, jti:string}} envelope
 * @returns {string}
 */
export function canonicalPayloadV2(envelope) {
	return [
		`nuncia-authority-v${ENVELOPE_VERSION}`,
		`level=${envelope.level}`,
		`scope=${envelope.scope ?? ''}`,
		`origin=${envelope.origin}`,
		`target=${envelope.target}`,
		`kid=${envelope.kid}`,
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
 * Structural rules shared by both wire versions.
 * @param {Record<string, any>} e
 * @returns {string|undefined} reason on failure
 */
function validateCommonFields(e) {
	if (!WIRE_LEVELS.includes(e.level)) return 'level'
	if (typeof e.origin !== 'string' || !NAME_PATTERN.test(e.origin)) return 'malformed'
	if (typeof e.target !== 'string' || !NAME_PATTERN.test(e.target)) return 'malformed'
	if (e.scope !== undefined) {
		if (typeof e.scope !== 'string') return 'malformed'
		if (e.scope.length > SCOPE_MAX_LENGTH) return 'scope-too-long'
		if (CONTROL_CHARACTERS.test(e.scope)) return 'malformed'
	}
	if (!Number.isSafeInteger(e.iat) || !Number.isSafeInteger(e.exp)) return 'malformed'
	if (e.exp <= e.iat) return 'malformed'
	if (typeof e.jti !== 'string' || !JTI_PATTERN.test(e.jti)) return 'malformed'
	return undefined
}

/**
 * Structural validation shared by sign and verify. Returns a reason string on
 * failure so callers can fail down *and* say why. Accepts both wire versions;
 * the version-specific verifier rejects the other one explicitly.
 * @param {unknown} envelope
 * @returns {{ok:true} | {ok:false, reason:string}}
 */
export function validateEnvelope(envelope) {
	if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
		return { ok: false, reason: 'malformed' }
	}
	const e = /** @type {Record<string, any>} */ (envelope)
	if (e.v !== LEGACY_ENVELOPE_VERSION && e.v !== ENVELOPE_VERSION) return { ok: false, reason: 'version' }

	const reason = validateCommonFields(e)
	if (reason !== undefined) return { ok: false, reason }

	if (e.v === ENVELOPE_VERSION) {
		if (typeof e.kid !== 'string' || !KID_PATTERN.test(e.kid)) return { ok: false, reason: 'malformed' }
		if (typeof e.sig !== 'string' || !SIGNATURE_PATTERN.test(e.sig)) return { ok: false, reason: 'signature' }
		return { ok: true }
	}

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
	const envelope = { v: LEGACY_ENVELOPE_VERSION, ...fields }
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
	// This verifier is the legacy HMAC path only; v2 must go through
	// verifyEnvelopeV2 so a node cannot be tricked into treating an Ed25519
	// envelope as an HMAC one (or vice versa) across a shared secret.
	if (e.v !== LEGACY_ENVELOPE_VERSION) return { ok: false, reason: 'version' }

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

// ---------------------------------------------------------------------------
// v2 — per-node Ed25519 identities
// ---------------------------------------------------------------------------

/**
 * Import a public key from either PEM text or a single-line base64url SPKI
 * blob (the form `bin/nuncia-identity.js` prints for pasting into a peer's
 * config). A private KeyObject is accepted and reduced to its public half —
 * that is how a freshly generated key pair derives its own `kid`. Returns
 * `undefined` for anything unparseable: callers treat that as "this peer
 * cannot be verified", never as a reason to fall back.
 * @param {unknown} value
 * @returns {import('node:crypto').KeyObject|undefined}
 */
export function parsePublicKey(value) {
	if (value === null || value === undefined) return undefined
	if (typeof value === 'object' && typeof (/** @type {any} */ (value).asymmetricKeyType) === 'string') {
		const key = /** @type {import('node:crypto').KeyObject} */ (value)
		if (key.asymmetricKeyType !== 'ed25519') return undefined
		if (key.type === 'public') return key
		if (key.type !== 'private') return undefined
		try {
			const derived = createPublicKey(key)
			return derived.asymmetricKeyType === 'ed25519' ? derived : undefined
		} catch {
			return undefined
		}
	}
	if (typeof value !== 'string') return undefined
	const text = value.trim()
	if (text.length === 0) return undefined
	try {
		if (text.includes('-----BEGIN')) {
			const key = createPublicKey(text)
			return key.asymmetricKeyType === 'ed25519' ? key : undefined
		}
		const key = createPublicKey({ key: Buffer.from(text, 'base64url'), format: 'der', type: 'spki' })
		return key.asymmetricKeyType === 'ed25519' ? key : undefined
	} catch {
		return undefined
	}
}

/**
 * Serialize a public key as one line of base64url SPKI (DER).
 * @param {import('node:crypto').KeyObject|string} publicKey
 * @returns {string}
 */
export function exportPublicKey(publicKey) {
	const key = parsePublicKey(publicKey)
	if (key === undefined) throw new TypeError('not an Ed25519 public key')
	return Buffer.from(key.export({ type: 'spki', format: 'der' })).toString('base64url')
}

/**
 * Short key id: 16 base64url chars of SHA-256 over the SPKI DER. Carried in
 * the envelope so a verifier can reject a wrong-key claim before doing any
 * signature work, and so operators can match a config entry to a key.
 * @param {import('node:crypto').KeyObject|string} publicKey
 * @returns {string}
 */
export function keyIdOf(publicKey) {
	const key = parsePublicKey(publicKey)
	if (key === undefined) throw new TypeError('not an Ed25519 public key')
	const der = Buffer.from(key.export({ type: 'spki', format: 'der' }))
	return createHash('sha256').update(der).digest('base64url').slice(0, 16)
}

/**
 * Human fingerprint for out-of-band comparison: `SHA256:` plus the grouped
 * digest. The whole point of showing it is to compare it *out of band*, so it
 * must be stable and easy to read aloud.
 * @param {import('node:crypto').KeyObject|string} publicKey
 * @returns {string}
 */
export function fingerprintOf(publicKey) {
	const key = parsePublicKey(publicKey)
	if (key === undefined) throw new TypeError('not an Ed25519 public key')
	const der = Buffer.from(key.export({ type: 'spki', format: 'der' }))
	const digest = createHash('sha256').update(der).digest('base64url')
	return `SHA256:${digest.match(/.{1,4}/g)?.join(' ') ?? digest}`
}

/**
 * Ed25519 signature over the v2 canonical payload.
 * @param {object} envelope v2 fields except `sig`
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {string} base64url signature (86 chars)
 */
export function signEnvelopeV2(envelope, privateKey) {
	return sign(null, Buffer.from(canonicalPayloadV2(envelope), 'utf8'), privateKey).toString('base64url')
}

/**
 * Ed25519 verification. Shape errors and junk keys return `false` rather than
 * throwing: an unverifiable envelope is a failed check, not a crash.
 * @param {object} envelope
 * @param {import('node:crypto').KeyObject|string} publicKey
 * @returns {boolean}
 */
export function verifySignatureV2(envelope, publicKey) {
	const key = parsePublicKey(publicKey)
	if (key === undefined) return false
	if (typeof envelope?.sig !== 'string' || !SIGNATURE_PATTERN.test(envelope.sig)) return false
	try {
		return verify(null, Buffer.from(canonicalPayloadV2(envelope), 'utf8'), key, Buffer.from(envelope.sig, 'base64url'))
	} catch {
		return false
	}
}

/**
 * Mint a v2 envelope signed by this node's private key.
 * @param {{level:string, scope?:string, origin:string, target:string, iat:number, exp:number, jti:string}} fields
 * @param {{privateKey:import('node:crypto').KeyObject, kid?:string}} key
 * @returns {object} envelope including `v`, `kid`, `sig`
 */
export function createEnvelopeV2(fields, key) {
	if (!key || key.privateKey === undefined) throw new TypeError('createEnvelopeV2 requires a privateKey')
	const kid = key.kid ?? keyIdOf(key.privateKey)
	const envelope = { v: ENVELOPE_VERSION, ...fields, kid }
	// Validate the body with a well-formed placeholder signature: the shape of
	// `sig` is checked on the wire, not while minting.
	const structural = validateEnvelope({ ...envelope, sig: 'A'.repeat(86) })
	if (!structural.ok) throw new Error(`invalid authority envelope: ${structural.reason}`)
	envelope.sig = signEnvelopeV2(envelope, key.privateKey)
	return envelope
}

/**
 * Verify a v2 envelope against a *public* key, then apply freshness + binding.
 *
 * Check order is deliberate: structure, then `kid` (cheap identity check),
 * then signature, then time, then binding. Each failure is a machine reason so
 * the gate can fail down to `peer` and raise one precise security event.
 *
 * @param {unknown} envelope
 * @param {object} options
 * @param {import('node:crypto').KeyObject|string} options.publicKey  the claimed origin's key
 * @param {string} [options.expectKid]       pin to a configured key id
 * @param {number} [options.now]
 * @param {number} [options.maxWindowMs]
 * @param {number} [options.skewMs]
 * @param {string} [options.expectOrigin]
 * @param {string} [options.expectTarget]
 * @returns {{ok:true, level:string, scope:string|undefined, origin:string, target:string, kid:string, iat:number, exp:number, jti:string} | {ok:false, reason:string}}
 */
export function verifyEnvelopeV2(envelope, options) {
	const {
		publicKey,
		expectKid,
		now = Date.now(),
		maxWindowMs = DEFAULT_MAX_WINDOW_MS,
		skewMs = DEFAULT_SKEW_MS,
		expectOrigin,
		expectTarget,
	} = options ?? {}

	const structural = validateEnvelope(envelope)
	if (!structural.ok) return { ok: false, reason: structural.reason }
	const e = /** @type {Record<string, any>} */ (envelope)
	if (e.v !== ENVELOPE_VERSION) return { ok: false, reason: 'version' }

	if (expectKid !== undefined && e.kid !== expectKid) return { ok: false, reason: 'kid-mismatch' }
	// The key is looked up by the *claimed* origin, so a mismatched kid means
	// the sender is not who it says it is — reject before verifying.
	if (keyIdOf(publicKey) !== e.kid) return { ok: false, reason: 'kid-mismatch' }
	if (!verifySignatureV2(e, publicKey)) return { ok: false, reason: 'signature' }

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
		kid: e.kid,
		iat: e.iat,
		exp: e.exp,
		jti: e.jti,
	}
}

/**
 * Signer facade used by the grant store, so it never learns which scheme is in
 * play. A v2 signer needs a private key; `hmacSigner` keeps a secret-only node
 * working during migration (its envelopes are v1 and say so on the wire).
 * @param {object} options
 * @param {import('node:crypto').KeyObject} options.privateKey
 * @param {import('node:crypto').KeyObject|string} [options.publicKey]
 * @param {string} [options.kid]
 * @returns {{version:number, kid:string, createEnvelope:(fields:object)=>object, verify:(envelope:unknown, options?:object)=>object, identity:()=>object}}
 */
export function createSigner(options) {
	const { privateKey } = options ?? {}
	if (!privateKey || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
		throw new TypeError('createSigner requires an Ed25519 private key')
	}
	const publicKey = options.publicKey ?? createPublicKey(privateKey)
	const kid = options.kid ?? keyIdOf(publicKey)
	return {
		version: ENVELOPE_VERSION,
		kid,
		createEnvelope: (fields) => createEnvelopeV2(fields, { privateKey, kid }),
		verify: (envelope, verifyOptions = {}) => verifyEnvelopeV2(envelope, { publicKey, ...verifyOptions }),
		identity: () => ({ version: ENVELOPE_VERSION, kid, publicKey: exportPublicKey(publicKey), fingerprint: fingerprintOf(publicKey) }),
	}
}

/**
 * Legacy HMAC signer for a node that has no key pair yet.
 * @param {Buffer|string} key deriveAuthorityKey(pairingSecret)
 * @returns {{version:number, kid:undefined, createEnvelope:(fields:object)=>object, verify:(envelope:unknown, options?:object)=>object}}
 */
export function hmacSigner(key) {
	if (key === undefined || key === null) throw new TypeError('hmacSigner requires a key')
	return {
		version: LEGACY_ENVELOPE_VERSION,
		kid: undefined,
		createEnvelope: (fields) => createEnvelope(fields, key),
		verify: (envelope, verifyOptions = {}) => verifyEnvelope(envelope, { key, ...verifyOptions }),
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
		case 'kid-mismatch': return 'envelope key id does not match the peer key'
		case 'unknown-origin': return 'envelope origin has no configured peer key'
		case 'legacy-disabled': return 'legacy v1 envelopes are not accepted on this node'
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
