/**
 * Tests for lib/authority.js — the envelope core of DESIGN §20.
 *
 * Run: node --test test-authority.test.mjs
 *
 * These run on a bare Node process: no DSH packages, no harness, no device.
 * That is the point of keeping the core dependency-free — the trust-critical
 * code is verifiable in isolation.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
	AUTHORITY_METADATA_KEY,
	DEFAULT_MAX_WINDOW_MS,
	ENVELOPE_VERSION,
	JtiLedger,
	WIRE_LEVELS,
	canonicalPayload,
	createEnvelope,
	deriveAuthorityKey,
	deriveBearerToken,
	describeReason,
	envelopeFromMetadata,
	signEnvelope,
	validateEnvelope,
	verifyEnvelope,
} from '../lib/authority.js'

const SECRET = 'test-pairing-secret-0123456789'
const KEY = deriveAuthorityKey(SECRET)
const NOW = 1_800_000_000_000

/** A valid grant body, fixed in time so assertions are deterministic. */
function fields(overrides = {}) {
	return {
		level: 'intent',
		scope: 'housekeeping',
		origin: 'desk',
		target: 'phone',
		iat: NOW,
		exp: NOW + 5 * 60 * 1000,
		jti: 'jti-abcdefgh12345',
		...overrides,
	}
}

function validEnvelope(overrides = {}) {
	return createEnvelope(fields(overrides), KEY)
}

function verify(envelope, options = {}) {
	return verifyEnvelope(envelope, { key: KEY, now: NOW + 1000, ...options })
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

test('derivation is deterministic and separates bearer from signing keys', () => {
	const a = deriveAuthorityKey(SECRET)
	const b = deriveAuthorityKey(SECRET)
	assert.equal(a.length, 32)
	assert.deepEqual(a, b, 'same secret must derive the same signing key')

	const token = deriveBearerToken(SECRET)
	assert.equal(token.length, 43, '32 bytes base64url is 43 chars')
	assert.match(token, /^[A-Za-z0-9_-]+$/)

	// Domain separation: the bearer token must not be a usable signing key.
	assert.notEqual(token, a.toString('base64url'))
	assert.ok(!a.toString('base64url').startsWith(token.slice(0, 20)))
})

test('different secrets derive different keys', () => {
	assert.notDeepEqual(deriveAuthorityKey('secret-one'), deriveAuthorityKey('secret-two'))
})

test('empty or non-string secrets are rejected', () => {
	assert.throws(() => deriveAuthorityKey(''), /must not be empty/)
	assert.throws(() => deriveAuthorityKey(null), /string or Buffer/)
})

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

test('canonical form is fixed-order and field separated', () => {
	const payload = canonicalPayload(fields())
	assert.equal(
		payload,
		[
			'nuncia-authority-v1',
			'level=intent',
			'scope=housekeeping',
			'origin=desk',
			'target=phone',
			`iat=${NOW}`,
			`exp=${NOW + 300_000}`,
			'jti=jti-abcdefgh12345',
		].join('\n'),
	)
})

test('omitted and empty scope canonicalize identically (documented behaviour)', () => {
	const omitted = canonicalPayload(fields({ scope: undefined }))
	const empty = canonicalPayload(fields({ scope: '' }))
	assert.equal(omitted, empty)
	assert.match(omitted, /\nscope=\n/)
})

test('field values cannot be shifted between fields', () => {
	// Swapping origin and target must change the payload.
	const ab = canonicalPayload(fields({ origin: 'a', target: 'b' }))
	const ba = canonicalPayload(fields({ origin: 'b', target: 'a' }))
	assert.notEqual(ab, ba)

	// A value that looks like another field is still just a value.
	const tricky = canonicalPayload(fields({ scope: 'x\nlevel=override' }))
	assert.notEqual(tricky, canonicalPayload(fields({ scope: 'x' })))
})

// ---------------------------------------------------------------------------
// Sign / verify round trip
// ---------------------------------------------------------------------------

test('a signed envelope verifies and returns its claims', () => {
	const envelope = validEnvelope()
	const result = verify(envelope)
	assert.equal(result.ok, true)
	assert.equal(result.level, 'intent')
	assert.equal(result.scope, 'housekeeping')
	assert.equal(result.origin, 'desk')
	assert.equal(result.target, 'phone')
	assert.equal(result.jti, 'jti-abcdefgh12345')
	assert.equal(result.iat, NOW)
	assert.equal(result.exp, NOW + 300_000)
})

test('both wire levels are accepted; house is not a wire level', () => {
	assert.equal(verify(validEnvelope({ level: 'intent' })).ok, true)
	assert.equal(verify(validEnvelope({ level: 'override' })).ok, true)
	assert.deepEqual(WIRE_LEVELS, ['intent', 'override'])
	assert.equal(validateEnvelope({ ...validEnvelope(), level: 'house' }).ok, false)
})

// ---------------------------------------------------------------------------
// Integrity: every field is under the signature
// ---------------------------------------------------------------------------

test('tampering with any signed field invalidates the signature', () => {
	const base = validEnvelope()
	for (const [field, value] of [
		['level', 'override'],
		['scope', 'something-else'],
		['origin', 'other-desk'],
		['target', 'other-phone'],
		['iat', NOW + 1],
		['exp', NOW + 400_000],
		['jti', 'jti-different9999'],
	]) {
		const tampered = { ...base, [field]: value }
		const result = verify(tampered)
		assert.equal(result.ok, false, `${field} tamper must be rejected`)
		assert.equal(result.reason, 'signature', `${field} tamper must surface as a signature failure`)
	}
})

test('signing with a different key fails verification', () => {
	const foreign = createEnvelope(fields(), deriveAuthorityKey('attacker-secret'))
	assert.equal(verify(foreign).reason, 'signature')
})

test('a re-signed but malformed level is still rejected structurally', () => {
	const envelope = createEnvelope(fields(), KEY)
	const forged = { ...envelope, level: 'house' }
	// Re-sign so the attacker's only remaining wall is the level validation.
	forged.sig = signEnvelope(forged, KEY)
	assert.equal(verify(forged).reason, 'level')
})

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

test('expired grants are rejected', () => {
	const expired = createEnvelope(fields({ iat: NOW - 600_000, exp: NOW - 1 }), KEY)
	assert.equal(verify(expired).reason, 'expired')
})

test('grants issued in the future beyond the skew are rejected', () => {
	const future = createEnvelope(fields({ iat: NOW + 120_000, exp: NOW + 300_000 }), KEY)
	assert.equal(verify(future).reason, 'not-yet-valid')
})

test('small clock skew into the future is tolerated', () => {
	const slightlyAhead = createEnvelope(fields({ iat: NOW + 30_000, exp: NOW + 300_000 }), KEY)
	assert.equal(verify(slightlyAhead).ok, true)
})

test('windows longer than the maximum are rejected', () => {
	const longWindow = createEnvelope(
		fields({ iat: NOW, exp: NOW + DEFAULT_MAX_WINDOW_MS + 1 }),
		KEY,
	)
	assert.equal(verify(longWindow).reason, 'window-too-long')
})

test('the maximum window is configurable downward', () => {
	const envelope = validEnvelope()
	assert.equal(verify(envelope, { maxWindowMs: 60_000 }).reason, 'window-too-long')
})

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

test('origin and target must match the expected link', () => {
	const envelope = validEnvelope()
	assert.equal(verify(envelope, { expectOrigin: 'desk', expectTarget: 'phone' }).ok, true)
	assert.equal(verify(envelope, { expectOrigin: 'laptop' }).reason, 'origin-mismatch')
	assert.equal(verify(envelope, { expectTarget: 'tablet' }).reason, 'target-mismatch')
})

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

test('non-objects and wrong versions are rejected without throwing', () => {
	for (const bad of [null, undefined, 'envelope', 42, [], [validEnvelope()]]) {
		const result = verify(bad)
		assert.equal(result.ok, false)
		assert.equal(result.reason, 'malformed')
	}
	assert.equal(validateEnvelope({ ...validEnvelope(), v: 2 }).reason, 'version')
	assert.equal(validateEnvelope({ ...validEnvelope(), v: ENVELOPE_VERSION + 1 }).reason, 'version')
})

test('malformed fields are rejected', () => {
	const base = validEnvelope()
	const cases = [
		['bad jti (too short)', { jti: 'short' }],
		['bad jti (charset)', { jti: 'jti with spaces!!' }],
		['exp not after iat', { exp: NOW }],
		['non-integer iat', { iat: NOW + 0.5 }],
		['origin not a token', { origin: 'desk with spaces' }],
		['origin starts with punctuation', { origin: '.desk' }],
		['scope not a string', { scope: 42 }],
		['scope too long', { scope: 'x'.repeat(257) }],
		['scope with control characters', { scope: 'house\u0000keeping' }],
		['missing signature', { sig: '' }],
	]
	for (const [label, overrides] of cases) {
		const candidate = { ...base, ...overrides }
		const result = validateEnvelope(candidate)
		assert.equal(result.ok, false, label)
	}
})

test('names cannot smuggle newline-delimited fields', () => {
	// The canonicalizer splits on newlines; a name containing one would let an
	// attacker sign one payload and declare another. The charset must forbid it.
	const injection = {
		...validEnvelope(),
		origin: 'desk\nlevel=override',
	}
	assert.equal(validateEnvelope(injection).reason, 'malformed')
	assert.equal(verify(injection).reason, 'malformed')

	const equalsInjection = { ...validEnvelope(), origin: 'desk=evil' }
	assert.equal(validateEnvelope(equalsInjection).reason, 'malformed')
})

test('createEnvelope refuses to sign an invalid body', () => {
	assert.throws(() => createEnvelope(fields({ level: 'house' }), KEY), /invalid authority envelope: level/)
	assert.throws(() => createEnvelope(fields({ jti: 'x' }), KEY), /invalid authority envelope: malformed/)
})

// ---------------------------------------------------------------------------
// jti ledger
// ---------------------------------------------------------------------------

test('ledger accepts a fresh jti and tolerates same-link replay', () => {
	const ledger = new JtiLedger({ now: () => NOW })
	const grant = { jti: 'jti-abcdefgh12345', origin: 'desk', target: 'phone', exp: NOW + 60_000 }

	assert.deepEqual(ledger.check(grant), { ok: true, replay: 'fresh' })
	assert.deepEqual(ledger.check(grant), { ok: true, replay: 'same-link' })
	assert.equal(ledger.size, 1)
})

test('ledger flags the same jti on a different target or origin', () => {
	const ledger = new JtiLedger({ now: () => NOW })
	const grant = { jti: 'jti-abcdefgh12345', origin: 'desk', target: 'phone', exp: NOW + 60_000 }
	ledger.check(grant)

	assert.deepEqual(ledger.check({ ...grant, target: 'tablet' }), { ok: false, reason: 'jti-reuse' })
	assert.deepEqual(ledger.check({ ...grant, origin: 'laptop' }), { ok: false, reason: 'jti-reuse' })
})

test('ledger prunes expired entries and drops stale replays', () => {
	let clock = NOW
	const ledger = new JtiLedger({ now: () => clock })
	const grant = { jti: 'jti-abcdefgh12345', origin: 'desk', target: 'phone', exp: NOW + 1000 }
	ledger.check(grant)
	assert.equal(ledger.size, 1)

	clock = NOW + 5000
	assert.equal(ledger.size, 1, 'size is not pruned until check/prune runs')
	ledger.prune()
	assert.equal(ledger.size, 0)

	// After expiry the same jti is treated as new — a fresh grant, not a replay.
	assert.deepEqual(ledger.check({ ...grant, exp: clock + 1000 }), { ok: true, replay: 'fresh' })
})

test('ledger stays bounded by maxEntries', () => {
	const ledger = new JtiLedger({ now: () => NOW, maxEntries: 2 })
	for (let i = 0; i < 5; i++) {
		ledger.check({ jti: `jti-abcdefgh${i}`, origin: 'desk', target: 'phone', exp: NOW + 60_000 })
	}
	assert.equal(ledger.size, 2)
})

// ---------------------------------------------------------------------------
// Metadata helpers
// ---------------------------------------------------------------------------

test('metadata helper reads only the authority key and returns it unverified', () => {
	const envelope = validEnvelope()
	assert.deepEqual(envelopeFromMetadata({ [AUTHORITY_METADATA_KEY]: envelope }), envelope)
	assert.equal(envelopeFromMetadata({ other: envelope }), undefined)
	assert.equal(envelopeFromMetadata(null), undefined)
	assert.equal(envelopeFromMetadata('string'), undefined)
})

test('every rejection reason has human-readable text', () => {
	const reasons = [
		'malformed', 'version', 'level', 'scope-too-long', 'signature',
		'window-too-long', 'not-yet-valid', 'expired', 'origin-mismatch',
		'target-mismatch', 'jti-reuse', 'something-new',
	]
	for (const reason of reasons) {
		const text = describeReason(reason)
		assert.equal(typeof text, 'string')
		assert.ok(text.length > 0, `reason ${reason} must have text`)
		assert.match(text, /^(?!authority rejected \(\)$)/)
	}
})
