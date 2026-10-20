/**
 * v2 authority tests — per-node Ed25519 identities.
 *
 * The property this suite exists to prove (DESIGN §20.1): **verification
 * material is not minting material.** A node that can check `intent` holds only
 * peer public keys, so there is no operation available to it that turns a
 * public key into a signature for someone else's name. The shared-HMAC v1
 * design could not express this at all — every verifier held the signing root.
 *
 * Run: node --test tests/test-v2.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'

import {
	DEFAULT_MAX_WINDOW_MS,
	canonicalPayloadV2,
	createEnvelope,
	createEnvelopeV2,
	createSigner,
	deriveAuthorityKey,
	exportPublicKey,
	fingerprintOf,
	keyIdOf,
	parsePublicKey,
	validateEnvelope,
	verifyEnvelope,
	verifyEnvelopeV2,
	verifySignatureV2,
} from '../lib/authority.js'
import { createAuthorityGate } from '../lib/inbound.js'
import { describeNodeKey } from '../lib/keys.js'

const alice = describeNodeKey(generateKeyPairSync('ed25519').privateKey)
const bob = describeNodeKey(generateKeyPairSync('ed25519').privateKey)
const ghost = describeNodeKey(generateKeyPairSync('ed25519').privateKey)

const NOW = 1_800_000_000_000
const SECRET = 'v2-suite-secret-0123456789abcdef'

const fields = (overrides = {}) => ({
	level: 'intent',
	scope: 'housekeeping',
	origin: 'alice',
	target: 'bob',
	iat: NOW,
	exp: NOW + 60_000,
	jti: 'jti-v2-000001',
	...overrides,
})

const sign = (who, overrides = {}) => createEnvelopeV2(fields(overrides), { privateKey: who.privateKey, kid: who.kid })
const verifyWith = (envelope, who, options = {}) => verifyEnvelopeV2(envelope, { publicKey: who.publicKey, now: NOW + 1000, ...options })

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

test('public keys round-trip through their paste form', () => {
	const text = exportPublicKey(alice.publicKey)
	assert.equal(text, alice.publicKeyText)
	assert.ok(!text.includes('\n'))
	const parsed = parsePublicKey(text)
	assert.ok(parsed)
	assert.equal(keyIdOf(parsed), alice.kid)
	assert.equal(fingerprintOf(parsed), alice.fingerprint)
	assert.match(alice.fingerprint, /^SHA256:(.{4} ){10}.{3}$/)
})

test('a private key reduces to its public half for id derivation', () => {
	assert.equal(keyIdOf(alice.privateKey), alice.kid)
	assert.equal(exportPublicKey(alice.privateKey), alice.publicKeyText)
})

test('non-Ed25519 and garbage key material is refused, not coerced', () => {
	assert.equal(parsePublicKey('not-a-key'), undefined)
	assert.equal(parsePublicKey(''), undefined)
	assert.equal(parsePublicKey(null), undefined)
	assert.throws(() => keyIdOf({}), /not an Ed25519 public key/)
})

test('two key pairs never share a kid', () => {
	assert.notEqual(alice.kid, bob.kid)
	assert.notEqual(alice.kid, ghost.kid)
})

// ---------------------------------------------------------------------------
// Envelope v2
// ---------------------------------------------------------------------------

test('a v2 envelope round-trips with the matching public key', () => {
	const envelope = sign(alice)
	assert.equal(envelope.v, 2)
	assert.equal(envelope.kid, alice.kid)
	const result = verifyWith(envelope, alice, { expectOrigin: 'alice', expectTarget: 'bob' })
	assert.equal(result.ok, true)
	assert.equal(result.level, 'intent')
	assert.equal(result.scope, 'housekeeping')
	assert.equal(result.kid, alice.kid)
})

test('canonical form binds every field, kid included', () => {
	const base = canonicalPayloadV2(fields({ kid: alice.kid }))
	assert.match(base, /^nuncia-authority-v2\n/)
	for (const [field, value] of [
		['level', 'override'],
		['scope', 'other'],
		['origin', 'carol'],
		['target', 'dave'],
		['kid', bob.kid],
		['iat', NOW + 1],
		['exp', NOW + 61_000],
		['jti', 'jti-v2-000002'],
	]) {
		assert.notEqual(canonicalPayloadV2(fields({ kid: alice.kid, [field]: value })), base, `${field} must affect the signature`)
	}
})

test('field tampering fails the signature', () => {
	const envelope = sign(alice)
	for (const [field, value] of [
		['level', 'override'],
		['scope', 'everything'],
		['origin', 'carol'],
		['target', 'dave'],
		['iat', NOW + 5],
		['exp', NOW + 120_000],
		['jti', 'jti-v2-000009'],
	]) {
		const result = verifyWith({ ...envelope, [field]: value }, alice)
		assert.equal(result.ok, false, field)
		assert.equal(result.reason, 'signature', field)
	}
})

test('a foreign key id is refused before any signature work', () => {
	const lying = sign(bob, { origin: 'alice' })
	const result = verifyWith(lying, alice)
	assert.equal(result.ok, false)
	assert.equal(result.reason, 'kid-mismatch')
})

test('the right kid with the wrong signer is a signature failure', () => {
	// ghost claims to be alice, copies alice's kid, signs with its own key.
	const forged = createEnvelopeV2(fields({ origin: 'alice' }), { privateKey: ghost.privateKey, kid: alice.kid })
	const result = verifyWith(forged, alice)
	assert.equal(result.ok, false)
	assert.equal(result.reason, 'signature')
	assert.equal(verifySignatureV2(forged, alice.publicKey), false)
})

test('a pinned kid must match', () => {
	const envelope = sign(alice)
	assert.equal(verifyWith(envelope, alice, { expectKid: alice.kid }).ok, true)
	assert.equal(verifyWith(envelope, alice, { expectKid: bob.kid }).reason, 'kid-mismatch')
})

test('freshness and window rules apply to v2 exactly as to v1', () => {
	const envelope = sign(alice)
	assert.equal(verifyEnvelopeV2(envelope, { publicKey: alice.publicKey, now: NOW + 120_000 }).reason, 'expired')
	const future = sign(alice, { iat: NOW + 120_000, exp: NOW + 300_000 })
	assert.equal(verifyEnvelopeV2(future, { publicKey: alice.publicKey, now: NOW }).reason, 'not-yet-valid')
	const long = sign(alice, { iat: NOW, exp: NOW + DEFAULT_MAX_WINDOW_MS + 1 })
	assert.equal(verifyEnvelopeV2(long, { publicKey: alice.publicKey, now: NOW }).reason, 'window-too-long')
})

test('binding checks reject a retargeted grant', () => {
	const envelope = sign(alice)
	assert.equal(verifyWith(envelope, alice, { expectOrigin: 'bob' }).reason, 'origin-mismatch')
	assert.equal(verifyWith(envelope, alice, { expectTarget: 'carol' }).reason, 'target-mismatch')
})

test('a v1 envelope is not accepted by the v2 verifier (and vice versa)', () => {
	const key = deriveAuthorityKey(SECRET)
	const legacy = createEnvelope(fields(), key)
	assert.equal(verifyEnvelopeV2(legacy, { publicKey: alice.publicKey, now: NOW }).reason, 'version')
	const modern = sign(alice)
	assert.equal(verifyEnvelope(modern, { key, now: NOW }).reason, 'version')
})

test('malformed v2 bodies are reported structurally', () => {
	const envelope = sign(alice)
	assert.equal(validateEnvelope({ ...envelope, kid: undefined }).reason, 'malformed')
	assert.equal(validateEnvelope({ ...envelope, sig: 'short' }).reason, 'signature')
	assert.equal(validateEnvelope({ ...envelope, v: 99 }).reason, 'version')
	assert.equal(validateEnvelope(null).reason, 'malformed')
})

test('the signer facade mints and re-verifies its own envelopes', () => {
	const signer = createSigner({ privateKey: alice.privateKey })
	assert.equal(signer.version, 2)
	assert.equal(signer.kid, alice.kid)
	const envelope = signer.createEnvelope(fields())
	assert.equal(signer.verify(envelope, { now: NOW + 1000, expectOrigin: 'alice' }).ok, true)
	const identity = signer.identity()
	assert.equal(identity.publicKey, alice.publicKeyText)
})

// ---------------------------------------------------------------------------
// Gate v2 — the asymmetry
// ---------------------------------------------------------------------------

const GATE = () => createAuthorityGate({
	nodeName: 'bob',
	peers: [{ name: 'alice', publicKey: alice.publicKeyText, kid: alice.kid }],
	now: () => NOW + 1000,
})

const withAuthority = (envelope) => ({ authority: envelope })

test('a gate with only a public key honors the matching envelope', () => {
	const gate = GATE()
	const result = gate.verify(withAuthority(sign(alice)))
	assert.equal(result.ok, true)
	assert.equal(result.level, 'intent')
	assert.equal(result.origin, 'alice')
	assert.equal(result.kid, alice.kid)
})

test('THE PROPERTY: the verifying gate cannot mint, even though it holds every key it checks', () => {
	const gate = GATE()
	// Everything the gate can compute for alice:
	const onlyPublicKey = gate.describe().peers[0]
	assert.equal(onlyPublicKey.canVerifyV2, true)

	// A node holding just that (as any verifier must) can produce signatures
	// with ITS OWN key — never with alice's.
	const impostor = createEnvelopeV2(fields({ origin: 'alice' }), { privateKey: ghost.privateKey, kid: alice.kid })
	assert.equal(gate.verify(withAuthority(impostor)).ok, false)
	assert.equal(gate.verify(withAuthority(impostor)).reason, 'signature')

	// Claiming alice's name with its own honest kid is refused even earlier.
	const honestGhost = createEnvelopeV2(fields({ origin: 'alice' }), { privateKey: ghost.privateKey, kid: ghost.kid })
	assert.equal(gate.verify(withAuthority(honestGhost)).reason, 'kid-mismatch')
})

test('an origin with no configured key fails down to peer', () => {
	const gate = GATE()
	const stranger = createEnvelopeV2(fields({ origin: 'stranger' }), { privateKey: ghost.privateKey, kid: ghost.kid })
	const result = gate.verify(withAuthority(stranger))
	assert.equal(result.ok, false)
	assert.equal(result.level, 'peer')
	assert.equal(result.reason, 'unknown-origin')
})

test('a name-only peer entry cannot verify v2 (migration is not silent)', () => {
	const gate = createAuthorityGate({ nodeName: 'bob', peers: ['alice'], now: () => NOW + 1000 })
	assert.equal(gate.verify(withAuthority(sign(alice))).reason, 'unknown-origin')
})

test('the gate clock advances with real time (no boot-time freeze)', () => {
	// Regression: capturing now() once at construction made a long-running node
	// reject every grant minted more than the skew window after its boot with
	// "not-yet-valid" — seen live on the AVD before this test existed.
	let clock = NOW
	const gate = createAuthorityGate({
		nodeName: 'bob',
		peers: [{ name: 'alice', publicKey: alice.publicKeyText }],
		now: () => clock,
	})
	const envelope = sign(alice, { iat: NOW + 300_000, exp: NOW + 360_000 })
	assert.equal(gate.verify(withAuthority(envelope)).reason, 'not-yet-valid')
	clock = NOW + 310_000
	assert.equal(gate.verify(withAuthority(envelope)).ok, true)
})

test('a node cannot speak for itself (bounced grant)', () => {
	const gate = GATE()
	const own = createEnvelopeV2(fields({ origin: 'bob', target: 'bob' }), { privateKey: bob.privateKey, kid: bob.kid })
	assert.equal(gate.verify(withAuthority(own)).reason, 'origin-mismatch')
})

test('legacy v1 is accepted only with a key and allowV1', () => {
	const key = deriveAuthorityKey(SECRET)
	const legacy = createEnvelope(fields(), key)

	const withLegacy = createAuthorityGate({ nodeName: 'bob', peers: ['alice'], legacyKey: key, now: () => NOW + 1000 })
	assert.equal(withLegacy.verify(withAuthority(legacy)).ok, true)

	const disabled = createAuthorityGate({ nodeName: 'bob', peers: ['alice'], legacyKey: key, allowV1: false, now: () => NOW + 1000 })
	assert.equal(disabled.verify(withAuthority(legacy)).reason, 'legacy-disabled')

	const noKey = createAuthorityGate({ nodeName: 'bob', peers: ['alice'], now: () => NOW + 1000 })
	assert.equal(noKey.verify(withAuthority(legacy)).reason, 'legacy-disabled')
})

test('legacy v1 without a shared secret is dead even for a name-only peer', () => {
	const key = deriveAuthorityKey(SECRET)
	const legacy = createEnvelope(fields(), key)
	const otherKey = createAuthorityGate({ nodeName: 'bob', peers: ['alice'], legacyKey: deriveAuthorityKey('another secret'), now: () => NOW + 1000 })
	assert.equal(otherKey.verify(withAuthority(legacy)).reason, 'signature')
})

test('peer configuration errors are loud at construction', () => {
	assert.throws(() => createAuthorityGate({ nodeName: 'bob', peers: ['alice', 'alice'] }), /duplicate peer/)
	assert.throws(() => createAuthorityGate({ nodeName: 'bob', peers: [{ name: 'alice', publicKey: 'garbage' }] }), /unreadable Ed25519 public key/)
	assert.throws(
		() => createAuthorityGate({ nodeName: 'bob', peers: [{ name: 'alice', publicKey: alice.publicKeyText, kid: bob.kid }] }),
		/pinned to kid/,
	)
	assert.throws(() => createAuthorityGate({ nodeName: '' }), /requires a nodeName/)
})

test('no envelope is peer authority, and junk envelopes fail down with a reason', () => {
	const gate = GATE()
	assert.deepEqual(gate.verify(undefined), { ok: true, level: 'peer', carried: false })
	assert.equal(gate.verify({ authority: { v: 2 } }).reason, 'level')
	assert.equal(gate.verify({ authority: { v: 2, level: 'intent' } }).reason, 'malformed')
	assert.equal(gate.verify({ authority: { v: 1, level: 'intent' } }).reason, 'malformed')
})

test('describe() exposes only public material', () => {
	const description = GATE().describe()
	assert.equal(description.nodeName, 'bob')
	assert.deepEqual(description.peers, [{ name: 'alice', kid: alice.kid, canVerifyV2: true }])
	assert.ok(!JSON.stringify(description).includes(alice.publicKeyText))
})

