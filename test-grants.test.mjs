/**
 * Tests for lib/grants.js — mint / revoke / expire / persist.
 *
 * Run: node --test test-grants.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { deriveAuthorityKey, verifyEnvelope } from './lib/authority.js'
import { DEFAULT_TTL_MS, GrantStore } from './lib/grants.js'

const SECRET = 'grant-test-secret-0123456789'
const KEY = deriveAuthorityKey(SECRET)
const T0 = 1_800_000_000_000

/** Store with a controllable clock. */
function makeStore(overrides = {}) {
	const clock = { now: T0 }
	const store = new GrantStore({
		key: KEY,
		origin: 'desk',
		now: () => clock.now,
		...overrides,
	})
	return { store, clock }
}

function tempPath() {
	return join(mkdtempSync(join(tmpdir(), 'nuncia-grants-')), 'grants.json')
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

test('mint produces a signed, verifiable grant with the requested window', () => {
	const { store } = makeStore()
	const grant = store.mint({ target: 'phone', scope: 'housekeeping', ttlMs: 60_000 })

	assert.equal(grant.level, 'intent')
	assert.equal(grant.target, 'phone')
	assert.equal(grant.scope, 'housekeeping')
	assert.equal(grant.origin, 'desk')
	assert.equal(grant.exp - grant.iat, 60_000)
	assert.equal(store.origin, 'desk')

	// The held envelope is a real envelope the receiver would accept.
	const verified = verifyEnvelope(grant.envelope, {
		key: KEY,
		now: T0 + 1000,
		expectOrigin: 'desk',
		expectTarget: 'phone',
	})
	assert.equal(verified.ok, true)
	assert.equal(verified.jti, grant.id)
})

test('mint defaults to the default TTL and level intent', () => {
	const { store } = makeStore()
	const grant = store.mint({ target: 'phone' })
	assert.equal(grant.level, 'intent')
	assert.equal(grant.exp - grant.iat, DEFAULT_TTL_MS)
})

test('override can be minted explicitly', () => {
	const { store } = makeStore()
	assert.equal(store.mint({ target: 'phone', level: 'override' }).level, 'override')
})

test('mint rejects bad requests instead of clamping silently', () => {
	const { store } = makeStore({ maxWindowMs: 60_000 })
	assert.throws(() => store.mint({ target: 'phone', level: 'house' }), /cannot mint level/)
	assert.throws(() => store.mint({}), /requires a target/)
	assert.throws(() => store.mint({ target: 'phone', ttlMs: 0 }), /positive integer/)
	assert.throws(() => store.mint({ target: 'phone', ttlMs: -5 }), /positive integer/)
	assert.throws(() => store.mint({ target: 'phone', ttlMs: 60_001 }), /exceeds the maximum window/)
	assert.throws(() => store.mint({ target: 'phone', ttlMs: 1.5 }), /positive integer/)
})

test('each mint gets a distinct jti', () => {
	const { store } = makeStore()
	const ids = new Set()
	for (let i = 0; i < 20; i++) ids.add(store.mint({ target: 'phone' }).id)
	assert.equal(ids.size, 20)
})

// ---------------------------------------------------------------------------
// Expiry (drift rule)
// ---------------------------------------------------------------------------

test('grants lapse at exp and disappear from active/envelopeFor', () => {
	const { store, clock } = makeStore()
	store.mint({ target: 'phone', ttlMs: 1000 })
	assert.equal(store.active({ target: 'phone' }).length, 1)
	assert.ok(store.envelopeFor('phone'))

	clock.now = T0 + 1001
	assert.equal(store.active({ target: 'phone' }).length, 0)
	assert.equal(store.envelopeFor('phone'), undefined)
})

test('prune reports how many grants expired', () => {
	const { store, clock } = makeStore()
	store.mint({ target: 'phone', ttlMs: 1000 })
	store.mint({ target: 'tablet', ttlMs: 1000 })
	assert.equal(store.prune(), 0)
	clock.now = T0 + 2000
	assert.equal(store.prune(), 2)
})

// ---------------------------------------------------------------------------
// Lookup and selection
// ---------------------------------------------------------------------------

test('envelopeFor prefers override over intent, then the later expiry', () => {
	const { store, clock } = makeStore()
	const intent = store.mint({ target: 'phone', ttlMs: 60_000 })

	clock.now = T0 + 1
	const override = store.mint({ target: 'phone', level: 'override', ttlMs: 30_000 })

	assert.equal(store.envelopeFor('phone').jti, override.id)

	// With the override gone, the intent window takes over.
	store.revoke(override.id)
	assert.equal(store.envelopeFor('phone').jti, intent.id)
})

test('envelopeFor ignores other targets', () => {
	const { store } = makeStore()
	store.mint({ target: 'tablet' })
	assert.equal(store.envelopeFor('phone'), undefined)
})

test('revoke removes a live grant and reports whether it existed', () => {
	const { store } = makeStore()
	const grant = store.mint({ target: 'phone' })
	assert.equal(store.revoke(grant.id), true)
	assert.equal(store.revoke(grant.id), false)
	assert.equal(store.get(grant.id), undefined)
	assert.equal(store.active().length, 0)
})

test('list summaries omit the signature and report remaining time', () => {
	const { store, clock } = makeStore()
	const grant = store.mint({ target: 'phone', ttlMs: 10_000, scope: 'ops' })
	clock.now = T0 + 4000

	const listed = store.list()
	assert.equal(listed.origin, 'desk')
	assert.equal(listed.grants.length, 1)
	const [entry] = listed.grants
	assert.equal(entry.id, grant.id)
	assert.equal(entry.remainingMs, 6000)
	assert.equal(entry.scope, 'ops')
	assert.equal('sig' in entry, false)
	assert.equal('envelope' in entry, false)

	// The copy returned by mint/get cannot mutate the stored grant.
	const copy = store.get(grant.id)
	copy.exp = 0
	assert.equal(store.get(grant.id).exp, grant.exp)
})

test('a store requires an origin', () => {
	assert.throws(() => new GrantStore({ key: KEY }), /requires an origin/)
})

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

test('grants survive a restart when persistence is enabled', () => {
	const persistPath = tempPath()
	const { store } = makeStore({ persistPath })
	const grant = store.mint({ target: 'phone', ttlMs: 60_000 })

	const reloaded = new GrantStore({ key: KEY, origin: 'desk', now: () => T0 + 1000, persistPath })
	assert.equal(reloaded.active().length, 1)
	assert.equal(reloaded.get(grant.id).level, 'intent')
	assert.equal(reloaded.envelopeFor('phone').jti, grant.id)
})

test('a tampered grant file cannot resurrect authority', () => {
	const persistPath = tempPath()
	const { store } = makeStore({ persistPath })
	store.mint({ target: 'phone', ttlMs: 60_000 })

	const payload = JSON.parse(readFileSync(persistPath, 'utf8'))
	// Flip one character of the signature, keeping the JSON valid.
	const sig = payload.grants[0].envelope.sig
	payload.grants[0].envelope.sig = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)
	writeFileSync(persistPath, JSON.stringify(payload))

	const warnings = []
	const reloaded = new GrantStore({
		key: KEY,
		origin: 'desk',
		now: () => T0 + 1000,
		persistPath,
		onWarn: (message) => warnings.push(message),
	})
	assert.equal(reloaded.active().length, 0)
	assert.equal(warnings.length, 1)
	assert.match(warnings[0], /dropped 1 unverifiable/)
})

test('a rotated pairing secret invalidates persisted grants', () => {
	const persistPath = tempPath()
	const { store } = makeStore({ persistPath })
	store.mint({ target: 'phone', ttlMs: 60_000 })

	const rotated = new GrantStore({
		key: deriveAuthorityKey('a-completely-different-secret'),
		origin: 'desk',
		now: () => T0 + 1000,
		persistPath,
		onWarn: () => {},
	})
	assert.equal(rotated.active().length, 0)
})

test('a corrupt grant file warns and starts empty instead of crashing', () => {
	const persistPath = tempPath()
	writeFileSync(persistPath, '{not json')
	const warnings = []
	const store = new GrantStore({
		key: KEY,
		origin: 'desk',
		persistPath,
		onWarn: (message) => warnings.push(message),
	})
	assert.equal(store.active().length, 0)
	assert.equal(warnings.length, 1)
	assert.match(warnings[0], /ignoring unreadable/)
})

test('persistence is off by default', () => {
	const { store } = makeStore()
	assert.doesNotThrow(() => store.mint({ target: 'phone' }))
	// No file is produced anywhere: the store simply keeps state in memory.
	assert.equal(store.active().length, 1)
})
