/**
 * Tests for lib/inbound.js — the fail-down gate and the security log.
 *
 * Run: node --test test-inbound.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { createEnvelope, deriveAuthorityKey } from '../lib/authority.js'
import { SecurityLog, claimedLevel, createAuthorityGate } from '../lib/inbound.js'

const SECRET = 'inbound-test-secret-0123456789'
const KEY = deriveAuthorityKey(SECRET)
const NOW = 1_800_000_000_000

function gate(overrides = {}) {
	let clock = { now: NOW }
	const g = createAuthorityGate({
		key: KEY,
		nodeName: 'phone',
		now: () => clock.now,
		...overrides,
	})
	return { gate: g, clock }
}

function envelope(overrides = {}) {
	return createEnvelope(
		{
			level: 'intent',
			scope: 'housekeeping',
			origin: 'desk',
			target: 'phone',
			iat: NOW,
			exp: NOW + 60_000,
			jti: 'jti-inbound123456',
			...overrides,
		},
		KEY,
	)
}

const metadata = (authority) => ({ authority })

// ---------------------------------------------------------------------------
// Peer passthrough
// ---------------------------------------------------------------------------

test('no envelope means peer authority', () => {
	const { gate: g } = gate()
	assert.deepEqual(g.verify(undefined), { ok: true, level: 'peer', carried: false })
	assert.deepEqual(g.verify({}), { ok: true, level: 'peer', carried: false })
	assert.deepEqual(g.verify({ agentPreset: 'standard' }), { ok: true, level: 'peer', carried: false })
})

// ---------------------------------------------------------------------------
// Accepted grants
// ---------------------------------------------------------------------------

test('a valid intent envelope is honored and its jti recorded', () => {
	const { gate: g } = gate()
	const result = g.verify(metadata(envelope()))
	assert.equal(result.ok, true)
	assert.equal(result.level, 'intent')
	assert.equal(result.carried, true)
	assert.equal(result.scope, 'housekeeping')
	assert.equal(result.origin, 'desk')
	assert.equal(result.jti, 'jti-inbound123456')
	assert.equal(result.replay, 'fresh')
})

test('override is honored when signed', () => {
	const { gate: g } = gate()
	const result = g.verify(metadata(envelope({ level: 'override' })))
	assert.equal(result.ok, true)
	assert.equal(result.level, 'override')
})

test('same-link replay is tolerated inside the window', () => {
	const { gate: g } = gate()
	assert.equal(g.verify(metadata(envelope())).replay, 'fresh')
	assert.equal(g.verify(metadata(envelope())).replay, 'same-link')
})

test('an empty allowlist accepts any signed origin', () => {
	const { gate: g } = gate()
	assert.equal(g.verify(metadata(envelope({ origin: 'laptop' }))).ok, true)
})

test('a configured allowlist rejects other origins', () => {
	const { gate: g } = gate({ peers: ['desk'] })
	assert.equal(g.verify(metadata(envelope({ origin: 'desk' }))).ok, true)

	const stranger = g.verify(metadata(envelope({ origin: 'laptop', jti: 'jti-stranger1234' })))
	assert.equal(stranger.ok, false)
	assert.equal(stranger.level, 'peer')
	assert.equal(stranger.reason, 'origin-mismatch')
})

// ---------------------------------------------------------------------------
// Fail-down behaviour
// ---------------------------------------------------------------------------

test('every rejection fails down to peer with a reason and a message', () => {
	const { gate: g } = gate()
	const expired = envelope({ iat: NOW - 120_000, exp: NOW - 1000 })
	const wrongTarget = envelope({ target: 'tablet', jti: 'jti-wrongtarget1' })
	const tampered = { ...envelope({ jti: 'jti-tampered1234' }), scope: 'something-else' }

	for (const [label, env, reason] of [
		['expired', expired, 'expired'],
		['wrong target', wrongTarget, 'target-mismatch'],
		['tampered', tampered, 'signature'],
	]) {
		const result = g.verify(metadata(env))
		assert.equal(result.ok, false, label)
		assert.equal(result.level, 'peer', `${label} must fail down to peer`)
		assert.equal(result.reason, reason, label)
		assert.equal(typeof result.message, 'string')
		assert.ok(result.message.length > 0)
	}
})

test('a malformed envelope fails down instead of throwing', () => {
	const { gate: g } = gate()
	for (const bad of [null, 'nope', 42, [], { level: 'override' }]) {
		const result = g.verify(metadata(bad))
		assert.equal(result.ok, false)
		assert.equal(result.level, 'peer')
	}
})

test('rejection detail never echoes the signature', () => {
	const { gate: g } = gate()
	const env = envelope({ jti: 'jti-detailcheck1' })
	const tampered = { ...env, scope: 'changed', sig: env.sig }
	const result = g.verify(metadata(tampered))
	assert.equal(result.ok, false)
	assert.equal(JSON.stringify(result.detail).includes(env.sig), false)
})

test('a gate requires a node name', () => {
	assert.throws(() => createAuthorityGate({ key: KEY }), /nodeName/)
})

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

test('claimedLevel reports what was carried, unverified', () => {
	assert.equal(claimedLevel(metadata(envelope({ level: 'override' }))), 'override')
	assert.equal(claimedLevel({}), undefined)
	assert.equal(claimedLevel(undefined), undefined)
	assert.equal(claimedLevel(metadata('garbage')), undefined)
})

// ---------------------------------------------------------------------------
// Security log
// ---------------------------------------------------------------------------

test('security log keeps newest first and trims to its limit', () => {
	let clock = 1000
	const log = new SecurityLog({ limit: 3, now: () => clock++ })
	for (let i = 0; i < 5; i++) log.record({ kind: 'authority-rejected', reason: `reason-${i}`, detail: { i } })

	assert.equal(log.size, 3)
	const events = log.list()
	assert.deepEqual(events.map((e) => e.reason), ['reason-4', 'reason-3', 'reason-2'])
	assert.deepEqual(events[0].detail, { i: 4 })
	assert.ok(events[0].at > events[1].at)
})

test('security log defaults to a bounded 50 entries', () => {
	const log = new SecurityLog()
	for (let i = 0; i < 60; i++) log.record({ kind: 'x', reason: 'y' })
	assert.equal(log.size, 50)
})
