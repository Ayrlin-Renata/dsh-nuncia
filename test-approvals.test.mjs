/**
 * Tests for lib/approvals.js — the plugin-owned approval queue.
 *
 * Run: node --test test-approvals.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { ApprovalBroker, DEFAULT_APPROVAL_TIMEOUT_MS } from './lib/approvals.js'

function makeBroker(overrides = {}) {
	const clock = { now: 1_800_000_000_000 }
	const broker = new ApprovalBroker({
		now: () => clock.now,
		idFactory: (() => {
			let n = 0
			return () => `approval-${++n}`
		})(),
		...overrides,
	})
	return { broker, clock }
}

test('a granted decision resolves the waiter', async () => {
	const { broker } = makeBroker()
	const waiting = broker.request({ reason: 'grant intent to desk', target: 'desk', level: 'intent' })

	assert.equal(broker.size, 1)
	const [pending] = broker.list()
	assert.equal(pending.id, 'approval-1')
	assert.equal(pending.target, 'desk')
	assert.equal(pending.level, 'intent')

	assert.equal(broker.decide(pending.id, 'allowed-once'), true)
	assert.equal(await waiting, 'allowed-once')
	assert.equal(broker.size, 0)
})

test('a rejection resolves the waiter and clears the request', async () => {
	const { broker } = makeBroker()
	const waiting = broker.request({ reason: 'nope' })
	const [pending] = broker.list()
	broker.decide(pending.id, 'rejected')
	assert.equal(await waiting, 'rejected')
	assert.equal(broker.list().length, 0)
})

test('unknown ids and invalid decisions are refused', async () => {
	const { broker } = makeBroker()
	const waiting = broker.request({ reason: 'x' })
	const [pending] = broker.list()

	assert.equal(broker.decide('approval-999', 'allowed-once'), false)
	assert.equal(broker.decide(pending.id, 'maybe'), false)
	assert.equal(broker.decide(pending.id, 'timeout'), false, 'timeout is not something a surface may decide')
	assert.equal(broker.size, 1)

	broker.decide(pending.id, 'rejected')
	assert.equal(await waiting, 'rejected')
})

test('a second decision on the same request is a no-op', async () => {
	const { broker } = makeBroker()
	const waiting = broker.request({ reason: 'x' })
	const [pending] = broker.list()
	assert.equal(broker.decide(pending.id, 'allowed-once'), true)
	assert.equal(broker.decide(pending.id, 'rejected'), false)
	assert.equal(await waiting, 'allowed-once')
})

test('requests expire to timeout (fail closed)', async () => {
	const { broker, clock } = makeBroker({ timeoutMs: 1000 })
	const waiting = broker.request({ reason: 'slow human' })
	assert.equal(broker.list().length, 1)

	clock.now += 1001
	assert.equal(broker.list().length, 0, 'listing prunes expired requests')
	assert.equal(await waiting, 'timeout')
})

test('the default timeout is two minutes and is reported on the request', () => {
	const { broker, clock } = makeBroker()
	broker.request({ reason: 'x' })
	const [pending] = broker.list()
	assert.equal(pending.expiresAt - pending.createdAt, DEFAULT_APPROVAL_TIMEOUT_MS)
	assert.equal(pending.createdAt, clock.now)
})

test('cancelAll closes everything as cancelled (plugin unload)', async () => {
	const { broker } = makeBroker()
	const a = broker.request({ reason: 'a' })
	const b = broker.request({ reason: 'b' })
	broker.cancelAll()
	assert.equal(await a, 'cancelled')
	assert.equal(await b, 'cancelled')
	assert.equal(broker.size, 0)
})

test('an announce hook runs on creation and cannot strand a request', async () => {
	const announced = []
	const { broker } = makeBroker({
		onCreate: (request) => {
			announced.push(request.id)
			throw new Error('announce failed')
		},
	})
	const waiting = broker.request({ reason: 'x' })
	assert.deepEqual(announced, ['approval-1'])

	// The request is still decidable even though announcing threw.
	const [pending] = broker.list()
	assert.equal(broker.decide(pending.id, 'allowed-once'), true)
	assert.equal(await waiting, 'allowed-once')
})

test('pending requests carry no secrets', () => {
	const { broker } = makeBroker()
	broker.request({ reason: 'grant intent to desk', target: 'desk', level: 'intent', scope: 'ops', toolName: 'request_user_intent' })
	const [pending] = broker.list()
	const serialized = JSON.stringify(pending)
	assert.doesNotMatch(serialized, /\bsig\b|jti|secret/i)
	assert.equal(pending.toolName, 'request_user_intent')
})
