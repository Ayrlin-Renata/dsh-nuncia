/**
 * Tests for lib/notices.js.
 *
 * The notices are the agent's only view of authority, so the assertions that
 * matter are: they carry the facts the agent needs, and they carry NOTHING the
 * agent must never see.
 *
 * Run: node --test test-notices.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { authorityRejectedNotice, describeRemaining, intentGrantedNotice, intentLapsedNotice } from './lib/notices.js'

const NOW = 1_800_000_000_000

test('granted notice states level, peer, scope and remaining time', () => {
	const text = intentGrantedNotice({ level: 'intent', origin: 'desk', scope: 'housekeeping', expiresAt: NOW + 5 * 60_000, now: NOW })
	assert.match(text, /peer "desk"/)
	assert.match(text, /user intent/)
	assert.match(text, /about 5 minutes/)
	assert.match(text, /scope: housekeeping/)
	assert.match(text, /You will be told when it ends/)
	assert.equal(text.split('\n').length, 3, 'three short lines; the first is the summary')
})

test('override notice warns that house rules may be contradicted', () => {
	const text = intentGrantedNotice({ level: 'override', origin: 'desk', expiresAt: NOW + 60_000, now: NOW })
	assert.match(text, /user override/)
	assert.match(text, /may contradict house rules/)
	assert.doesNotMatch(text, /scope:/)
})

test('lapsed notice drops the peer back to peer authority', () => {
	const text = intentLapsedNotice({ origin: 'desk', level: 'intent', scope: 'housekeeping' })
	assert.match(text, /window from peer "desk" has ended/)
	assert.match(text, /\(scope: housekeeping\)/)
	assert.match(text, /arrive as "peer"/)
	assert.match(text, /Ask the user again/)
})

test('rejection notice names the peer and the reason, and keeps peer semantics', () => {
	const text = authorityRejectedNotice({ origin: 'desk', reason: 'expired', message: 'grant has expired' })
	assert.match(text, /peer "desk"/)
	assert.match(text, /grant has expired/)
	assert.match(text, /handled as "peer"/)

	const anonymous = authorityRejectedNotice({ reason: 'signature' })
	assert.match(anonymous, /a peer claimed user authority/)
})

test('no notice ever contains grant material', () => {
	const samples = [
		intentGrantedNotice({ level: 'intent', origin: 'desk', scope: 'ops', expiresAt: NOW + 30_000, now: NOW }),
		intentGrantedNotice({ level: 'override', origin: 'phone', expiresAt: NOW + 30_000, now: NOW }),
		intentLapsedNotice({ origin: 'desk', level: 'override', scope: 'ops' }),
		authorityRejectedNotice({ origin: 'desk', reason: 'signature', message: 'signature does not verify' }),
	]
	for (const text of samples) {
		assert.doesNotMatch(text, /\bsig\b|signature=|envelope|metadata\.authority|jti/i, text)
	}
})

test('remaining time degrades gracefully', () => {
	assert.equal(describeRemaining(0), 'no time left')
	assert.equal(describeRemaining(-1000), 'no time left')
	assert.equal(describeRemaining(30_000), 'less than a minute')
	assert.equal(describeRemaining(60_000), 'about a minute')
	assert.equal(describeRemaining(5 * 60_000), 'about 5 minutes')
	assert.equal(describeRemaining(3 * 60 * 60_000), 'about 3 hours')
})
