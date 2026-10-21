/**
 * Tests for the chatelaine's RESILIENCE (DESIGN §20.12 P2).
 *
 * The chatelaine is the channel every operator reports through. It must never
 * be a dead end:
 *
 *  - The session may not exist yet (a fresh node) — it must be created.
 *  - The stored id may point at a session that is GONE (the store was wiped,
 *    or the id was migrated to a tagged form whose directory does not exist)
 *    — the node must fall back to the previous id, and then to a new session.
 *  - Delivery must never throw into the calling turn: a report that cannot be
 *    delivered says so and returns.
 *
 * These tests drive the real runtime with a fake agents service.
 *
 * Run: node --test tests/test-chatelaine-resilience.test.mjs
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createChatelaineRuntime } from '../lib/chatelaine.js'

/** A minimal agent that records what it was told. */
function makeAgent(id, log) {
	return {
		id,
		injected: [],
		followedUp: [],
		inject: (message) => { log.injected.push(message) },
		followup: (message) => { log.followedUp.push(message) },
	}
}

/**
 * A fake `agents` service.
 * @param {{sessions?: Set<string>, resumeFails?: Set<string>}} opts
 */
function makeAgents(opts = {}) {
	const live = new Map()
	const known = opts.sessions ?? new Set()
	const log = { injected: [], followedUp: [], created: [], resumed: [] }
	const agents = {
		create: async (options) => {
			const id = String(options.sessionId)
			log.created.push(id)
			known.add(id)
			const agent = makeAgent(id, log)
			live.set(id, agent)
			return { agent, dispose: async () => { live.delete(id) } }
		},
		get: (id) => live.get(String(id)),
		resume: async ({ resumeSessionId }) => {
			const id = String(resumeSessionId)
			log.resumed.push(id)
			if (opts.resumeFails?.has(id)) throw new Error(`session "${id}" not found`)
			if (!known.has(id)) throw new Error(`session "${id}" not found`)
			const agent = makeAgent(id, log)
			live.set(id, agent)
			return { agent, dispose: async () => { live.delete(id) } }
		},
	}
	return { agents, log, known }
}

function makeCtx(agents) {
	return {
		agents,
		logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
		get: () => undefined,
	}
}

async function scratchDir() {
	const dir = await mkdtemp(join(tmpdir(), 'nuncia-chatelaine-'))
	return { dir, stateFile: join(dir, 'chatelaine.json') }
}

test('a fresh node creates the chatelaine session on the first report', async () => {
	const { dir } = await scratchDir()
	const { agents, log } = makeAgents()
	const runtime = createChatelaineRuntime({
		ctx: makeCtx(agents),
		config: {},
		workspace: '/tmp/house',
		stateDir: dir,
	})

	const result = await runtime.report('hello')

	assert.equal(result.delivered, true, `report failed: ${result.reason}`)
	assert.equal(log.created.length, 1, 'the session was created')
	assert.match(log.created[0], /^a2a-chatelaine-/)
})

test('a stored id whose session is gone falls back to the previous id', async () => {
	const { dir, stateFile } = await scratchDir()
	// The state points at a TAGGED id (the migrated form) but only the OLD
	// id exists on disk — exactly the state a migration leaves behind.
	await mkdir(dir, { recursive: true })
	await writeFile(stateFile, JSON.stringify({
		version: 1,
		sessionId: 'a2a-chatelaine-11111111-2222-3333-4444-555555555555',
		previousSessionId: 'session-11111111-2222-3333-4444-555555555555',
	}, null, 2))

	const { agents, log } = makeAgents({ sessions: new Set(['session-11111111-2222-3333-4444-555555555555']) })
	const runtime = createChatelaineRuntime({
		ctx: makeCtx(agents),
		config: {},
		workspace: '/tmp/house',
		stateDir: dir,
	})

	const result = await runtime.report('hello')

	assert.equal(result.delivered, true, `report failed: ${result.reason}`)
	assert.equal(result.sessionId, 'session-11111111-2222-3333-4444-555555555555', 'the report landed in the thread that EXISTS')
	assert.deepEqual(log.resumed, [
		'a2a-chatelaine-11111111-2222-3333-4444-555555555555',
		'session-11111111-2222-3333-4444-555555555555',
	], 'the dead tagged id was tried first, then the thread that exists')
})

test('a stored id whose session AND its predecessor are gone gets a new session', async () => {
	const { dir, stateFile } = await scratchDir()
	await mkdir(dir, { recursive: true })
	await writeFile(stateFile, JSON.stringify({
		version: 1,
		sessionId: 'a2a-chatelaine-11111111-2222-3333-4444-555555555555',
		previousSessionId: 'session-11111111-2222-3333-4444-555555555555',
	}, null, 2))

	const { agents, log } = makeAgents({ sessions: new Set() })
	const runtime = createChatelaineRuntime({
		ctx: makeCtx(agents),
		config: {},
		workspace: '/tmp/house',
		stateDir: dir,
	})

	const result = await runtime.report('hello')

	assert.equal(result.delivered, true, `report failed: ${result.reason}`)
	assert.equal(log.created.length, 1, 'a fresh session was created')
	assert.match(log.created[0], /^a2a-chatelaine-/)
	assert.notEqual(log.created[0], 'a2a-chatelaine-11111111-2222-3333-4444-555555555555')
})

test('an unreachable chatelaine never throws into the calling turn', async () => {
	const { dir } = await scratchDir()
	const { agents } = makeAgents({ sessions: new Set() })
	// No create() support at all: the node cannot make a session.
	const agentsNoCreate = {
		get: agents.get,
		resume: async () => { throw new Error('no sessions') },
	}
	const runtime = createChatelaineRuntime({
		ctx: makeCtx(agentsNoCreate),
		config: {},
		workspace: '/tmp/house',
		stateDir: dir,
	})

	const result = await runtime.report('hello')
	assert.equal(result.delivered, false)
	assert.ok(typeof result.reason === 'string' && result.reason.length > 0, 'the reason explains why')
})
