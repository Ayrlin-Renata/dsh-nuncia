/**
 * The chatelaine session id must be RECOGNISABLE, not just valid.
 *
 * A chatelaine created before the A2A tagging (P3.1) has a plain
 * `session-<uuid>` id. The metered gate (sylvia-bridge) recognises A2A
 * sessions by their id prefix, so an untagged chatelaine is invisible to it
 * and loses its exemption. The old thread stays on disk; the node runs on the
 * tagged id.
 *
 * The bug this pins: the migration lived only in resolveId(), so a node that
 * had never delivered a report kept publishing the untagged id in /status and
 * never migrated at all.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createChatelaineRuntime } from '../lib/chatelaine.js'
import { A2A_CHATELAINE_PREFIX } from '../lib/chatelaine.js'

async function scratchState() {
	const dir = await mkdtemp(join(tmpdir(), 'nuncia-chatelaine-'))
	const stateFile = join(dir, 'chatelaine.json')
	return { dir, stateFile }
}

function makeCtx() {
	const created = []
	return {
		created,
		agents: {
			create: async (options) => {
				created.push(options)
				return { dispose: async () => {} }
			},
			get: () => undefined,
			resume: async () => { throw new Error('no resume in this test') },
		},
	}
}

test('an untagged stored id is migrated to the tagged form', async () => {
	const { dir, stateFile } = await scratchState()
	await writeFile(stateFile, JSON.stringify({ version: 1, sessionId: 'session-11111111-2222-3333-4444-555555555555' }))

	const ctx = makeCtx()
	const runtime = createChatelaineRuntime({
		ctx,
		config: {},
		workspace: '/tmp/work',
		agentOptions: () => ({}),
		stateDir: dir,
		logger: { info: () => {}, warn: () => {} },
	})

	// peekId() is the path /status uses — it must migrate, not just report.
	const id = await runtime.peekId()
	assert.ok(id.startsWith(A2A_CHATELAINE_PREFIX), `expected a tagged id, got ${id}`)
	assert.ok(id.endsWith('11111111-2222-3333-4444-555555555555'))

	// And the migration must be PERSISTED, not just returned.
	const stored = JSON.parse(await readFile(stateFile, 'utf8'))
	assert.ok(stored.sessionId.startsWith(A2A_CHATELAINE_PREFIX))
	assert.equal(stored.previousSessionId, 'session-11111111-2222-3333-4444-555555555555')
})

test('an already-tagged id is left alone', async () => {
	const { dir, stateFile } = await scratchState()
	const tagged = `${A2A_CHATELAINE_PREFIX}11111111-2222-3333-4444-555555555555`
	await writeFile(stateFile, JSON.stringify({ version: 1, sessionId: tagged }))

	const runtime = createChatelaineRuntime({
		ctx: makeCtx(),
		config: {},
		workspace: '/tmp/work',
		agentOptions: () => ({}),
		stateDir: dir,
		logger: { info: () => {}, warn: () => {} },
	})

	assert.equal(await runtime.peekId(), tagged)
	const stored = JSON.parse(await readFile(stateFile, 'utf8'))
	assert.equal(stored.sessionId, tagged)
	assert.equal(stored.previousSessionId, undefined)
})

test('a fresh node adopts a tagged id from the start', async () => {
	const { dir, stateFile } = await scratchState()
	const ctx = makeCtx()
	const runtime = createChatelaineRuntime({
		ctx,
		config: {},
		workspace: '/tmp/work',
		agentOptions: () => ({}),
		stateDir: dir,
		logger: { info: () => {}, warn: () => {} },
	})

	const id = await runtime.resolveId()
	assert.ok(id.startsWith(A2A_CHATELAINE_PREFIX), `expected a tagged id, got ${id}`)
	assert.equal(ctx.created.length, 1)
	assert.equal(ctx.created[0].sessionId, id)
})
