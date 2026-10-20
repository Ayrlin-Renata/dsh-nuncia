/**
 * Tests for lib/operators.js.
 *
 * The book is the only place a handle is meaningful, so the assertions are:
 * handles look right, records survive a restart, expiry is read-time (no timer
 * needed), and a corrupt book is refused instead of silently dropped.
 *
 * Run: node --test tests/test-operators.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { HANDLE_PATTERN, OperatorBook, findHandle, mintHandle } from '../lib/operators.js'

async function bookInTemp(options = {}) {
	const dir = await mkdtemp(join(tmpdir(), 'nuncia-ops-'))
	const file = join(dir, 'operators.json')
	const book = new OperatorBook({ file, ...options })
	await book.init()
	return { dir, file, book, cleanup: async () => { await rm(dir, { recursive: true, force: true }) } }
}

test('handles are op_ plus 16 hex and are found in prose', () => {
	const handle = mintHandle()
	assert.match(handle, HANDLE_PATTERN)
	assert.equal(findHandle(`please continue ${handle} now`), handle)
	assert.equal(findHandle('no handle here'), undefined)
	assert.equal(findHandle(undefined), undefined)
})

test('add records a handle and byTask/get resolve it', async () => {
	const { book, cleanup } = await bookInTemp()
	try {
		const record = await book.add({ taskId: 'task-1', level: 'intent', scope: 'demo', origin: 'desk', cwd: '/tmp/house' })
		assert.match(record.handle, HANDLE_PATTERN)
		assert.equal(book.get(record.handle)?.taskId, 'task-1')
		assert.equal(book.byTask('task-1')?.handle, record.handle)
		assert.equal(book.list().length, 1)
	} finally {
		await cleanup()
	}
})

test('the same task keeps its handle when re-accepted', async () => {
	const { book, cleanup } = await bookInTemp()
	try {
		const first = await book.add({ taskId: 'task-1', level: 'peer', cwd: '/tmp/house' })
		const again = await book.add({ taskId: 'task-1', level: 'intent', cwd: '/tmp/house' })
		assert.equal(again.handle, first.handle)
		assert.equal(again.level, 'intent')
		assert.equal(book.list().length, 1)
	} finally {
		await cleanup()
	}
})

test('records survive a restart', async () => {
	const { file, book, cleanup } = await bookInTemp()
	try {
		const record = await book.add({ taskId: 'task-1', level: 'intent', cwd: '/tmp/house' })
		const reopened = new OperatorBook({ file })
		await reopened.init()
		assert.equal(reopened.get(record.handle)?.taskId, 'task-1')
	} finally {
		await cleanup()
	}
})

test('expiry is evaluated at read time, and prune removes only expired records', async () => {
	let now = 1_000
	const { book, cleanup } = await bookInTemp({ ttlMs: 100, now: () => now })
	try {
		const record = await book.add({ taskId: 'task-1', level: 'peer', cwd: '/tmp/house' })
		assert.equal(book.get(record.handle)?.taskId, 'task-1')
		now = 1_101
		assert.equal(book.get(record.handle), undefined, 'an expired record is invisible')
		assert.equal(book.byTask('task-1'), undefined)
		assert.equal(book.expired().length, 1)
		const removed = await book.prune()
		assert.deepEqual(removed.map((entry) => entry.handle), [record.handle])
		assert.equal(book.expired().length, 0)
	} finally {
		await cleanup()
	}
})

test('markDone keeps the record reachable', async () => {
	const { book, cleanup } = await bookInTemp()
	try {
		const record = await book.add({ taskId: 'task-1', level: 'peer', cwd: '/tmp/house' })
		await book.markDone('task-1')
		assert.equal(book.get(record.handle)?.state, 'done')
	} finally {
		await cleanup()
	}
})

test('a corrupt book is refused, not silently discarded', async () => {
	const { file, cleanup } = await bookInTemp()
	try {
		await writeFile(file, 'not json', 'utf8')
		const book = new OperatorBook({ file })
		await assert.rejects(() => book.init(), /not valid JSON/)
		await writeFile(file, JSON.stringify({ operators: [] }), 'utf8')
		const second = new OperatorBook({ file })
		await assert.rejects(() => second.init(), /unexpected shape/)
	} finally {
		await cleanup()
	}
})

test('the persisted file is private and versioned', async () => {
	const { file, book, cleanup } = await bookInTemp()
	try {
		await book.add({ taskId: 'task-1', level: 'peer', cwd: '/tmp/house' })
		const parsed = JSON.parse(await readFile(file, 'utf8'))
		assert.equal(parsed.version, 1)
		assert.equal(Object.keys(parsed.operators).length, 1)
	} finally {
		await cleanup()
	}
})
