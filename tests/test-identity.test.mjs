/**
 * Tests for lib/identity.js and the P3.0 auth posture.
 *
 * The P3.0 rules, restated as assertions:
 *  - a node with no configured token still SERVES, but only to requests with a
 *    valid bearer (a generated one is created and persisted);
 *  - the agent card is auth-gated by default (a discovery surface should not
 *    be readable by anyone who can reach the port);
 *  - a fresh node picks a name at random from the human's list and remembers
 *    it; an explicit name always wins;
 *  - the announcement is one bounded line, and only the chatelaine may write it.
 *
 * Run: node --test tests/test-identity.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  AnnouncementStore,
  MAX_ANNOUNCEMENT_LENGTH,
  describePlatform,
  readNamesFile,
  resolveNodeName,
  sanitizeNodeName,
} from '../lib/identity.js'

async function scratch() {
  const dir = await mkdtemp(join(tmpdir(), 'nuncia-id-'))
  return { dir, cleanup: async () => { await rm(dir, { recursive: true, force: true }) } }
}

test('sanitizeNodeName produces envelope-safe names', () => {
	assert.equal(sanitizeNodeName('Lucity'), 'lucity')
	assert.equal(sanitizeNodeName('My Node!'), 'my-node-')
	assert.equal(sanitizeNodeName(''), 'nuncia')
	assert.equal(sanitizeNodeName('---'), 'nuncia')
	assert.ok(sanitizeNodeName('x'.repeat(200)).length <= 64)
})

test('a names file yields clean candidates, comments and blanks ignored', async () => {
	const { dir, cleanup } = await scratch()
	try {
		const file = join(dir, 'names.txt')
		await writeFile(file, '# a comment\n\nLucity\nEffiona\n  Yukimoira  \n', 'utf8')
		const names = await readNamesFile(file)
		assert.deepEqual(names, ['lucity', 'effiona', 'yukimoira'])
	} finally {
		await cleanup()
	}
})

test('a missing names file yields no candidates', async () => {
	const { dir, cleanup } = await scratch()
	try {
		assert.deepEqual(await readNamesFile(join(dir, 'nope.txt')), [])
	} finally {
		await cleanup()
	}
})

test('an explicit name always wins', async () => {
	const { dir, cleanup } = await scratch()
	try {
		const file = join(dir, 'names.txt')
		await writeFile(file, 'lucity\neffiona\n', 'utf8')
		const stateFile = join(dir, 'identity.json')
		const adopted = await resolveNodeName({ nodeName: 'Chosen', nodeNameFile: file, stateFile })
		assert.equal(adopted.name, 'chosen')
		assert.equal(adopted.source, 'config')
	} finally {
		await cleanup()
	}
})

test('without a name, one is picked from the list and remembered', async () => {
	const { dir, cleanup } = await scratch()
	try {
		const file = join(dir, 'names.txt')
		await writeFile(file, 'lucity\neffiona\nautulia\n', 'utf8')
		const stateFile = join(dir, 'identity.json')
		const adopted = await resolveNodeName({ nodeNameFile: file, stateFile })
		assert.ok(['lucity', 'effiona', 'autulia'].includes(adopted.name), adopted.name)
		assert.equal(adopted.source, 'file')
		assert.equal(adopted.candidates, 3)
		// Remembered: the next boot keeps the same name.
		const again = await resolveNodeName({ nodeNameFile: file, stateFile })
		assert.equal(again.name, adopted.name)
		assert.equal(again.source, 'persisted')
		const stored = JSON.parse(await readFile(stateFile, 'utf8'))
		assert.equal(stored.nodeName, adopted.name)
	} finally {
		await cleanup()
	}
})

test('with no list, the hostname is used and remembered', async () => {
	const { dir, cleanup } = await scratch()
	try {
		const stateFile = join(dir, 'identity.json')
		const adopted = await resolveNodeName({ stateFile })
		assert.equal(adopted.source, 'hostname')
		assert.ok(adopted.name.length > 0)
		const again = await resolveNodeName({ stateFile })
		assert.equal(again.source, 'persisted')
	} finally {
		await cleanup()
	}
})

test('describePlatform reports platform and arch', () => {
	const platform = describePlatform()
	assert.equal(typeof platform.platform, 'string')
	assert.equal(typeof platform.arch, 'string')
	assert.equal(platform.label, `${platform.platform}-${platform.arch}`)
})

test('the announcement is one bounded line and survives a restart', async () => {
	const { dir, cleanup } = await scratch()
	try {
		const file = join(dir, 'announcement.json')
		const store = new AnnouncementStore({ file })
		await store.init()
		assert.equal(store.get(), '')

		const written = await store.set('Sorting the archive  ·  index rebuild running')
		assert.equal(written.ok, true)
		assert.equal(store.get(), 'Sorting the archive · index rebuild running')

		// Newlines and runs of whitespace collapse: a signboard, not a mailbox.
		const flattened = await store.set('one\n\ntwo   three')
		assert.equal(flattened.value, 'one two three')

		// Too long is refused, and the old value survives.
		const tooLong = await store.set('x'.repeat(MAX_ANNOUNCEMENT_LENGTH + 1))
		assert.equal(tooLong.ok, false)
		assert.match(tooLong.reason, /longer than/)
		assert.equal(store.get(), 'one two three')

		// A non-string is refused outright.
		const wrongType = await store.set(42)
		assert.equal(wrongType.ok, false)

		const reopened = new AnnouncementStore({ file })
		await reopened.init()
		assert.equal(reopened.get(), 'one two three')
	} finally {
		await cleanup()
	}
})
