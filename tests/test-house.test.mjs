/**
 * Tests for lib/house.js.
 *
 * The house is a directory plus a git history. What matters: the seed is
 * written once and never clobbered, every edit is one commit, an edit that
 * changes nothing is not a commit, and a host without git still serves rules.
 *
 * Run: node --test test-house.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createHouse, expandHome, sanitizeSummary, SEED_RULES } from '../lib/house.js'

async function houseInTemp(options = {}) {
	const dir = await mkdtemp(join(tmpdir(), 'nuncia-house-'))
	const house = createHouse({ workspace: join(dir, 'house'), ...options })
	const ensured = await house.ensure()
	return { dir, house, ensured, async cleanup() { await rm(dir, { recursive: true, force: true }) } }
}

test('ensure seeds the rules once and makes an initial commit', async () => {
	const { house, ensured, cleanup } = await houseInTemp()
	try {
		assert.equal(ensured.rulesCreated, true)
		assert.equal(ensured.git.ok, true, `git should be usable: ${ensured.git.reason}`)
		const rules = await house.read()
		assert.equal(rules, SEED_RULES)
		const log = await house.log()
		assert.equal(log.length, 1)
		assert.match(log[0].subject, /house rules: initial/)
	} finally {
		await cleanup()
	}
})

test('ensure never overwrites an edited rules file', async () => {
	const { house, cleanup } = await houseInTemp()
	try {
		await house.write('# House rules\n\nedited by the human\n', { summary: 'human edit' })
		const again = await house.ensure()
		assert.equal(again.rulesCreated, false)
		assert.equal(await house.read(), '# House rules\n\nedited by the human\n')
	} finally {
		await cleanup()
	}
})

test('write commits once and an unchanged write is a no-op', async () => {
	const { house, cleanup } = await houseInTemp()
	try {
		const first = await house.write('# House rules\n\none\n', { summary: 'first body' })
		assert.equal(first.changed, true)
		assert.equal(first.ok, true)
		const second = await house.write('# House rules\n\none\n', { summary: 'same body' })
		assert.equal(second.changed, false)
		const log = await house.log()
		assert.equal(log.length, 2, 'seed + one edit')
		assert.match(log[0].subject, /first body/)
	} finally {
		await cleanup()
	}
})

test('commit summary is a single sanitized line', async () => {
	const { house, cleanup } = await houseInTemp()
	try {
		await house.write('# House rules\n\nx\n', { summary: 'multi\nline   summary\there' })
		const log = await house.log()
		assert.equal(log[0].subject, 'multi line summary here')
		const raw = await readFile(join(house.workspace, 'HOUSE-RULES.md'), 'utf8')
		assert.equal(raw, '# House rules\n\nx\n', 'the body is stored verbatim')
	} finally {
		await cleanup()
	}
})

test('a repository keeps its own identity even without a global git user', async () => {
	const { house, cleanup } = await houseInTemp()
	try {
		const log = await house.log()
		assert.ok(log.length >= 1)
		// The commit exists at all only because the house set a local identity.
		const { execFile } = await import('node:child_process')
		const author = await new Promise((resolve) => {
			execFile('git', ['log', '-1', '--pretty=%an <%ae>'], { cwd: house.workspace }, (error, stdout) => resolve(String(stdout ?? '').trim()))
		})
		assert.equal(author, 'nuncia house <nuncia@localhost>')
	} finally {
		await cleanup()
	}
})

test('a rules file written outside git is picked up on the next ensure', async () => {
	const { dir, house, cleanup } = await houseInTemp()
	try {
		await writeFile(join(house.workspace, 'HOUSE-RULES.md'), '# House rules\n\nlocal edit\n', 'utf8')
		const again = await house.ensure()
		assert.equal(again.git.ok, true)
		const log = await house.log()
		assert.ok(log.some((entry) => /track existing file/.test(entry.subject)), 'the local edit is committed, not lost')
		assert.equal(await house.read(), '# House rules\n\nlocal edit\n')
	} finally {
		await cleanup()
	}
})

test('expandHome handles ~ and leaves absolute paths alone', () => {
	assert.notEqual(expandHome('~/x'), '~/x')
	assert.ok(expandHome('~/x').endsWith('x'))
	assert.equal(expandHome('C:\\temp\\x'), 'C:\\temp\\x')
	assert.equal(expandHome('/var/x'), '/var/x')
})

test('sanitizeSummary collapses whitespace and bounds length', () => {
	assert.equal(sanitizeSummary('  a\n b  '), 'a b')
	assert.equal(sanitizeSummary(''), undefined)
	assert.equal(sanitizeSummary(undefined), undefined)
	assert.equal(sanitizeSummary('x'.repeat(200)).length, 98)
})

test('a rulesFile that is a path is refused at construction', () => {
	assert.throws(() => createHouse({ workspace: '/tmp/x', rulesFile: '../escape.md' }), /bare file name/)
	assert.throws(() => createHouse({ workspace: 'relative/dir' }), /absolute path/)
})
