/**
 * Tests for lib/keys.js — per-node identity storage.
 *
 * Run: node --test tests/test-keys.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, statSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describeNodeKey, exportPrivateKey, loadOrCreateNodeKey, parsePrivateKey } from '../lib/keys.js'

const scratch = () => mkdtempSync(join(tmpdir(), 'nuncia-keys-'))

test('generates a key file with mode 0600 and reloads the same identity', () => {
	const dir = scratch()
	const file = join(dir, 'nuncia-node.key')
	const warnings = []
	const first = loadOrCreateNodeKey({ file, onWarn: (m) => warnings.push(m) })
	assert.equal(first.source, 'generated')
	assert.equal(typeof first.kid, 'string')
	assert.equal(first.kid.length, 16)
	// POSIX modes are not honored on Windows (stat reports 0666 regardless).
	if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600)
	assert.ok(warnings.some((w) => /generated a new node identity/.test(w)))

	const second = loadOrCreateNodeKey({ file })
	assert.equal(second.source, 'file')
	assert.equal(second.kid, first.kid)
	assert.equal(second.publicKeyText, first.publicKeyText)
	assert.equal(second.fingerprint, first.fingerprint)
	assert.equal(first.publicKeyText, first.publicKeyText.trim(), 'public key is single-line paste material')
	assert.ok(!/\s/.test(first.publicKeyText), 'public key has no whitespace')
})

test('an existing key that cannot be parsed is fatal and is left untouched', () => {
	const dir = scratch()
	const file = join(dir, 'nuncia-node.key')
	const garbage = 'not a key at all'
	writeFileSync(file, garbage, { mode: 0o600 })
	assert.throws(() => loadOrCreateNodeKey({ file }), /exists but is not a readable Ed25519 private key/)
	assert.equal(readFileSync(file, 'utf8'), garbage, 'refuses to overwrite a peer-pinned identity')
})

test('a loose file mode is tightened to 0600', () => {
	const dir = scratch()
	const file = join(dir, 'nuncia-node.key')
	const { privateKey } = generateKeyPairSync('ed25519')
	writeFileSync(file, exportPrivateKey(privateKey), { mode: 0o644 })
	chmodSync(file, 0o644)
	const warnings = []
	const loaded = loadOrCreateNodeKey({ file, onWarn: (m) => warnings.push(m) })
	assert.equal(loaded.source, 'file')
	if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600)
	assert.ok(warnings.some((w) => /tightened to 600/.test(w)))
})

test('inline config wins over the file and over the environment', () => {
	const dir = scratch()
	const file = join(dir, 'nuncia-node.key')
	const onDisk = loadOrCreateNodeKey({ file })

	const inlineKey = describeNodeKey(generateKeyPairSync('ed25519').privateKey)
	process.env.NUNCIA_NODE_KEY = exportPrivateKey(describeNodeKey(generateKeyPairSync('ed25519').privateKey).privateKey)
	const fromConfig = loadOrCreateNodeKey({ file, inline: exportPrivateKey(inlineKey.privateKey) })
	assert.equal(fromConfig.source, 'config')
	assert.equal(fromConfig.kid, inlineKey.kid)
	assert.notEqual(fromConfig.kid, onDisk.kid)

	const fromEnv = loadOrCreateNodeKey({ file })
	assert.equal(fromEnv.source, 'env')
	assert.notEqual(fromEnv.kid, inlineKey.kid)
	delete process.env.NUNCIA_NODE_KEY
})

test('a non-Ed25519 inline value is rejected with an explanation', () => {
	const dir = scratch()
	const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
	assert.throws(
		() => loadOrCreateNodeKey({ file: join(dir, 'k'), inline: exportPrivateKey(rsa) }),
		/is set but is not an Ed25519 private key/,
	)
	assert.equal(parsePrivateKey(exportPrivateKey(rsa)), undefined)
})

test('no file configured yields an ephemeral identity and a warning', () => {
	const warnings = []
	const a = loadOrCreateNodeKey({ onWarn: (m) => warnings.push(m) })
	const b = loadOrCreateNodeKey({ onWarn: () => {} })
	assert.equal(a.source, 'generated')
	assert.equal(a.file, undefined)
	assert.notEqual(a.kid, b.kid, 'two ephemeral identities are distinct')
	assert.ok(warnings.some((w) => /will not survive a restart/.test(w)))
})

