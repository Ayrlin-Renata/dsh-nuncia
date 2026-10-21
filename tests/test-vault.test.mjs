/**
 * Tests for the vault wiring: lib/secrets.js plus the plugin's
 * loadVaultIntoEnvironment().
 *
 * The behaviour that matters is "the vault fills the environment, and the
 * environment still wins" — because everything downstream (the bearer, the
 * pairing secret) already reads process.env.
 *
 * Run: node --test tests/test-vault.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { loadVaultIntoEnvironment } from '../lib/index.js'
import { writeSecretsFile } from '../lib/secrets.js'

const KEY = 'vault passphrase'

async function scratch() {
	const dir = await mkdtemp(join(tmpdir(), 'nuncia-vault-'))
	return {
		dir,
		file: join(dir, 'secrets.enc'),
		audit: join(dir, 'secrets-access.log'),
		cleanup: async () => { await rm(dir, { recursive: true, force: true }) },
	}
}

test('the vault fills the environment for the names it holds', async () => {
	const { file, audit, cleanup } = await scratch()
	try {
		writeSecretsFile(file, { NUNCIA_PAIRING_SECRET: 'from-vault', NUNCIA_ADMIN_TOKEN: 'admin-from-vault' }, KEY)
		const env = { VAULT_KEY: KEY }
		const result = loadVaultIntoEnvironment({ file, auditFile: audit, keyEnv: 'VAULT_KEY', env, logger: { info: () => {}, warn: () => {} } })
		assert.equal(result.loaded, true)
		assert.equal(env.NUNCIA_PAIRING_SECRET, 'from-vault')
		assert.equal(env.NUNCIA_ADMIN_TOKEN, 'admin-from-vault')
	} finally {
		await cleanup()
	}
})

test('the environment wins over the vault', async () => {
	const { file, audit, cleanup } = await scratch()
	try {
		writeSecretsFile(file, { NUNCIA_PAIRING_SECRET: 'from-vault' }, KEY)
		const env = { NUNCIA_PAIRING_SECRET: 'from-environment', VAULT_KEY: KEY }
		loadVaultIntoEnvironment({ file, auditFile: audit, keyEnv: 'VAULT_KEY', env, logger: { info: () => {}, warn: () => {} } })
		assert.equal(env.NUNCIA_PAIRING_SECRET, 'from-environment', 'the vault overwrote a deliberate override')
	} finally {
		await cleanup()
	}
})

test('no key means no vault and no failure', async () => {
	const { file, audit, cleanup } = await scratch()
	try {
		const env = {}
		const result = loadVaultIntoEnvironment({ file, auditFile: audit, keyEnv: 'VAULT_KEY', env: {}, logger: { info: () => {}, warn: () => {} } })
		assert.equal(result.loaded, false)
		assert.equal(result.reason, 'no-key')
		assert.equal(env.NUNCIA_PAIRING_SECRET, undefined)
	} finally {
		await cleanup()
	}
})

test('a wrong key is reported, not fatal', async () => {
	const { file, audit, cleanup } = await scratch()
	try {
		writeSecretsFile(file, { NUNCIA_PAIRING_SECRET: 'x' }, KEY)
		const env = { VAULT_KEY: 'wrong' }
		const result = loadVaultIntoEnvironment({ file, auditFile: audit, keyEnv: 'VAULT_KEY', env, logger: { info: () => {}, warn: () => {} } })
		assert.equal(result.loaded, false)
		assert.match(result.reason, /does not open/)
		assert.equal(env.NUNCIA_PAIRING_SECRET, undefined)
	} finally {
		await cleanup()
	}
})

test('opening the vault is recorded in the audit log', async () => {
	const { file, audit, cleanup } = await scratch()
	try {
		writeSecretsFile(file, { NUNCIA_PAIRING_SECRET: 'x' }, KEY)
		loadVaultIntoEnvironment({ file, auditFile: audit, keyEnv: 'VAULT_KEY', env: { VAULT_KEY: KEY }, logger: { info: () => {}, warn: () => {} } })
		const log = await readFile(audit, 'utf8')
		assert.match(log, /source=vault:env:VAULT_KEY/)
		assert.match(log, /NUNCIA_PAIRING_SECRET/)
	} finally {
		await cleanup()
	}
})
