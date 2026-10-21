/**
 * Tests for lib/secrets.js — the encrypted secret store.
 *
 * The properties that matter, in order of how much they matter:
 *   1. A wrong key does not decrypt (and says so clearly).
 *   2. A tampered file is refused, not silently mis-decrypted.
 *   3. The file on disk contains no plaintext secret.
 *   4. Access is recorded (the tripwire).
 *   5. Rotation replaces the value without changing the envelope's shape.
 *
 * Run: node --test tests/test-secrets.test.mjs
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
	decryptSecrets,
	encryptSecrets,
	readSecretAccess,
	readSecretsFile,
	recordSecretAccess,
	resolvePassphrase,
	writeSecretsFile,
} from '../lib/secrets.js'

const KEY = 'correct horse battery staple'
const OTHER = 'a different passphrase entirely'

async function scratch() {
	const dir = await mkdtemp(join(tmpdir(), 'nuncia-secrets-'))
	return { dir, file: join(dir, 'secrets.enc'), log: join(dir, 'secrets-access.log'), cleanup: async () => { await rm(dir, { recursive: true, force: true }) } }
}

test('a secret round-trips through the envelope', () => {
	const values = { NUNCIA_PAIRING_SECRET: 'pairing-value', NUNCIA_ADMIN_TOKEN: 'admin-value' }
	const envelope = encryptSecrets(values, KEY)
	assert.equal(envelope.version, 1)
	assert.equal(envelope.cipher, 'aes-256-gcm')
	assert.equal(envelope.kdf.name, 'scrypt')
	assert.deepEqual(decryptSecrets(envelope, KEY), values)
})

test('a wrong key is refused with a clear message', () => {
	const envelope = encryptSecrets({ A: 'b' }, KEY)
	assert.throws(() => decryptSecrets(envelope, OTHER), /does not open/)
})

test('a tampered file is refused, not mis-decrypted', () => {
	const envelope = encryptSecrets({ A: 'b' }, KEY)
	const bytes = Buffer.from(envelope.data, 'base64url')
	bytes[0] ^= 0xff
	envelope.data = bytes.toString('base64url')
	assert.throws(() => decryptSecrets(envelope, KEY), /does not open/)
})

test('the file on disk contains no plaintext secret', async () => {
	const { file, cleanup } = await scratch()
	try {
		const secret = 'super-secret-pairing-value'
		writeSecretsFile(file, { NUNCIA_PAIRING_SECRET: secret }, KEY)
		const raw = await readFile(file, 'utf8')
		assert.equal(raw.includes(secret), false, 'the plaintext leaked into the file')
		assert.equal(raw.includes('NUNCIA_PAIRING_SECRET'), false, 'even the key name leaked')
		// …and it still opens with the right key.
		assert.deepEqual(readSecretsFile(file, KEY), { NUNCIA_PAIRING_SECRET: secret })
	} finally {
		await cleanup()
	}
})

test('a missing secrets file says so instead of throwing ENOENT raw', async () => {
	const { dir, cleanup } = await scratch()
	try {
		assert.throws(() => readSecretsFile(join(dir, 'nope.enc'), KEY), /cannot read the secrets file/)
	} finally {
		await cleanup()
	}
})

test('access is recorded, newest first', async () => {
	const { log, cleanup } = await scratch()
	try {
		recordSecretAccess(log, { source: 'boot', values: ['NUNCIA_PAIRING_SECRET'] })
		recordSecretAccess(log, { source: 'admin', values: ['NUNCIA_ADMIN_TOKEN'], reason: 'panel' })
		const lines = readSecretAccess(log)
		assert.equal(lines.length, 2)
		assert.match(lines[0], /source=admin/)
		assert.match(lines[0], /reason=panel/)
		assert.match(lines[1], /source=boot/)
	} finally {
		await cleanup()
	}
})

test('a broken audit path never breaks the caller', () => {
	// A path that cannot be created (a file where a directory is expected).
	recordSecretAccess('/proc/nonexistent-dir-xyz/audit.log', { source: 'test' })
	assert.doesNotThrow(() => readSecretAccess('/proc/nonexistent-dir-xyz/audit.log'))
})

test('rotation replaces the value in place', async () => {
	const { file, cleanup } = await scratch()
	try {
		writeSecretsFile(file, { NUNCIA_ADMIN_TOKEN: 'first' }, KEY)
		writeSecretsFile(file, { NUNCIA_ADMIN_TOKEN: 'second' }, KEY)
		assert.deepEqual(readSecretsFile(file, KEY), { NUNCIA_ADMIN_TOKEN: 'second' })
	} finally {
		await cleanup()
	}
})

test('the passphrase resolves from the environment first, then a file', async () => {
	const { dir, file, cleanup } = await scratch()
	try {
		const keyFile = join(dir, 'key')
		await writeFile(keyFile, 'from-file\n', 'utf8')
		assert.deepEqual(
			resolvePassphrase({ envName: 'NOPE', keyFile, env: {} }),
			{ passphrase: 'from-file', source: `file:${keyFile}` },
		)
		assert.deepEqual(
			resolvePassphrase({ envName: 'YES', keyFile, env: { YES: 'from-env' } }),
			{ passphrase: 'from-env', source: 'env:YES' },
		)
		assert.deepEqual(resolvePassphrase({ envName: 'NOPE', keyFile, env: {} }).passphrase, 'from-file')
	} finally {
		await cleanup()
	}
})

test('an empty passphrase never derives a key', () => {
	assert.throws(() => encryptSecrets({ A: 'b' }, ''), /passphrase is required/)
})

//
// The tripwire must be a SIBLING of the vault, so the plugin, the daemon and
// the CLI all land in the same file with no configuration at all.
test('the audit path is a sibling of the vault', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'nuncia-sibling-'));
  const vault = join(dir, 'secrets.enc');
  await writeSecretsFile(vault, { NUNCIA_ADMIN_TOKEN: 'token' }, 'pass');
  const audit = join(dir, 'secrets-access.log');
  await recordSecretAccess(audit, { source: 'test', values: ['NUNCIA_ADMIN_TOKEN'], reason: 'sibling' });
  const line = await readFile(audit, 'utf8');
  assert.match(line, /secrets=\[NUNCIA_ADMIN_TOKEN\]/);
  await rm(dir, { recursive: true, force: true });
});
