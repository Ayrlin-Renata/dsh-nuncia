#!/usr/bin/env node
/**
 * nuncia-secrets — manage the node's encrypted secret vault.
 *
 * The vault holds the pairing secret and the admin token. Only the
 * passphrase lives in the environment; the vault holds the ciphertext.
 *
 *   node bin/nuncia-secrets.js set NUNCIA_PAIRING_SECRET=… NUNCIA_ADMIN_TOKEN=…
 *   node bin/nuncia-secrets.js get            # print the names only
 *   node bin/nunca-secrets.js show NUNCIA_ADMIN_TOKEN
 *   node bin/nuncia-secrets.js rotate         # re-encrypt with the current key
 *   node bin/nuncia-secrets.js audit           # the access trail
 *
 * The passphrase comes from $SYLVIA_SECRET_KEY (or --key-env NAME). It is
 * never written to the vault and never printed.
 */
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

import {
	DEFAULT_SECRETS_KEY_ENV,
	readSecretAccess,
	readSecretsFile,
	resolvePassphrase,
	writeSecretsFile,
} from '../lib/secrets.js'

const args = process.argv.slice(2)
const command = args[0] ?? 'help'

const keyEnv = (() => {
	const flag = args.indexOf('--key-env')
	return flag >= 0 ? args[flag + 1] : DEFAULT_SECRETS_KEY_ENV
})()
const fileFlag = args.indexOf('--file')
const file = fileFlag >= 0 ? args[fileFlag + 1] : join(homedir(), '.sylvia', 'secrets.enc')
const auditFile = join(file.replace(/\.enc$/, ''), 'secrets-access.log')
const auditFileFlag = args.indexOf('--audit')
const audit = auditFileFlag >= 0 ? args[auditFileFlag + 1] : join(homedir(), '.sylvia', 'secrets-access.log')

const { passphrase, source } = resolvePassphrase({ envName: keyEnv })
if (passphrase === undefined) {
	console.error(`nuncia-secrets: no passphrase in ${keyEnv} — export it, or pass --key-env NAME`)
	process.exit(2)
}

switch (command) {
	case 'set': {
		const pairs = args.slice(1).filter((value) => value.includes('=') && !value.startsWith('--'))
		if (pairs.length === 0) {
			console.error('nuncia-secrets: set needs NAME=value pairs')
			process.exit(2)
		}
		const values = {}
		for (const pair of pairs) {
			const index = pair.indexOf('=')
			values[pair.slice(0, index)] = pair.slice(index + 1)
		}
		// Merge with what is already there, so one secret can be rotated
		// without re-supplying the others.
		let existing = {}
		if (existsSync(file)) {
			try { existing = readSecretsFile(file, passphrase) } catch { existing = {} }
		}
		const merged = { ...existing, ...values }
		const written = writeSecretsFile(file, merged, passphrase)
		console.log(`wrote ${Object.keys(merged).length} secret(s) to ${written.file} (key from ${source})`)
		break
	}
	case 'get': {
		const values = readSecretsFile(file, passphrase)
		for (const name of Object.keys(values)) console.log(name)
		break
	}
	case 'show': {
		const name = args[1]
		if (name === undefined) {
			console.error('nuncia-secrets: show needs a name')
			process.exit(2)
		}
		const values = readSecretsFile(file, passphrase)
		if (values[name] === undefined) {
			console.error(`nuncia-secrets: no such secret: ${name}`)
			process.exit(1)
		}
		console.log(values[name])
		break
	}
	case 'rotate': {
		// Re-encrypt with the current passphrase. The values do not change; the
		// salt and nonce do, so the ciphertext is fresh.
		const values = readSecretsFile(file, passphrase)
		const written = writeSecretsFile(file, values, passphrase)
		console.log(`re-encrypted ${Object.keys(values).length} secret(s) in ${written.file}`)
		break
	}
	case 'audit': {
		const lines = readSecretAccess(audit, 40)
		if (lines.length === 0) console.log('no access recorded yet')
		else for (const line of lines) console.log(line)
		break
	}
	case 'path': {
		console.log(file)
		break
	}
	default: {
		console.log('usage: nunia-secrets <set|get|show|rotate|audit|path> [NAME=value…] [--key-env NAME] [--file PATH]')
		process.exit(command === 'help' ? 0 : 2)
	}
}
