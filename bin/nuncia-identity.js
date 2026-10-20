#!/usr/bin/env node
/**
 * Print this node's authority identity for pairing, and inspect peer keys.
 *
 * Pairing is deliberately a *public* exchange: each side sends its public key,
 * never a shared secret. That is what makes verification one-way — a peer that
 * can check your grants holds no key that could produce them.
 *
 *   node bin/nuncia-identity.js                       # this node's identity
 *   node bin/nuncia-identity.js --name avd            # label the peers: snippet
 *   node bin/nuncia-identity.js --check <base64key>   # what is this key?
 *   node bin/nuncia-identity.js --check <key> --kid abc123   # verify a pin
 *
 * Key resolution matches the plugin: --file, then $NUNCIA_NODE_KEY_FILE, then
 * --key / $NUNCIA_NODE_KEY (inline base64url PKCS8), then ~/.sylvia/nuncia-node.key.
 * A missing file is created (mode 0600) exactly as the plugin would.
 *
 * Exit codes: 0 ok, 1 unusable input, 2 pin mismatch.
 */

import { homedir } from 'node:os'
import { join } from 'node:path'

import { exportPublicKey, fingerprintOf, keyIdOf, parsePublicKey } from '../lib/authority.js'
import { loadOrCreateNodeKey } from '../lib/keys.js'

const args = process.argv.slice(2)
const valueOf = (flag) => {
	const index = args.indexOf(flag)
	return index === -1 ? undefined : args[index + 1]
}

const check = valueOf('--check')
const wantKid = valueOf('--kid')
const name = valueOf('--name')

if (check !== undefined) {
	const key = parsePublicKey(check)
	if (key === undefined) {
		console.error('nuncia-identity: not an Ed25519 public key (expected base64url SPKI or PEM)')
		process.exit(1)
	}
	const kid = keyIdOf(key)
	console.log(`kid:         ${kid}`)
	console.log(`fingerprint: ${fingerprintOf(key)}`)
	console.log(`publicKey:   ${exportPublicKey(key)}`)
	if (wantKid !== undefined) {
		if (wantKid !== kid) {
			console.error(`nuncia-identity: PIN MISMATCH — expected kid ${wantKid}, key hashes to ${kid}`)
			process.exit(2)
		}
		console.log('pin:         ok')
	}
	process.exit(0)
}

const file = valueOf('--file') ?? process.env.NUNCIA_NODE_KEY_FILE ?? join(homedir(), '.sylvia', 'nuncia-node.key')
const inline = valueOf('--key') ?? process.env.NUNCIA_NODE_KEY

let nodeKey
try {
	nodeKey = loadOrCreateNodeKey({
		file,
		...(inline === undefined ? {} : { inline }),
		onWarn: (message) => console.error(`[nuncia-identity] ${message}`),
	})
} catch (error) {
	console.error(`nuncia-identity: ${error instanceof Error ? error.message : String(error)}`)
	process.exit(1)
}

const publicKeyText = exportPublicKey(nodeKey.publicKey)
console.log(`node:        ${name ?? '(set authority.nodeName)'}`)
console.log(`kid:         ${nodeKey.kid}`)
console.log(`fingerprint: ${nodeKey.fingerprint}`)
console.log(`publicKey:   ${publicKeyText}`)
console.log(`source:      ${nodeKey.source}${nodeKey.file === undefined ? '' : ` (${nodeKey.file})`}`)
console.log('')
console.log('Paste into the peer node\'s authority.peers:')
console.log('  peers:')
console.log(`    - name: ${name ?? '<this-node-name>'}`)
console.log(`      publicKey: ${publicKeyText}`)
console.log(`      kid: ${nodeKey.kid}`)
