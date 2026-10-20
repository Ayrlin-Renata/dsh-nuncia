#!/usr/bin/env node
/**
 * Print the bearer token a node derives from its pairing secret.
 *
 * Scope note (DESIGN §20.1): the pairing secret now derives *only* the bearer
 * token. Authority envelopes are signed with a per-node Ed25519 key, so this
 * token is a connection credential — holding it grants no ability to claim user
 * intent.
 *
 * The derivation includes the node name, so `--node avd` prints the token the
 * `avd` node itself serves. Without `--node` the historical (pre-v2) derivation
 * is printed, which only matches nodes that still omit a node name.
 *
 *   node bin/nuncia-token.js --node avd          # reads NUNCIA_PAIRING_SECRET
 *   node bin/nuncia-token.js <secret> --node avd
 *   NUNCIA_PAIRING_SECRET=... node bin/nuncia-token.js --node avd --url
 *
 * Exit codes: 0 printed, 1 no secret available.
 */

import { deriveBearerToken } from '../lib/authority.js'

const args = process.argv.slice(2)
const wantUrl = args.includes('--url')
const nodeIndex = args.indexOf('--node')
const nodeName = nodeIndex === -1 ? undefined : args[nodeIndex + 1]
const secret = args.find((a, i) => !a.startsWith('--') && !(nodeIndex !== -1 && i === nodeIndex + 1)) ?? process.env.NUNCIA_PAIRING_SECRET

if (secret === undefined || secret === '') {
	console.error('nuncia-token: no pairing secret (pass one as an argument or set NUNCIA_PAIRING_SECRET)')
	process.exit(1)
}
if (nodeIndex !== -1 && (nodeName === undefined || nodeName.startsWith('--'))) {
	console.error('nuncia-token: --node needs a node name (the value of authority.nodeName on that node)')
	process.exit(1)
}
if (nodeName === undefined) {
	console.error('nuncia-token: warning: no --node given, printing the pre-v2 derivation (authority-bearing nodes derive per name)')
}

const token = deriveBearerToken(secret, nodeName)
if (wantUrl) {
	console.log('http://127.0.0.1:4123/.well-known/agent.json')
	console.error(`authorization: Bearer ${token}`)
} else {
	console.log(token)
}
