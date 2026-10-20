#!/usr/bin/env node
/**
 * Print the bearer token a paired node derives from its pairing secret.
 *
 * A paired node uses one secret for two capabilities: envelope signing and the
 * bearer token on its own A2A endpoint. That means the token is never copied
 * between machines — it is derived. This helper prints it so you can curl a
 * node without digging through its profile config.
 *
 *   node bin/nuncia-token.js                       # reads NUNCIA_PAIRING_SECRET
 *   node bin/nuncia-token.js <secret>              # explicit secret
 *   NUNCIA_PAIRING_SECRET=... node bin/nuncia-token.js --url avd
 *
 * Exit codes: 0 printed, 1 no secret available.
 */

import { deriveBearerToken } from '../lib/authority.js'

const args = process.argv.slice(2)
const wantUrl = args.includes('--url')
const secret = args.find((a) => !a.startsWith('--')) ?? process.env.NUNCIA_PAIRING_SECRET

if (secret === undefined || secret === '') {
	console.error('nuncia-token: no pairing secret (pass one as an argument or set NUNCIA_PAIRING_SECRET)')
	process.exit(1)
}

const token = deriveBearerToken(secret)
if (wantUrl) {
	console.log(`http://127.0.0.1:4123/.well-known/agent.json`)
	console.error(`authorization: Bearer ${token}`)
} else {
	console.log(token)
}
