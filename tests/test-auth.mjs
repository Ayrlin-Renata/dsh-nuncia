/**
 * Tests for bearer-token resolution and the inline pairing secret.
 *
 * The failure these cover, seen on a GUI-launched harness: enabling authority
 * made the plugin refuse to load with
 *   dsh-nuncia: auth is configured but no bearer token is available
 * because `auth.tokenEnv` named a variable the harness process never had. A
 * paired node already derives a bearer token from the pairing secret (that is
 * what "one secret, two capabilities" means), so requiring a second, separately
 * exported token was a configuration trap. Same for the secret itself: a host
 * whose environment is fixed at launch needs a way to pair without a restart.
 *
 * Run: node tests/test-auth.test.mjs   (exit 0 = all pass)
 */

import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../lib/index.js'
import { deriveBearerToken } from '../lib/authority.js'

let failures = 0
const check = (name, cond, detail = '') => {
	console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
	if (!cond) failures++
}

// Keys and grants must not land in the repo: give every apply() a scratch dir.
const STATE = mkdtempSync(join(tmpdir(), 'nuncia-auth-'))
// The house writes a rules file + a git repo; keep it out of the user's home.
const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-auth-house-'))

const SECRET = 'inline-secret-0123456789-abcdefghij'
const ENV_SECRET = 'env-secret-different-value-9876543210'
delete process.env.NUNCIA_TEST_SECRET

const fakeCtx = () => {
	const listeners = {}
	const ctx = {
		get: () => undefined,
		inject: (_deps, callback) => { callback(ctx) },
		logger: { info: () => {}, warn: () => {}, error: (m) => console.error('[logger.error]', m) },
		on: (name, handler) => { (listeners[name] ??= []).push(handler) },
		effect: (fn) => { fn() },
		emit: () => {},
		listeners,
	}
	return ctx
}

const base = {
	path: '/a2a',
	agentCardPath: '/.well-known/agent.json',
	adminPath: '/a2a/admin',
	host: '127.0.0.1',
	agentPreset: 'standard',
	taskTtlMs: 60000,
	// Node keys and grant files belong in scratch space, never in the repo.
	persistenceRoot: STATE,
	chatelaine: { workspace: HOUSE },
}

// --- 1. inline secret + tokenless auth entirely derives the bearer -----------
await apply(fakeCtx(), {
	...base,
	port: 4205,
	auth: { type: 'bearer' },          // no token, no tokenEnv
	authority: {
		enabled: true,
		nodeName: 'desk',
		pairingSecret: SECRET,          // inline, not from the environment
		pairingSecretEnv: 'NUNCIA_TEST_SECRET',
	},
})

const derived = deriveBearerToken(SECRET, 'desk')
const wrong = deriveBearerToken('some-other-secret-entirely', 'desk')

const unauth = await fetch('http://127.0.0.1:4205/a2a/admin/status', { headers: { connection: 'close' } })
check('endpoint still requires a bearer', unauth.status === 401, `status=${unauth.status}`)

const badToken = await fetch('http://127.0.0.1:4205/a2a/admin/status', {
	headers: { authorization: 'Bearer ' + wrong, connection: 'close' },
})
check('a token from another secret is refused', badToken.status === 401, `status=${badToken.status}`)

const ok = await fetch('http://127.0.0.1:4205/a2a/admin/status', {
	headers: { authorization: 'Bearer ' + derived, connection: 'close' },
})
const status = await ok.json()
check('derived bearer is accepted', ok.status === 200, `status=${ok.status}`)
check('inline secret enabled the authority layer', status.authority?.enabled === true, JSON.stringify(status.authority))
check('node name came from config', status.authority?.nodeName === 'desk', status.authority?.nodeName)

// --- 1b. an exported secret wins over the inline one -----------------------
// A node that CAN export the secret must not be silently overridden by a stale
// value left in a config file.
process.env.NUNCIA_TEST_SECRET = ENV_SECRET
await apply(fakeCtx(), {
	...base,
	port: 4208,
	auth: { type: 'bearer' },
	authority: {
		enabled: true,
		nodeName: 'desk',
		pairingSecret: SECRET,
		pairingSecretEnv: 'NUNCIA_TEST_SECRET',
	},
})
const envDerived = deriveBearerToken(ENV_SECRET, 'desk')
const fromEnv = await fetch('http://127.0.0.1:4208/a2a/admin/status', {
	headers: { authorization: 'Bearer ' + envDerived, connection: 'close' },
})
check('environment secret wins for derivation', fromEnv.status === 200, `status=${fromEnv.status}`)
const inlineRejected = await fetch('http://127.0.0.1:4208/a2a/admin/status', {
	headers: { authorization: 'Bearer ' + derived, connection: 'close' },
})
check('inline secret is not used when the env var is set', inlineRejected.status === 401, `status=${inlineRejected.status}`)

// --- 2. an explicit token still wins over derivation ------------------------
await apply(fakeCtx(), {
	...base,
	port: 4206,
	auth: { type: 'bearer', token: 'explicit-token-wins' },
	authority: { enabled: true, nodeName: 'desk', pairingSecret: SECRET },
})
const explicit = await fetch('http://127.0.0.1:4206/a2a/admin/status', {
	headers: { authorization: 'Bearer explicit-token-wins', connection: 'close' },
})
check('explicit auth.token wins', explicit.status === 200, `status=${explicit.status}`)
const derivedRejected = await fetch('http://127.0.0.1:4206/a2a/admin/status', {
	headers: { authorization: 'Bearer ' + derived, connection: 'close' },
})
check('derived bearer is NOT accepted when a token is pinned', derivedRejected.status === 401, `status=${derivedRejected.status}`)

// --- 3. mount: standalone ignores an available web server -------------------
// A node whose peers use a stable advertised address must actually serve on it;
// mounting on the harness port makes agentCard.url a lie.
const registeredOnHost = []
const hostWithWebServer = fakeCtx()
hostWithWebServer.get = (name) => (name === 'webServer'
	? { register: (route) => { registeredOnHost.push(route.path); return () => {} } }
	: undefined)
await apply(hostWithWebServer, {
	...base,
	port: 4209,
	mount: 'standalone',
	auth: { type: 'bearer' },
	authority: { enabled: true, nodeName: 'desk', pairingSecret: SECRET },
})
check('mount standalone registers nothing on the host server', registeredOnHost.length === 0, JSON.stringify(registeredOnHost))
const ownPort = await fetch('http://127.0.0.1:4209/a2a/admin/status', {
	headers: { authorization: 'Bearer ' + derived, connection: 'close' },
})
check('mount standalone binds its own port', ownPort.status === 200, `status=${ownPort.status}`)

// --- 4. unpaired + missing env is still a loud configuration error ----------
delete process.env.NUNCIA_ABSENT_TOKEN
let refused = ''
try {
	await apply(fakeCtx(), {
		...base,
		port: 4207,
		auth: { type: 'bearer', tokenEnv: 'NUNCIA_ABSENT_TOKEN' },
	})
} catch (error) {
	refused = error.message
}
check('missing token with authority off is explained', /NUNCIA_ABSENT_TOKEN is empty and the authority layer is off/.test(refused), refused)

// Give the sockets a moment; exiting mid-close trips a libuv assertion on win32.
await new Promise((resolve) => setTimeout(resolve, 250))
console.log(failures === 0 ? 'ALL AUTH PASS' : `AUTH FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)

