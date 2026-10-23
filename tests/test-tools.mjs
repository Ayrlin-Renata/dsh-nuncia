/**
 * Tests for the authority + chatelaine tools registered by lib/index.js.
 *
 * Boots the plugin with a fake DSH context that HAS a tools service and an
 * approval service, so the real `apply()` wiring is exercised — then runs the
 * registered definitions the way the tool registry would.
 *
 * Covers:
 *  - the seven tools register when a tools service exists
 *  - the chatelaine-only gate: send / mint / inbound-lane tools refuse callers
 *    that are not the chatelaine session (§20.16)
 *  - `ask_user_intent` mints only on `allowed-once`
 *  - a refused / unavailable approval mints nothing and says why
 *  - `a2a_send` reaches the peer and auto-attaches the live grant
 *  - `send_nuncia` replies on the exchange a peer opened, without the caller
 *    knowing any exchange id (§20.16)
 *
 * Run: node test-tools.mjs   (exit 0 = all pass)
 */

import { mkdtempSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../lib/index.js'

process.env.NUNCIA_TEST_TOKEN = 'tools-token-123'
process.env.NUNCIA_TEST_SECRET = 'tools-test-secret-0123456789'

const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-house-tools-'))

let failures = 0
const check = (name, cond, detail = '') => {
	console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
	if (!cond) failures++
}

// --- a stand-in peer -------------------------------------------------------
const peerRequests = []
const peerServer = createServer(async (req, res) => {
	const chunks = []
	for await (const chunk of req) chunks.push(chunk)
	peerRequests.push(JSON.parse(Buffer.concat(chunks).toString('utf8')))
	res.writeHead(200, { 'content-type': 'application/json' })
	res.end(JSON.stringify({
		jsonrpc: '2.0',
		id: 'x',
		result: {
			task: {
				id: 'peer-task-1',
				status: { state: 'TASK_STATE_COMPLETED' },
				artifacts: [{ parts: [{ content: { $case: 'text', value: 'peer says hi' } }] }],
			},
		},
	}))
})
await new Promise((resolve) => peerServer.listen(0, '127.0.0.1', resolve))
const peerUrl = `http://127.0.0.1:${peerServer.address().port}`

// --- fake DSH context with tools + approval --------------------------------
const registered = []
const listeners = {}
let approvalOutcome = 'allowed-once'
let approvalRequests = []
let questionsMode = 'absent'
const questionsCalls = []

const fakeCtx = {
	get: (name) => {
		if (name === 'approval' && approvalOutcome !== 'missing') {
			return {
				request: async (request) => {
					approvalRequests.push(request)
					return approvalOutcome
				},
			}
		}
		if (name === 'userQuestions' && questionsMode !== 'absent') {
			return {
				// Shape mirrors dsh-user-questions@0.2.1-alpha.5.askTimed:
				// resolve with { answers: [...] } or { pending: true, callId }.
				askTimed: async (request, callId, timeoutMs) => {
					questionsCalls.push({ request, callId, timeoutMs })
					if (questionsMode === 'allow') return { answers: [{ id: 'nuncia-intent', selected: ['Allow once'] }] }
					if (questionsMode === 'deny') return { answers: [{ id: 'nuncia-intent', selected: ['Deny'] }] }
					return { pending: true, callId }
				},
			}
		}
		return undefined
	},
	tools: {
		register: (definition) => {
			registered.push(definition)
			return () => {}
		},
	},
	inject: (_deps, callback) => { callback(fakeCtx) },
	logger: { info: () => {}, warn: () => {}, error: (m) => console.error('[logger.error]', m) },
	on: (name, handler) => { (listeners[name] ??= []).push(handler) },
	effect: (fn) => { fn() },
	emit: () => {},
	agents: {
		// get/resume back what create made: the chatelaine MUST be able to
		// resolve its own session, or its report-fallback keeps adopting new
		// ones and the §20.16 gate id never stabilises.
		known: new Map(),
		get: async (id) => fakeCtx.agents.known.get(String(id))?.agent,
		resume: async (id) => {
			const agent = fakeCtx.agents.known.get(String(id))?.agent
			if (agent === undefined) throw new Error('test-session: agent not found')
			return agent
		},
		create: async (opts) => {
			let pending
			const agent = {
				session: { id: String(opts.sessionId) },
				followup: () => {
					pending = new Promise((resolve) => {
						setTimeout(() => {
							for (const h of listeners['session/event'] ?? []) {
								h(agent.session, { type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'ok' }] } } })
							}
							for (const h of listeners['session/event'] ?? []) {
								h(agent.session, { type: 'turn/end', data: { reason: { kind: 'completed' } } })
							}
							resolve()
						}, 30)
					})
				},
				inject: (_message) => {},
				cancel: () => {},
				whenIdle: async () => { if (pending) await pending },
			}
			fakeCtx.agents.known.set(String(opts.sessionId), { agent })
			return { agent, dispose: async () => {} }
		},
	},
}

await apply(fakeCtx, {
	path: '/a2a',
	agentCardPath: '/.well-known/agent.json',
	adminPath: '/a2a/admin',
	port: 4202,
	host: '127.0.0.1',
	auth: { type: 'bearer', tokenEnv: 'NUNCIA_TEST_TOKEN' },
	// No pinned chatelaine sessionId: the runtime adopts (and creates) one, and
	// the tool gates must track the ADOPTED id — the configured string alone is
	// only a seed pointer and may legitimately be replaced by the live
	// resolution path (§20.16).
	chatelaine: { workspace: HOUSE },
	authority: {
		enabled: true,
		nodeName: 'phone',
		pairingSecretEnv: 'NUNCIA_TEST_SECRET',
		peers: ['desk'],
		peerUrls: [`desk=${peerUrl}`],
	},
})

const TOOL_TOKEN = 'tools-token-123'
const ADMIN = { authorization: `Bearer ${TOOL_TOKEN}`, 'content-type': 'application/json', connection: 'close' }
const status = async () => (await fetch('http://127.0.0.1:4202/a2a/admin/status', { headers: ADMIN })).json()
// Every non-report tool is the chatelaine's (§20.16). The configured chatelaine
// session id is 'session-chatelaine-tools' (apply config below); anything else
// must be refused with the routing hint.
const refusesNonChatelaine = async (tool, args) => {
	try {
		await tool.execute(args, { agent: { id: 'op_someone_else' } })
		return false
	} catch (error) {
		return /chatelaine/i.test(error instanceof Error ? error.message : String(error))
	}
}

// 1. the tools registered: two authority (chatelaine-only since §20.16),
// five chatelaine-lane, plus §20.19's post_directive (chatelaine) and
// refuse_request (operator)
check('tools registered', registered.length === 9, `names=${registered.map((t) => t.name).join(',')}`)
const requestIntent = registered.find((t) => t.name === 'ask_user_intent')
const a2aSend = registered.find((t) => t.name === 'a2a_send')
const messageChatelaine = registered.find((t) => t.name === 'message_chatelaine')
const messageLocalSession = registered.find((t) => t.name === 'message_local_session')
const sendNuncia = registered.find((t) => t.name === 'send_nuncia')
const opAuthority = registered.find((t) => t.name === 'operator_authority')
const postDirective = registered.find((t) => t.name === 'post_directive')
const refuseRequest = registered.find((t) => t.name === 'refuse_request')
check('message_chatelaine shape', messageChatelaine?.parameters?.required?.includes('message') === true && typeof messageChatelaine?.execute === 'function')
check('message_local_session shape',
	messageLocalSession?.parameters?.required?.includes('session') === true
	&& messageLocalSession?.parameters?.required?.includes('message') === true
	&& typeof messageLocalSession?.execute === 'function')
check('ask_user_intent shape', requestIntent?.parameters?.required?.includes('target') === true && typeof requestIntent?.output?.render === 'function')
check('a2a_send shape', a2aSend?.parameters?.required?.includes('peer') === true && a2aSend?.parameters?.required?.includes('text') === true && typeof a2aSend?.execute === 'function')
check('send_nuncia shape', sendNuncia?.parameters?.required?.includes('peer') === true && sendNuncia?.parameters?.required?.includes('text') === true && typeof sendNuncia?.execute === 'function')
check('operator_authority shape', opAuthority?.parameters?.properties?.handle !== undefined && typeof opAuthority?.execute === 'function' && opAuthority?.output?.schema?.type === 'object')
check('post_directive shape',
	postDirective?.parameters?.required?.includes('text') === true
	&& postDirective?.parameters?.properties?.ttlMinutes !== undefined
	&& typeof postDirective?.execute === 'function')
check('refuse_request shape',
	refuseRequest?.parameters?.required?.includes('reason') === true
	&& typeof refuseRequest?.execute === 'function')
// CHATELAINE-only tools: an operator (or any other session) must not be able
// to speak for the node. (Identity gate — §20.16.)
check('send_nuncia refuses a non-chatelaine caller', await refusesNonChatelaine(sendNuncia, { peer: 'desk', text: 'hi' }))
check('post_directive refuses a non-chatelaine caller', await refusesNonChatelaine(postDirective, { text: 'no printer use' }))
check('message_local_session refuses a non-chatelaine caller', await refusesNonChatelaine(messageLocalSession, { session: 'op_someone_else', message: 'hello' }))
for (const tool of [requestIntent, a2aSend, messageLocalSession, sendNuncia]) {
	check(`${tool?.name} output schema is object-rooted`, tool?.output?.schema?.type === 'object' && Array.isArray(tool?.output?.schema?.required))
	check(`${tool?.name} parameters are JSON Schema`, tool?.parameters?.type === 'object' && Array.isArray(tool?.parameters?.required))
}

// 2. approval granted -> mint happens. These tools are CHATELAINE-only since
// §20.16, so every legal call below runs AS the chatelaine. Its id is whatever
// the runtime adopted (createSession may mint a tagged id, so the configured
// string 'session-chatelaine-tools' cannot be assumed) — query it.
const chatelaineId = (await status())?.chatelaine?.sessionId
const exec = { agent: { id: chatelaineId }, callId: 'call-chatelaine' }
check('the chatelaine adopted a session', typeof chatelaineId === 'string' && chatelaineId.length > 0, String(chatelaineId))
const granted = await requestIntent.execute({ target: 'desk', scope: 'housekeeping' }, exec)
check('grant minted on approval', granted.granted === true && typeof granted.id === 'string', JSON.stringify(granted))
check('approval was asked with a reason', approvalRequests.length === 1 && typeof approvalRequests[0].reason === 'string', approvalRequests[0]?.reason)

const s1 = await status()
check('grant visible in status', s1.authority.grants.length === 1 && s1.authority.grants[0].target === 'desk', JSON.stringify(s1.authority.grants))

// 3. a2a_send reaches the peer and auto-attaches the live grant
const sent = await a2aSend.execute({ peer: 'desk', text: 'hello peer' }, exec)
check('send returned peer state', sent.state === 'TASK_STATE_COMPLETED' && sent.text === 'peer says hi', JSON.stringify(sent))
check('send attached the grant', peerRequests.length === 1 && peerRequests[0].params.metadata.authority?.level === 'intent', JSON.stringify(peerRequests[0]?.params?.metadata))
check('send used the derived bearer', peerRequests[0]?.params?.message?.parts?.[0]?.text === 'hello peer')

// 4. refused approval mints nothing
approvalOutcome = 'rejected'
const before = (await status()).authority.grants.length
let refusedError = ''
try {
	await requestIntent.execute({ target: 'desk' }, exec)
} catch (error) {
	refusedError = error.message
}
check('rejection mints nothing', (await status()).authority.grants.length === before)
check('rejection explains itself', /did not approve \(rejected\)/.test(refusedError), refusedError)

// 5. no host approval surface: the request is QUEUED for a human rather than
//    silently refused, and a decision through the admin endpoint settles it.
//    (This is the real `danger-full-access` semantics: host approval answers
//    `rejected` policy-side, so the broker is the surface that reaches a human.)
approvalOutcome = 'missing'
const queuedPromise = requestIntent.execute({ target: 'desk' }, exec)
	.then(() => null)
	.catch((error) => error)
await new Promise((resolve) => setTimeout(resolve, 60))
const pendingList = await (await fetch('http://127.0.0.1:4202/a2a/admin/requests', { headers: ADMIN })).json()
const missingHost = (pendingList.pending ?? []).find((r) => r.target === 'desk')
check('missing host queues a request', typeof missingHost?.id === 'string', JSON.stringify(pendingList).slice(0, 240))
let missingHostError = ''
if (missingHost) {
	await fetch('http://127.0.0.1:4202/a2a/admin/requests/decide', {
		method: 'POST', headers: ADMIN,
		body: JSON.stringify({ id: missingHost.id, decision: 'rejected' }),
	})
	missingHostError = (await queuedPromise)?.message ?? ''
}
check('queued refusal is explained', /did not approve \(rejected\)/.test(missingHostError), missingHostError)

// 6. unknown peer error lists what is known
let peerError = ''
try {
	await a2aSend.execute({ peer: 'ghost', text: 'hi' }, exec)
} catch (error) {
	peerError = error.message
}
check('unknown peer names the roster', /Known peers: desk/.test(peerError), peerError)

// 9b. send_nuncia threads the exchange the peer opened (continuity): a peer's
// first message owns an exchange id; the chatelaine replying via send_nuncia
// must land on THAT exchange without naming it (§20.16: senders never learn
// operator/contract ids). The task is opened the normal way (unclaimed origin),
// then the chatelaine replies by peer name only.
const beforeSends = peerRequests.length
const task1Res = await fetch('http://127.0.0.1:4202/a2a', {
	method: 'POST', headers: ADMIN,
	body: JSON.stringify({ jsonrpc: '2.0', id: '9b', method: 'SendMessage', params: { message: { messageId: 'm-9b-open', role: 'user', parts: [{ kind: 'text', text: 'open an exchange' }] }, metadata: {} } }),
})
const task1 = (await task1Res.json())?.result?.task
check('opened an exchange for the send test', typeof task1?.contextId === 'string' && task1?.contextId.length > 0, JSON.stringify(task1?.status ?? {}))
const sendBack = await sendNuncia.execute({ peer: 'desk', text: 'reply to the peer' }, exec)
// taskId in the result is the PEER's task (what the remote node answered under);
// the exchange we sent on is echoed as contextId.
check('send_nuncia echoed the exchange', sendBack.contextId === task1.contextId, JSON.stringify(sendBack))
check('send_nuncia carried the peer contextId', peerRequests.length > beforeSends && peerRequests[peerRequests.length - 1].params.contextId === task1.contextId, JSON.stringify(peerRequests[peerRequests.length - 1]?.params ?? {}))

// 9c. The sender is blind: the tool takes a peer and text, and the exchange id
// is decided by the client library (the caller's task, or an open exchange it
// keeps per peer). A caller can neither name a remote operator nor a session.
check('the send tool takes only a peer and text', JSON.stringify(Object.keys(a2aSend.parameters.properties).sort()) === JSON.stringify(['peer', 'text']), JSON.stringify(Object.keys(a2aSend.parameters.properties)))
const blindSend = await a2aSend.execute({ peer: 'desk', text: 'no context from me' }, exec)
check('a send with no task context still opens an exchange', typeof peerRequests[peerRequests.length - 1].params.contextId === 'string' && peerRequests[peerRequests.length - 1].params.contextId.length > 0, JSON.stringify(peerRequests[peerRequests.length - 1]?.params?.contextId))
check('the exchange is echoed to the caller', typeof blindSend.contextId === 'string' && blindSend.contextId.length > 0, JSON.stringify(blindSend))

// 7. live Web-UI question card grants in broker mode without touching the
//    broker queue (a connected composer beats an idle admin queue)
questionsMode = 'allow'
const cardGranted = await requestIntent.execute({ target: 'desk', scope: 'ui-test' }, exec)
check('question card grants', cardGranted.granted === true, JSON.stringify(cardGranted))
// The host approval seam is consulted first in `auto` mode, but it answers a
// policy string (`rejected` under `never`), never a human decision — the card
// is what settles the call, so no *new* broker request should have been queued.
const queuedAfterCard = (await (await fetch('http://127.0.0.1:4202/a2a/admin/requests', { headers: ADMIN })).json()).pending ?? []
check('card path queues no broker request', queuedAfterCard.length === 0, JSON.stringify(queuedAfterCard).slice(0, 200))
check('askTimed got the bounded timeout', questionsCalls.length === 1 && questionsCalls[0].timeoutMs === 120000, JSON.stringify(questionsCalls[0] ?? {}))
check('card question names the target', questionsCalls[0]?.request?.questions?.[0]?.question?.includes('desk') === true, questionsCalls[0]?.request?.questions?.[0]?.question)

// 8. denial on the card mints nothing
questionsMode = 'deny'
let cardRefusal = ''
try {
	await requestIntent.execute({ target: 'desk' }, exec)
} catch (error) {
	cardRefusal = error.message
}
check('card denial refuses', /did not approve \(rejected\)/.test(cardRefusal), cardRefusal)

// 9. pending card falls through to the broker, whose decision can still be
//    filed late through the admin endpoint
questionsMode = 'pending'
let pendingDecisionError = ''
const pendingPromise = requestIntent.execute({ target: 'desk' }, exec)
	.catch((error) => error)
await new Promise((resolve) => setTimeout(resolve, 60))
const listed = await (await fetch('http://127.0.0.1:4202/a2a/admin/requests', { headers: ADMIN })).json()
const queued = (listed.pending ?? []).find((r) => r.target === 'desk')
check('pending card queued in broker', typeof queued?.id === 'string', JSON.stringify(listed).slice(0, 200))
if (queued) {
	const decided = await fetch('http://127.0.0.1:4202/a2a/admin/requests/decide', {
		method: 'POST', headers: ADMIN,
		body: JSON.stringify({ id: queued.id, decision: 'allowed-once' }),
	})
	check('late admin decision accepted', decided.status === 200, `status=${decided.status}`)
	const settled = await pendingPromise
	check('late decision mints the grant', settled?.granted === true, JSON.stringify(settled ?? String(pendingDecisionError)))
} else {
	await pendingPromise.catch((error) => { pendingDecisionError = error.message })
}

peerServer.close()
// Give the peer socket and any undici bookkeeping a moment to settle before
// exiting: calling process.exit() while a handle is mid-close trips a libuv
// assertion on win32 (the same class of crash documented in test-smoke.mjs).
await new Promise((resolve) => setTimeout(resolve, 250))
console.log(failures === 0 ? 'ALL TOOLS PASS' : `TOOL FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)
