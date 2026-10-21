/**
 * P2 end-to-end: the chatelaine layer over the real plugin wiring.
 *
 * Uses a fake DSH context that can do what the spike proved the real one does:
 * `agents.get` (live) and `agents.resume` (cold), a tools registry, a
 * workspace registry, and the `user-questions/request` waterfall. The checks
 * are the P2 acceptance items that need no model:
 *
 *   1. First contact creates an operator in the workspace, records a handle,
 *      and injects the operator brief BEFORE the task turn.
 *   2. The handle rides in the A2A task metadata.
 *   3. message_chatelaine delivers into the chatelaine session (created once).
 *   4. message_local_session delivers back into the operator session.
 *   5. An operator's ask-user question is forwarded to the chatelaine and
 *      answered in place (custom answer), so it never hangs.
 *   6. An aborted turn is CANCELED, not COMPLETED (the old lie).
 *   7. Expiry prunes: session archived, handle dead, chatelaine told.
 *
 * Run: node tests/test-p2.mjs   (exit 0 = all pass)
 */

import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../lib/index.js'
import { operatorBrief } from '../lib/chatelaine.js'

const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-p2-'))
process.env.NUNCIA_TEST_TOKEN = 'p2-token-123'

const TOKEN = 'p2-token-123'
const ADMIN = { authorization: `Bearer ${TOKEN}`, connection: 'close' }
const listeners = {}
const disposers = []
const created = []
const deliveries = []
const attached = []
const archived = []
const registered = []
const live = new Map()

const textOf = (message) => (message?.content ?? [])
	.map((block) => (block?.type === 'text' ? block.text : ''))
	.filter(Boolean)
	.join('\n')

function makeAgent(id, { abortOnFollowup = false } = {}) {
	const agent = {
		session: { id },
		inject: (message) => { deliveries.push({ sessionId: id, kind: 'inject', text: textOf(message) }) },
		followup: (message) => {
			deliveries.push({ sessionId: id, kind: 'followup', text: textOf(message) })
			pending = new Promise((resolve) => {
				setTimeout(() => {
					const assistant = { type: 'assistant/message', data: { message: { content: [{ type: 'text', text: abortOnFollowup ? 'partial' : 'operator reply' }] } } }
					for (const handler of listeners['session/event'] ?? []) handler(agent.session, assistant)
					const reason = abortOnFollowup ? { kind: 'aborted', reason: { kind: 'user' } } : { kind: 'completed' }
					for (const handler of listeners['session/event'] ?? []) handler(agent.session, { type: 'turn/end', data: { reason } })
					resolve()
				}, 20)
			})
		},
		steer: (message) => { deliveries.push({ sessionId: id, kind: 'steer', text: textOf(message) }) },
		cancel: () => {},
		whenIdle: async () => { if (pending) await pending },
	}
	let pending
	return agent
}

const tools = { register: (definition) => { registered.push(definition) } }
const services = {
	agentDefaultModel: { currentSelection: () => ({ provider: 'p2-provider', model: 'p2-model' }) },
	tools,
	workspaceRegistry: {
		create: async (_path, _title) => ({ attachSession: async (sessionId) => { attached.push(String(sessionId)) } }),
		archiveSession: async (sessionId, options) => { archived.push({ sessionId: String(sessionId), options }) },
	},
}

const fakeCtx = {
	get: (name) => services[name],
	logger: { info: () => {}, error: (m) => console.error('[logger.error]', m), warn: (m) => console.error('[logger.warn]', m) },
	on: (name, handler) => { (listeners[name] ??= []).push(handler) },
	effect: (fn) => { disposers.push(fn()) },
	inject: (_deps, callback) => { callback(fakeCtx) },
	agents: {
		create: async (options) => {
			const id = String(options.sessionId)
			created.push({ id, options })
			const agent = makeAgent(id, { abortOnFollowup: (options.meta?.cwd ?? '').length > 0 && options.__abort === true })
			live.set(id, agent)
			return { agent, dispose: async () => { live.delete(id) } }
		},
		get: (id) => live.get(String(id)),
		resume: async ({ resumeSessionId }) => {
			const id = String(resumeSessionId)
			if (live.has(id)) throw new Error('SessionAlreadyOwnedError')
			const agent = makeAgent(id)
			live.set(id, agent)
			return { agent, dispose: async () => { live.delete(id) } }
		},
	},
}

await apply(fakeCtx, {
	path: '/a2a',
	agentCardPath: '/.well-known/agent.json',
	adminPath: '/a2a/admin',
	port: 4210,
	host: '127.0.0.1',
	auth: { type: 'bearer', token: TOKEN },
	chatelaine: { workspace: HOUSE, operatorTtlMs: 1200 },
})

let failures = 0
const check = (name, cond, detail = '') => {
	console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
	if (!cond) failures++
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const post = (body) => fetch('http://127.0.0.1:4210/a2a', {
	method: 'POST',
	headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', connection: 'close' },
	body: JSON.stringify(body),
})

// --- 1. first contact -------------------------------------------------------
const send1 = await post({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message: { messageId: 'm1', role: 'user', parts: [{ kind: 'text', text: 'please say hi' }] }, metadata: {} } })
const task1 = (await send1.json())?.result?.task
await sleep(80)

check('task completed', task1?.status?.state === 'TASK_STATE_COMPLETED', `state=${task1?.status?.state}`)
const operatorSession = created.find((entry) => entry.options.meta?.cwd === HOUSE)
check('operator session created in the workspace', operatorSession !== undefined, `created=${created.map((entry) => entry.id).join(',')}`)
check('handle rides in task metadata', /^op_[0-9a-f]{16}$/.test(task1?.metadata?.handle ?? ''), JSON.stringify(task1?.metadata))
const operatorDeliveries = () => deliveries.filter((delivery) => delivery.sessionId === operatorSession?.id)
const brief = operatorDeliveries().find((delivery) => delivery.text.startsWith('[operator brief]'))
check('operator brief injected before the turn', brief !== undefined, brief?.text?.split('\n')[0])
check('brief states the handle, level and workspace', brief !== undefined && brief.text.includes(task1.metadata.handle) && /authority is peer/.test(brief.text) && brief.text.includes(HOUSE))
// The brief must answer the two questions an operator cannot look up without
// excavating the node (observed live: 45 tool calls to find a peer name and a
// send path). Exercised directly on the exported builder: this suite runs with
// authority disabled, so the live brief above legitimately has no node/roster.
const rosterBrief = operatorBrief({
  handle: 'op_0123456789abcdef',
  taskId: 'task-x',
  nodeName: 'sylviana',
  peers: [{ name: 'vienzie', kid: 'W0jt', canVerifyV2: true }, { name: 'oldbox', canVerifyV2: false }],
  level: 'peer',
  workspace: HOUSE,
})
check('brief names the node it runs on', /on node "sylviana"/.test(rosterBrief), rosterBrief.split('\n')[0])
check('brief lists paired peers with verification state',
  /Peers paired with this node \(by name\): vienzie, oldbox \(legacy key\)/.test(rosterBrief))
check('brief without peers says so and stops', /No peers are paired with this node right now/.test(operatorBrief({ handle: 'h', taskId: 't', nodeName: 'n', peers: [], level: 'peer', workspace: HOUSE })))
check('brief names the tools it needs', /message_chatelaine \(report, ask a question/.test(brief.text) && /operator_authority/.test(brief.text))
check('brief forbids digging for configuration', /do NOT read configuration, grep the disk/.test(brief.text))
check('operator attached to the housekeeping workspace', attached.includes(operatorSession?.id), JSON.stringify(attached))

// --- 2. chatelaine adopted + told about contact -----------------------------
// Since P4.1 the chatelaine is created at BOOT (in its own directory, so DSH can
// list it), not lazily on the first report — so find it by its tag, not by the
// operators' cwd.
const chatelaineSession = created.find((entry) => String(entry.id).startsWith('a2a-chatelaine-'))
check('chatelaine session adopted once', chatelaineSession !== undefined, created.map((entry) => entry.id).join(','))
// P3.1: both session kinds carry the durable A2A tag in their SESSION ID (the
// v4 session header accepts only `origin: "subagent"`, so the id is the
// carrier) — the metered gate can still recognise them after a restart.
check('operator session is tagged as A2A', operatorSession?.id?.startsWith('a2a-op-') === true, operatorSession?.id)
check('chatelaine session is tagged as A2A', chatelaineSession?.id?.startsWith('a2a-chatelaine-') === true, chatelaineSession?.id)
const chatelaineDeliveries = () => deliveries.filter((delivery) => delivery.sessionId === chatelaineSession?.id)
check('contact reported to the chatelaine', chatelaineDeliveries().some((delivery) => /^Contact: .* opened task/.test(delivery.text)), JSON.stringify(chatelaineDeliveries().map((delivery) => delivery.text.slice(0, 40))))

// --- 3. tools round-trip ----------------------------------------------------
const chatTool = registered.find((tool) => tool.name === 'message_chatelaine')
const localTool = registered.find((tool) => tool.name === 'message_local_session')
check('chatelaine lane tools registered', chatTool !== undefined && localTool !== undefined, registered.map((tool) => tool.name).join(','))

const reported = await chatTool.execute({ message: 'about to touch files' }, { agent: { id: operatorSession.id } })
check('message_chatelaine delivers', reported.delivered === true, JSON.stringify(reported))
check('report landed in the chatelaine session', chatelaineDeliveries().some((delivery) => delivery.text.includes('about to touch files')))

const replied = await localTool.execute({ session: task1.metadata.handle, message: 'approved, go ahead' }, { agent: { id: chatelaineSession.id } })
// The reply names the TASK (the record key), while the session it lands in is
// the tagged operator session.
check('message_local_session delivers', replied.delivered === true && replied.taskId === task1.id, JSON.stringify(replied))
check('reply landed in the operator session', operatorDeliveries().some((delivery) => delivery.kind === 'followup' && delivery.text.includes('approved, go ahead')))

// --- 4. question forwarding -------------------------------------------------
const questionHandler = (listeners['user-questions/request'] ?? [])[0]
check('user-questions handler registered at plugin scope', typeof questionHandler === 'function')
const answer = await questionHandler(
	{ questions: [{ id: 'q1', question: 'Delete the old backups?' }], agent: { id: operatorSession.id } },
	() => { throw new Error('next() should not be reached for an operator') },
)
check('question answered in place', answer?.answers?.[0]?.id === 'q1' && /chatelaine/.test(answer.answers[0].custom ?? ''), JSON.stringify(answer))
check('question forwarded to the chatelaine with a wake', chatelaineDeliveries().some((delivery) => delivery.kind === 'followup' && delivery.text.includes('Delete the old backups?')))

// A session the plugin does not own must fall through to the real UI.
let fellThrough = false
await questionHandler({ questions: [{ id: 'q2', question: 'anything' }], agent: { id: 'session-not-ours' } }, () => { fellThrough = true; return 'ui' })
check('foreign session question falls through', fellThrough === true)

// --- 4b. continued conversation returns to the SAME operator session --------
// The user rule (2026-10-21): continued A2A from the same source goes to the
// same operator by default. A caller that keeps the contextId (the way A2A
// exchanges work) must land on the existing operator, not mint a new one.
const contContextId = task1?.contextId
check('task response carries a contextId', typeof contContextId === 'string' && contContextId.length > 0, contContextId)
const operatorsBefore = created.filter((entry) => entry.options.meta?.cwd === HOUSE).length
const sendCont = await post({ jsonrpc: '2.0', id: 21, method: 'SendMessage', params: { message: { messageId: 'm-cont-1', role: 'user', contextId: contContextId, parts: [{ kind: 'text', text: 'following up on the same thread' }] }, metadata: {} } })
const taskCont = (await sendCont.json())?.result?.task
await sleep(80)
check('continuation completed', taskCont?.status?.state === 'TASK_STATE_COMPLETED', JSON.stringify(taskCont?.status))
check('continuation keeps the context', taskCont?.contextId === contContextId, taskCont?.contextId)
check('continuation is a new task id', taskCont?.id !== task1.id)
const operatorsAfter = created.filter((entry) => entry.options.meta?.cwd === HOUSE).length
check('no second operator session was created', operatorsAfter === operatorsBefore, `${operatorsBefore} -> ${operatorsAfter}`)
check('follow-up delivered to the same session', operatorDeliveries().some((delivery) => delivery.text.includes('following up on the same thread')))
const rosterCont = await (await fetch('http://127.0.0.1:4210/a2a/admin/operators', { headers: ADMIN })).json()
check('handle survives the re-key', rosterCont.operators?.some((op) => op.handle === task1.metadata.handle && op.taskId === taskCont.id), JSON.stringify(rosterCont.operators))

// --- 4c. the fresh-task preamble keeps small tasks small ---------------------
// Live finding (2026-10-21): peers' one-line questions ("Reply with exactly:
// X") sent the model digging through config and the network to "verify" the
// ask. A fresh operator's first message is now prefixed with a brief that says
// answer-and-finish; continuations must NOT get it again.
const firstDeliveries = operatorDeliveries()
// The very first followup is the task turn itself; the brief rides as an inject.
check('fresh task first turn carries the preamble',
	firstDeliveries.some((delivery) => delivery.kind === 'followup' && delivery.text.startsWith('[A2A task]') && delivery.text.includes('exactly what it says')),
	firstDeliveries.map((delivery) => delivery.text.slice(0, 30)).join('|'))
check('continuation turn does NOT get the preamble again',
	firstDeliveries.filter((delivery) => delivery.kind === 'followup' && delivery.text.includes('following up on the same thread')).length === 1
		&& firstDeliveries.every((delivery) => !(delivery.kind === 'followup' && delivery.text.includes('following up on the same thread') && delivery.text.startsWith('[A2A task]'))))
const contReply = await localTool.execute({ session: task1.metadata.handle, message: 'still here' }, { agent: { id: chatelaineSession.id } })
check('reply follows the re-keyed handle', contReply.delivered === true && contReply.taskId === taskCont.id, JSON.stringify(contReply))

// --- 5. abort is not success ------------------------------------------------
const abortSession = (() => {
	const fake = makeAgent('unused')
	return fake
})()
// Drive a second task whose agent aborts: swap the factory for this one call.
const originalCreate = fakeCtx.agents.create
fakeCtx.agents.create = async (options) => {
	const id = String(options.sessionId)
	created.push({ id, options })
	const agent = makeAgent(id, { abortOnFollowup: true })
	live.set(id, agent)
	return { agent, dispose: async () => { live.delete(id) } }
}
const send2 = await post({ jsonrpc: '2.0', id: 2, method: 'SendMessage', params: { message: { messageId: 'm2', role: 'user', parts: [{ kind: 'text', text: 'do something long' }] }, metadata: {} } })
const task2 = (await send2.json())?.result?.task
fakeCtx.agents.create = originalCreate
await sleep(60)
check('aborted turn reports CANCELED', task2?.status?.state === 'TASK_STATE_CANCELED', `state=${task2?.status?.state}`)
check('unexpected end told to the chatelaine', chatelaineDeliveries().some((delivery) => /ended cancelled/.test(delivery.text)), JSON.stringify(chatelaineDeliveries().map((delivery) => delivery.text.slice(0, 60))))

// --- 6. expiry + prune ------------------------------------------------------
const roster1 = await (await fetch('http://127.0.0.1:4210/a2a/admin/operators', { headers: ADMIN })).json()
check('roster lists the operators', roster1.operators?.length >= 2 && roster1.chatelaine !== null, JSON.stringify({ count: roster1.operators?.length, chatelaine: roster1.chatelaine }))
await sleep(1500)
const pruned = await (await fetch('http://127.0.0.1:4210/a2a/admin/operators/prune', { method: 'POST', headers: { ...ADMIN, 'content-type': 'application/json' }, body: '{}' })).json()
const roster2 = await (await fetch('http://127.0.0.1:4210/a2a/admin/operators', { headers: ADMIN })).json()
check('expired operators pruned', roster2.operators?.length === 0, `pruned=${pruned.pruned}, left=${roster2.operators?.length}`)
check('sessions archived, never silently deleted', archived.length >= 1, JSON.stringify(archived.map((entry) => entry.options)))
check('chatelaine told about the prune', chatelaineDeliveries().some((delivery) => /Pruned \d+ expired operator/.test(delivery.text)))
let deadHandle = ''
try { await localTool.execute({ session: task1.metadata.handle, message: 'too late' }, { agent: { id: chatelaineSession.id } }) } catch (error) { deadHandle = error.message }
check('a pruned handle is refused by name', /unknown operator handle/.test(deadHandle), deadHandle)

console.log(failures === 0 ? 'ALL P2 PASS' : `P2 FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)
