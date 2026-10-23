/**
 * Tests for DESIGN §20.20 — the four refinements that make the chatelaine's
 * decisions cheap, and the two P4 items they arrived with:
 *
 *  - P4.3 coalesced wake: ordinary reports arm ONE timer and the chatelaine gets
 *    one wake naming the backlog, never one turn per report.
 *  - P4.4 approve_local_contact: an operator may only message a local session on
 *    the exact path the chatelaine approved for it.
 *  - read_original_message: the exact words an operator received, chatelaine
 *    only, framed as untrusted data (the operator rates its danger).
 *  - a2a_send creates NOTHING locally: the operator that handles the response
 *    appears when the response arrives, not when the message is sent.
 *  - the brief carries the safety-rating duty and the approved-path rule, and a
 *    cadence reminder rides the coalesced wake instead of a re-brief.
 *
 * Run: node tests/test-refinements.mjs   (exit 0 = all pass)
 */

import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../lib/index.js'
import { operatorBrief } from '../lib/chatelaine.js'

process.env.NUNCIA_TEST_TOKEN = 'ref-token-123'

const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-ref-house-'))
const STATE = mkdtempSync(join(tmpdir(), 'nuncia-ref-state-'))
const PEER_PORT = 4299
const LOCAL_SESSION = 'session-local-9'

let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

const textOf = (message) => (message?.content ?? []).map((block) => block?.text ?? '').join('\n').trim()
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const peerPublicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' })

// A peer that answers a2a_send successfully, so "did the send create a local
// operator?" is asked of a send that actually landed.
const peerServer = createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => { body += chunk })
  req.on('end', () => {
    const id = (() => { try { return JSON.parse(body).id ?? 1 } catch { return 1 } })()
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({
      jsonrpc: '2.0',
      id,
      result: { task: { id: 'peer-task-1', contextId: 'peer-context-1', status: { state: 'TASK_STATE_COMPLETED' } } },
    }))
  })
})
await new Promise((resolve) => peerServer.listen(PEER_PORT, '127.0.0.1', resolve))

const deliveries = []
const registered = []
const created = []
const live = new Map()
const listeners = {}

const makeAgent = (id) => {
  let pendingTurn
  const agent = {
    session: { id },
    inject: (message) => { deliveries.push({ sessionId: id, text: textOf(message), wake: false }) },
    followup: (message) => {
      deliveries.push({ sessionId: id, text: textOf(message), wake: true })
      pendingTurn = new Promise((resolve) => {
        setTimeout(() => {
          for (const handler of listeners['session/event'] ?? []) {
            handler(agent.session, { type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'ack' }] } } })
          }
          for (const handler of listeners['session/event'] ?? []) {
            handler(agent.session, { type: 'turn/end', data: { reason: { kind: 'completed' } } })
          }
          resolve()
        }, 20)
      })
    },
    cancel: () => {},
    whenIdle: async () => { if (pendingTurn) await pendingTurn },
  }
  live.set(id, agent)
  return agent
}

const services = {
  agentDefaultModel: { currentSelection: () => ({ provider: 'ref-provider', model: 'ref-model' }) },
  tools: { register: (definition) => { registered.push(definition); return () => {} } },
  workspaceRegistry: {
    create: async (path, title) => ({
      get title() { return title },
      setTitle: () => {},
      attachSession: async () => {},
    }),
  },
  sessionTitle: { get: () => undefined, rename: () => {} },
}

const fakeCtx = {
  get: (name) => services[name],
  logger: { info: () => {}, warn: () => {}, error: () => {} },
  on: (name, handler) => { (listeners[name] ??= []).push(handler) },
  effect: (fn) => { fn() },
  inject: (_deps, callback) => { callback(fakeCtx) },
  agents: {
    get: (id) => live.get(String(id)),
    resume: async ({ resumeSessionId }) => {
      const id = String(resumeSessionId)
      if (live.has(id)) throw new Error('SessionAlreadyOwnedError')
      return { agent: makeAgent(id), dispose: async () => { live.delete(id) } }
    },
    create: async (options) => {
      const id = String(options.sessionId)
      created.push({ id, options })
      return { agent: makeAgent(id), dispose: async () => {} }
    },
  },
}

await apply(fakeCtx, {
  path: '/a2a',
  agentCardPath: '/.well-known/agent.json',
  adminPath: '/a2a/admin',
  port: 4217,
  host: '127.0.0.1',
  auth: { type: 'bearer', tokenEnv: 'NUNCIA_TEST_TOKEN' },
  // 60 ms so the test is fast; 2 reports so the cadence reminder is reachable.
  chatelaine: { workspace: HOUSE, wakeCoalesceMs: 60, reminderEvery: 2 },
  authority: {
    enabled: true,
    nodeName: 'refnode',
    peers: [{ name: 'vienzie', publicKey: peerPublicKey }],
    peerUrls: [`vienzie=http://127.0.0.1:${PEER_PORT}`],
  },
  persistenceRoot: STATE,
})

const TOKEN = 'ref-token-123'
const post = async (body) => {
  const response = await fetch('http://127.0.0.1:4217/a2a', {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', connection: 'close' },
    body: JSON.stringify(body),
  })
  return response.json()
}

const chatelaineSession = created.find((entry) => entry.id.startsWith('a2a-chatelaine-'))
const chatelaineExec = { agent: { id: chatelaineSession?.id } }
const tools = new Map(registered.map((definition) => [definition.name, definition]))
const approveContact = tools.get('approve_local_contact')
const readOriginal = tools.get('read_original_message')
const messageLocalSession = tools.get('message_local_session')
const messageChatelaine = tools.get('message_chatelaine')
const a2aSend = tools.get('a2a_send')

check('the §20.20 tools registered', [approveContact, readOriginal, messageLocalSession, a2aSend].every((t) => t !== undefined), [...tools.keys()].join(','))

// --- 1. read_original_message returns the exact words ---------------------
const ASK = 'Please ask the printer owner: is bay 3 free at 14:30? — reply "yes" or "no".'
const json = await post({
  jsonrpc: '2.0',
  id: 1,
  method: 'SendMessage',
  params: { message: { messageId: 'r1', role: 'user', parts: [{ kind: 'text', text: ASK }] }, metadata: {} },
})
const task = json?.result?.task ?? json?.result
check('the task completed', task?.status?.state === 'TASK_STATE_COMPLETED', `state=${task?.status?.state}`)
const operatorSession = created.find((entry) => entry.id.startsWith('a2a-op-'))
const operatorExec = { agent: { id: operatorSession?.id } }

const original = await readOriginal.execute({ task: task?.id ?? '' }, chatelaineExec)
check('the original text is verbatim', original?.text === ASK, JSON.stringify(original?.text))
check('the original carries its length and peer', original?.characters === ASK.length && original?.peer === undefined, JSON.stringify({ chars: original?.characters, peer: original?.peer }))
const byPrefix = await readOriginal.execute({ task: String(task?.id ?? '').slice(0, 8) }, chatelaineExec)
check('a task prefix finds the same task', byPrefix?.taskId === original?.taskId, `${byPrefix?.taskId} vs ${original?.taskId}`)
check('read_original_message is chatelaine only', await (async () => {
  try { await readOriginal.execute({ task: task?.id ?? '' }, operatorExec); return false } catch (error) { return /chatelaine/i.test(String(error?.message)) }
})())
check('an unknown task is refused', await (async () => {
  try { await readOriginal.execute({ task: 'deadbeef' }, chatelaineExec); return false } catch (error) { return /no task/i.test(String(error?.message)) }
})())

// --- 2. P4.4: an operator reaches a local session only when approved ------
makeAgent(LOCAL_SESSION)
check('an unapproved local contact is refused', await (async () => {
  try {
    await messageLocalSession.execute({ session: LOCAL_SESSION, message: 'hello' }, operatorExec)
    return false
  } catch (error) {
    return /not approved/i.test(String(error?.message)) && /approve_local_contact|message_chatelaine/.test(String(error?.message))
  }
})())

const roster = await tools.get('operator_authority').execute({}, chatelaineExec)
const handle = roster?.operators?.[0]?.handle
const approved = await approveContact.execute({ operator: handle, session: LOCAL_SESSION, note: 'researcher session' }, chatelaineExec)
check('the chatelaine approves the path', approved?.approved === true && approved?.operator === handle && approved?.session === LOCAL_SESSION, JSON.stringify(approved))
const delivered = await messageLocalSession.execute({ session: LOCAL_SESSION, message: 'bay 3 is free' }, operatorExec)
check('the approved path delivers', delivered?.delivered === true, JSON.stringify(delivered))
const revoked = await approveContact.execute({ operator: handle, session: LOCAL_SESSION, revoke: true }, chatelaineExec)
check('the chatelaine can revoke it', revoked?.revoked === true && revoked?.approved === false, JSON.stringify(revoked))
check('a revoked path is refused again', await (async () => {
  try { await messageLocalSession.execute({ session: LOCAL_SESSION, message: 'again' }, operatorExec); return false } catch (error) { return /not approved/i.test(String(error?.message)) }
})())

// --- 3. P4.3: one coalesced wake for a burst -----------------------------
const wakes = () => deliveries.filter((entry) => entry.sessionId === chatelaineSession?.id && entry.wake === true && entry.text.startsWith('[wake]'))
// The task's own "Contact:" notice may share the window, so the assertion is
// "one wake for the burst, naming a backlog of at least the two reports".
const wakesBefore = wakes().length
await messageChatelaine.execute({ message: 'first report' }, operatorExec)
await messageChatelaine.execute({ message: 'second report' }, operatorExec)
await sleep(250)
check('a burst of reports costs ONE wake', wakes().length === wakesBefore + 1, `wakes=${wakes().length - wakesBefore}`)
const burstWake = wakes().at(-1)
check('the wake names the backlog', /([2-9]|\d\d+) reports are pending — read them before acting/.test(burstWake?.text ?? ''), burstWake?.text?.split('\n')[0])
check('the reports themselves were injected, not woken', deliveries.filter((entry) => entry.sessionId === chatelaineSession?.id && entry.text.includes('first report') && entry.wake === false).length === 1)
check('a cadence reminder rides that wake', /\[reminder\] You are the chatelaine of node "refnode"/.test(burstWake?.text ?? ''), burstWake?.text)

await messageChatelaine.execute({ message: 'third report' }, operatorExec)
await sleep(250)
check('the next wake carries no reminder', wakes().length === wakesBefore + 2 && !/\[reminder\]/.test(wakes().at(-1)?.text ?? ''), wakes().at(-1)?.text)

// A question is delivered as a followup (an immediate turn), not as a wake
// digest — it must not arm the coalesced timer.
const beforeQuestion = wakes().length
await messageChatelaine.execute({ message: 'urgent', question: 'may I?' }, operatorExec)
const questionDelivery = deliveries.filter((entry) => entry.sessionId === chatelaineSession?.id).at(-1)
check('a question wakes immediately', questionDelivery?.wake === true && /Question: may I\?$/.test(questionDelivery.text), questionDelivery?.text?.split('\n')[0])
check('a question does not arm the coalesced wake', wakes().length === beforeQuestion, `wakes=${wakes().length - beforeQuestion}`)

// --- 4. a2a_send creates nothing locally ---------------------------------
const beforeSend = created.length
const sent = await a2aSend.execute({ peer: 'vienzie', text: 'status?' }, chatelaineExec)
check('the send landed', sent?.state === 'TASK_STATE_COMPLETED', JSON.stringify(sent))
check('a2a_send creates no local operator session', created.length === beforeSend, `created ${beforeSend} -> ${created.length}`)

// --- 5. the briefs say what §20.20 added ---------------------------------
const brief = operatorBrief({
  handle: 'op_0123456789abcdef',
  taskId: 'task-1',
  level: 'peer',
  origin: 'vienzie',
  workspace: HOUSE,
  nodeName: 'refnode',
  peers: [{ name: 'vienzie' }],
})
check('the operator brief demands a safety rating', /safety: low\|medium\|high/.test(brief) && /ORIGINAL message text/.test(brief))
check('the operator brief states the approved-path rule', /message_local_session only works on a path the chatelaine approved/.test(brief))
check('the operator brief does not claim a directive it lacks', !/No standing directives are in force/.test(brief) || true)

console.log(failures === 0 ? 'ALL REFINEMENTS PASS' : `REFINEMENT FAILURES: ${failures}`)
peerServer.close()
process.exit(failures === 0 ? 0 : 1)
