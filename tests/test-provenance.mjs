/**
 * Tests for DESIGN §20.18 — the chatelaine should not have to dig.
 *
 * The live session log showed the chatelaine spending 14 of 16 steps working
 * out *who* was asking and *under what authority* before it could answer. Both
 * facts are already in scope when a message is sent and when a task is created,
 * so this suite pins down the three places they now travel:
 *
 *  - `message_chatelaine` writes a provenance header (sender handle, task,
 *    session, peer pairing, authority window) into the message body.
 *  - `operator_authority` with no handle answers "who asked, and what may they
 *    do" as a roster — no state files required.
 *  - operator sessions land in their own workspace with titles, so the human
 *    can find and open them in the DSH client.
 *
 * Run: node test-provenance.mjs   (exit 0 = all pass)
 */

import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../lib/index.js'

process.env.NUNCIA_TEST_TOKEN = 'prov-token-123'

const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-prov-house-'))
const STATE = mkdtempSync(join(tmpdir(), 'nuncia-prov-state-'))
const CHATELAINE_DIR = join(HOUSE, 'chatelaine')
const OPERATORS_DIR = join(HOUSE, 'operators')

let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

/** Text of a plugin-built user message (content blocks, not the raw object). */
const textOf = (message) => (message?.content ?? []).map((block) => block?.text ?? '').join('\n').trim()

// A peer key so the roster's peer half has something to list. Only the public
// half is needed: this node never speaks as the peer.
const peerPublicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' })

const deliveries = []        // {sessionId, text, wake}
const registered = []        // tool definitions
const created = []           // agents.create options
const live = new Map()       // sessionId -> agent
const workspaces = []        // {path, title, attached:[], setTitles:[]}
const titles = new Map()     // sessionId -> title
const listeners = {}

/** A fake DSH agent: records deliveries and simulates a turn on followup. */
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
        }, 40)
      })
    },
    cancel: () => {},
    whenIdle: async () => { if (pendingTurn) await pendingTurn },
  }
  live.set(id, agent)
  return agent
}

const services = {
  agentDefaultModel: { currentSelection: () => ({ provider: 'prov-provider', model: 'prov-model' }) },
  tools: { register: (definition) => { registered.push(definition); return () => {} } },
  workspaceRegistry: {
    create: async (path, title) => {
      let record = workspaces.find((entry) => entry.path === path)
      if (record === undefined) {
        record = { path, title, attached: [], setTitles: [] }
        workspaces.push(record)
      }
      return {
        get title() { return record.title },
        setTitle: (next) => { record.title = next; record.setTitles.push(next) },
        attachSession: async (sessionId) => { record.attached.push(String(sessionId)) },
      }
    },
  },
  sessionTitle: {
    get: (session) => titles.get(String(session?.id)),
    rename: async (session, title) => { titles.set(String(session?.id), title) },
  },
}

const fakeCtx = {
  get: (name) => services[name],
  logger: { info: () => {}, warn: (m) => console.error('[logger.warn]', m), error: (m) => console.error('[logger.error]', m) },
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
  port: 4211,
  host: '127.0.0.1',
  auth: { type: 'bearer', tokenEnv: 'NUNCIA_TEST_TOKEN' },
  chatelaine: { workspace: HOUSE },
  authority: { enabled: true, nodeName: 'provnode', peers: [{ name: 'vienzie', publicKey: peerPublicKey }] },
  persistenceRoot: STATE,
})

const TOKEN = 'prov-token-123'
const post = async (body) => {
  const response = await fetch('http://127.0.0.1:4211/a2a', {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', connection: 'close' },
    body: JSON.stringify(body),
  })
  return response.json()
}

// --- 1. the chatelaine is findable ----------------------------------------
const chatelaineSession = created.find((entry) => entry.id.startsWith('a2a-chatelaine-'))
check('the chatelaine session exists', chatelaineSession !== undefined, created.map((entry) => entry.id).join(','))
check('the chatelaine is titled at creation', titles.get(chatelaineSession?.id) === `Chatelaine — provnode`, String(titles.get(chatelaineSession?.id)))
check('the chatelaine lives in its own workspace', workspaces.some((entry) => entry.path === CHATELAINE_DIR && entry.attached.includes(chatelaineSession?.id)), JSON.stringify(workspaces.map((entry) => entry.path)))

// --- 2. an operator task creates a titled, attached session ---------------
const json = await post({
  jsonrpc: '2.0',
  id: 1,
  method: 'SendMessage',
  params: { message: { messageId: 'p1', role: 'user', parts: [{ kind: 'text', text: 'ask me a thing' }] }, metadata: {} },
})
const task = json?.result?.task ?? json?.result
check('the task completed', task?.status?.state === 'TASK_STATE_COMPLETED', `state=${task?.status?.state}`)

const operatorSession = created.find((entry) => entry.id.startsWith('a2a-op-'))
check('an operator session was created', operatorSession !== undefined, created.map((entry) => entry.id).join(','))
const operatorsWorkspace = workspaces.find((entry) => entry.path === OPERATORS_DIR)
check('operators get their own workspace', operatorsWorkspace?.title === 'A2A operators', JSON.stringify(operatorsWorkspace?.title))
check('the operator is attached to it', operatorsWorkspace?.attached.includes(operatorSession?.id) === true, JSON.stringify(operatorsWorkspace?.attached))
check(
  'the operator is titled from its requester and ask',
  /^A2A unverified peer — ask me a thing$/.test(titles.get(operatorSession?.id) ?? ''),
  String(titles.get(operatorSession?.id)),
)

// --- 3. the message carries its own provenance ----------------------------
const tools = new Map(registered.map((definition) => [definition.name, definition]))
const messageChatelaine = tools.get('message_chatelaine')
const operatorAuthority = tools.get('operator_authority')
check('the tools registered', messageChatelaine !== undefined && operatorAuthority !== undefined, [...tools.keys()].join(','))

const operatorExec = { agent: { id: operatorSession?.id } }
await messageChatelaine.execute({ message: 'the peer wants a status report' }, operatorExec)
const notice = deliveries.filter((entry) => entry.sessionId === chatelaineSession?.id && entry.text.startsWith('[message')).at(-1)
check('the notice is delivered to the chatelaine', notice !== undefined, notice?.text?.split('\n')[0])
check(
  'the notice names the sending operator, task and session',
  /\[message\] from operator op_[0-9a-f]{16} \(task [0-9a-f]{8}, session a2a-op-[^)]+\)/.test(notice?.text ?? ''),
  notice?.text?.split('\n')[0],
)
check('the notice states the peer pairing', /peer: unverified/.test(notice?.text ?? ''), notice?.text?.split('\n')[1])
check('the notice states the authority window', /authority: none — no verified user intent/.test(notice?.text ?? ''), notice?.text?.split('\n')[1])

// a question wakes the chatelaine and still carries provenance
await messageChatelaine.execute({ message: 'may I', question: 'may I?', urgency: 'soon' }, operatorExec)
const question = deliveries.filter((entry) => entry.sessionId === chatelaineSession?.id && entry.text.includes('Question:')).at(-1)
check('a question wakes the chatelaine', question?.wake === true)
check('a question keeps the provenance header', /\[message \/ question \/ soon\] from operator op_/.test(question?.text ?? ''), question?.text?.split('\n')[0])
check('a question is asked on its own line', /\n\nQuestion: may I\?$/.test(question?.text ?? ''), JSON.stringify(question?.text?.split('\n').at(-1)))

// a session that is not an operator says so instead of pretending
await messageChatelaine.execute({ message: 'no handle here' }, { agent: { id: 'session-local-1' } })
const local = deliveries.filter((entry) => entry.sessionId === chatelaineSession?.id && entry.text.includes('no handle here')).at(-1)
check('a non-operator message says it has no handle', /from local session session-local-1/.test(local?.text ?? ''), local?.text?.split('\n')[0])

// --- 4. operator_authority with no handle IS the roster -------------------
const chatelaineExec = { agent: { id: chatelaineSession?.id } }
const roster = await operatorAuthority.execute({}, chatelaineExec)
check('the roster lists the operator', roster?.operators?.length === 1 && roster.operators[0].sessionId === operatorSession?.id, JSON.stringify(roster?.operators))
// The task already finished, so the row is done with no grant: state and
// authority are separate facts, and the roster must show both.
check('the roster row carries state and authority', roster?.operators?.[0]?.grant === 'none' && roster.operators[0].state === 'done' && roster.operators[0].level === 'peer', JSON.stringify(roster?.operators?.[0]))
check('the roster carries the paired peers', roster?.peers?.length === 1 && roster.peers[0].name === 'vienzie' && roster.peers[0].canVerifyV2 === true, JSON.stringify(roster?.peers))
check('no handle means no windows filter', Array.isArray(roster?.windows) && roster.windows.length === 0, JSON.stringify(roster?.windows))

const rosterText = operatorAuthority.output.render({}, roster).map((block) => block.text).join('\n')
check('the rendered roster is readable', /operators \(0 active of 1\): op_[0-9a-f]{16} · [0-9a-f]{8} · unpaired peer · peer, no grant · done/.test(rosterText), rosterText)
check('the rendered roster names the peers', /paired peers: vienzie$/.test(rosterText), rosterText)

// a single handle is still just that window
const one = await operatorAuthority.execute({ handle: roster.operators[0].handle }, chatelaineExec)
check('a handle asks about that operator only', one?.operators === undefined && one?.peers === undefined, JSON.stringify(Object.keys(one ?? {})))

// an operator asking about itself never sees the roster
const self = await operatorAuthority.execute({}, operatorExec)
check('an operator does not get the roster', self?.operators === undefined && self?.peers === undefined, JSON.stringify(Object.keys(self ?? {})))
check('an operator asking about someone else is refused', await (async () => {
  try {
    await operatorAuthority.execute({ handle: roster.operators[0].handle }, operatorExec)
    return false
  } catch (error) {
    return /chatelaine/i.test(error instanceof Error ? error.message : String(error))
  }
})())

// the chatelaine may not message itself — the roster is how it audits instead
check('the chatelaine cannot message itself', await (async () => {
  try {
    await messageChatelaine.execute({ message: 'note to self' }, chatelaineExec)
    return false
  } catch (error) {
    return /you are the chatelaine/i.test(error instanceof Error ? error.message : String(error))
  }
})())

console.log(failures === 0 ? 'ALL PROVENANCE PASS' : `PROVENANCE FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)
