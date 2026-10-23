/**
 * Tests for DESIGN §20.19 — standing directives, operator replies, refusals.
 *
 * The design question this pins down: an operator that forwards every decision
 * to the chatelaine is a text transformer, and one that decides everything
 * alone is unsupervised. Three things make the middle possible:
 *
 *  - `send_nuncia` has a second lane: an operator may reply on ITS OWN
 *    conversation (ask the requester what is missing) and on no other.
 *  - `refuse_request` is a real protocol outcome (TASK_STATE_REJECTED with the
 *    reason), except when the request carries verified user intent — that is
 *    escalated, never refused.
 *  - `post_directive` records a decision the chatelaine just made as a
 *    time-boxed rule: existing operators are told QUIETLY (inject, never
 *    followup — nobody is woken to be told a rule changed), new operators get
 *    it in their brief, and it lapses on its own with a quiet notice.
 *
 * Run: node test-directives.mjs   (exit 0 = all pass)
 */

import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { TaskState } from '@a2a-js/sdk'
import { apply, postDirectiveTool, refuseRequestTool, sendNunciaTool } from '../lib/index.js'
import { DirectiveBook, directiveBriefLines } from '../lib/directives.js'
import { operatorBrief } from '../lib/chatelaine.js'

let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

const textOf = (message) => (message?.content ?? []).map((block) => block?.text ?? '').join('\n').trim()
const throws = async (fn, pattern) => {
  try {
    await fn()
    return false
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return pattern.test(message)
  }
}

// --- 1. the book: persistence, expiry, validation ---------------------------
const BOOK_DIR = mkdtempSync(join(tmpdir(), 'nuncia-dir-book-'))
const BOOK_FILE = join(BOOK_DIR, 'directives.json')
const book = new DirectiveBook(BOOK_FILE)
await book.init()
check('a missing book starts empty', book.list().length === 0)

const fiveHours = await book.add({ text: 'The printer is booked until 18:00 — refuse requests for printer usage.', ttlMs: 5 * 60 * 60_000 })
check('a directive is stored with an expiry', typeof fiveHours.id === 'string' && fiveHours.expiresAt > Date.now(), JSON.stringify(fiveHours))
check('the directive is active', book.active().length === 1)
check('the directive renders with its remaining time', directiveBriefLines(book.active()).join('\n').includes('~5 h left'), directiveBriefLines(book.active()).join(' | '))

const reloaded = new DirectiveBook(BOOK_FILE)
await reloaded.init()
check('the book reloads from disk', reloaded.list().length === 1 && reloaded.list()[0].text === fiveHours.text)

// Expiry is idempotent: the sweep calls it every few seconds and must report
// each lapse exactly once.
const lapsedBook = new DirectiveBook(join(BOOK_DIR, 'lapsed.json'))
await lapsedBook.init()
const lapsed = await lapsedBook.add({ text: 'Old policy', ttlMs: 60_000, now: Date.now() - 120_000 })
check('a lapsed directive is not active', lapsedBook.active().length === 0)
const firstExpire = await lapsedBook.expire()
const secondExpire = await lapsedBook.expire()
check('expire() returns a lapse once', firstExpire.length === 1 && firstExpire[0].id === lapsed.id)
check('expire() is idempotent', secondExpire.length === 0)

check('a directive needs text', await throws(() => book.add({ text: '   ', ttlMs: 60_000 }), /needs text/))
check('a directive must last at least a minute', await throws(() => book.add({ text: 'x', ttlMs: 1_000 }), /between/))
check('a directive cannot outlive the cap', await throws(() => book.add({ text: 'x', ttlMs: 31 * 24 * 60 * 60_000 }), /between/))
check('a directive can be withdrawn', await book.remove(fiveHours.id) === true && book.active().length === 0)

// --- 2. the operator brief carries the policy -------------------------------
const withPolicy = operatorBrief({
  handle: 'op_0123456789abcdef',
  taskId: 'task-1',
  level: 'peer',
  origin: 'vienzie',
  workspace: 'C:/house/operators',
  nodeName: 'sylviana',
  peers: [{ name: 'vienzie' }],
  directives: [{ text: 'Refuse printer requests until 18:00.', remainingMs: 5 * 60 * 60_000 }],
})
check('the brief carries the active directive', withPolicy.includes('Refuse printer requests until 18:00.') && withPolicy.includes('~5 h left'))
check('the brief says user intent overrides a directive', withPolicy.includes('verified user intent') && withPolicy.includes('escalate'))
check('the brief gives the operator its reply lane', withPolicy.includes('send_nuncia') && withPolicy.includes('refuse_request'))
check('the brief keeps new conversations the chatelaine\'s', withPolicy.includes('opening a NEW conversation is the chatelaine\'s'))
const withoutPolicy = operatorBrief({ handle: 'op_x', taskId: 't', level: 'peer', workspace: 'C:/w', nodeName: 'n', peers: [] })
check('the brief says so when no directive is in force', withoutPolicy.includes('No standing directives are in force.'))

// --- 3. post_directive: quiet delivery, chatelaine only ---------------------
const posted = []
const fakeChatelaine = {
  peekId: async () => 'a2a-chatelaine-test',
  send: async (sessionId, text, mode = {}) => { posted.push({ sessionId, text, wake: mode.wake === true }); return { delivered: true } },
}
const liveOperator = { taskId: 't1', sessionId: 'a2a-op-peer-t1', contextId: 'ctx-1', terminalPublished: false }
const doneOperator = { taskId: 't2', sessionId: 'a2a-op-peer-t2', contextId: 'ctx-2', terminalPublished: true }
const recordMap = new Map([[liveOperator.taskId, liveOperator], [doneOperator.taskId, doneOperator]])
const directiveBook = new DirectiveBook(join(BOOK_DIR, 'posted.json'))
await directiveBook.init()
const postTool = postDirectiveTool(fakeChatelaine, directiveBook, { records: recordMap, logger: { debug: () => {} } })
const postResult = await postTool.execute(
  { text: 'Printer booked — refuse printer requests.', ttlMinutes: 300 },
  { agent: { id: 'a2a-chatelaine-test' } },
)
check('post_directive stores the rule', directiveBook.active().length === 1 && directiveBook.active()[0].text === 'Printer booked — refuse printer requests.')
check('post_directive honours the lifetime', postResult.expiresAt - Date.now() > 4.9 * 60 * 60_000, String(postResult.expiresAt))
check('post_directive tells live operators without waking them', posted.length === 1 && posted[0].sessionId === 'a2a-op-peer-t1' && posted[0].wake === false, JSON.stringify(posted))
check('post_directive skips finished tasks', posted.every((entry) => entry.sessionId !== 'a2a-op-peer-t2'))
check('post_directive reports who it told', postResult.operatorsNotified === 1)
check('post_directive is the chatelaine\'s', await throws(
  () => postTool.execute({ text: 'x' }, { agent: { id: 'a2a-op-peer-t1' } }),
  /chatelaine only/,
))

// --- 4. send_nuncia: the operator lane --------------------------------------
const sent = []
const fakeOutbound = {
  send: async (request) => {
    sent.push(request)
    return { peer: request.peer, taskId: 'peer-task-1', contextId: request.contextId, state: 'TASK_STATE_COMPLETED', text: 'ok' }
  },
}
const operatorRecord = { taskId: 'task-9', contextId: 'ctx-9', authority: { level: 'peer', origin: 'vienzie' }, terminalPublished: false }
const sendTool = sendNunciaTool(
  fakeChatelaine,
  fakeOutbound,
  new Map([['task-9', operatorRecord]]),
  () => operatorRecord,
)
const reply = await sendTool.execute({ peer: 'vienzie', text: 'Which printer did you mean?' }, { agent: { id: 'a2a-op-peer-task-9' } })
check('an operator may reply on its own conversation', sent.length === 1 && sent[0].contextId === 'ctx-9' && reply.contextId === 'ctx-9', JSON.stringify(sent))
check('an operator may not address another peer', await throws(
  () => sendTool.execute({ peer: 'someone-else', text: 'hi' }, { agent: { id: 'a2a-op-peer-task-9' } }),
  /only reply on its own conversation/,
))
check('an operator with no verified peer is refused', await throws(
  () => sendNunciaTool(fakeChatelaine, fakeOutbound, new Map(), () => ({ taskId: 't', contextId: 'c', authority: undefined }))
    .execute({ peer: 'vienzie', text: 'hi' }, { agent: { id: 'a2a-op-peer-t' } }),
  /no verified peer name/,
))
check('send_nuncia still refuses an unknown session', await throws(
  () => sendNunciaTool(fakeChatelaine, fakeOutbound, new Map(), () => undefined)
    .execute({ peer: 'vienzie', text: 'hi' }, { agent: { id: 'session-nobody' } }),
  /belongs to the chatelaine/,
))

// --- 5. refuse_request: a real outcome, with the intent guard ---------------
const published = []
const doneMarks = []
const refusals = []
const refusingChatelaine = {
  peekId: async () => 'a2a-chatelaine-test',
  report: async (text) => { refusals.push(text); return { delivered: true } },
}
const peerRecord = {
  taskId: 'task-refuse',
  contextId: 'ctx-refuse',
  handle: 'op_fedcba9876543210',
  authority: { level: 'peer', origin: 'vienzie' },
  terminalPublished: false,
  eventBus: { publish: (event) => published.push(event) },
}
const refuseTool = refuseRequestTool(refusingChatelaine, new Map(), {
  operators: { markDone: async (taskId) => { doneMarks.push(taskId) } },
  recordOf: () => peerRecord,
  logger: { debug: () => {} },
})
const refusal = await refuseTool.execute({ reason: 'The printer is booked until 18:00.' }, { agent: { id: 'a2a-op-peer-task-refuse' } })
check('a refusal is recorded', refusal.refused === true && peerRecord.terminalPublished === true)
const statusEvent = published[0]
check('a refusal publishes TASK_STATE_REJECTED',
  statusEvent?.kind === 'statusUpdate' && statusEvent?.data?.status?.state === TaskState.TASK_STATE_REJECTED,
  JSON.stringify(statusEvent?.data?.status?.state))
check('the requester reads the reason', statusEvent?.data?.status?.message?.parts?.[0]?.content?.value === 'The printer is booked until 18:00.')
check('the operator is marked done', doneMarks[0] === 'task-refuse')
check('the chatelaine learns of the refusal', refusals.some((text) => text.includes('refused task task-refuse') && text.includes('printer is booked')))

const intentRecord = {
  taskId: 'task-intent',
  contextId: 'ctx-intent',
  handle: 'op_1111222233334444',
  authority: { level: 'intent', origin: 'vienzie' },
  terminalPublished: false,
  eventBus: { publish: () => {} },
}
check('a request with user intent cannot be refused', await throws(
  () => refuseRequestTool(refusingChatelaine, new Map(), { operators: undefined, recordOf: () => intentRecord, logger: { debug: () => {} } })
    .execute({ reason: 'busy' }, { agent: { id: 'a2a-op-intent-task-intent' } }),
  /verified user intent.*escalate/,
))
check('a refusal needs a reason', await throws(
  () => refuseTool.execute({ reason: '  ' }, { agent: { id: 'a2a-op-peer-task-refuse' } }),
  /needs a reason/,
))
check('the chatelaine does not refuse with the operator\'s tool', await throws(
  () => refuseTool.execute({ reason: 'no' }, { agent: { id: 'a2a-chatelaine-test' } }),
  /operator's tool/,
))

// --- 6. wired end to end: the sweep reports a lapse quietly ----------------
const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-dir-house-'))
const STATE = mkdtempSync(join(tmpdir(), 'nuncia-dir-state-'))
const STATE_DIR = join(HOUSE, '.nuncia')
mkdirSync(STATE_DIR, { recursive: true })
// Pre-seed the book with one ACTIVE rule and one already-lapsed rule: the
// lapsed one must produce exactly one quiet notice, the active one must reach
// the next operator's brief.
const seededActive = {
  id: 'dir_aaaaaaaaaaaa',
  text: 'Printer booked until 18:00 — refuse printer requests.',
  createdAt: Date.now() - 60_000,
  expiresAt: Date.now() + 5 * 60 * 60_000,
}
const seededLapsed = {
  id: 'dir_bbbbbbbbbbbb',
  text: 'Old policy that lapsed.',
  createdAt: Date.now() - 300_000,
  expiresAt: Date.now() - 120_000,
}
writeFileSync(join(STATE_DIR, 'directives.json'), JSON.stringify({ version: 1, directives: [seededActive, seededLapsed] }))

process.env.NUNCIA_TEST_TOKEN = 'dir-token-123'
const deliveries = []
const registered = []
const created = []
const live = new Map()
const listeners = {}
const titles = new Map()

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

const fakeCtx = {
  get: (name) => ({
    agentDefaultModel: { currentSelection: () => ({ provider: 'p', model: 'm' }) },
    tools: { register: (definition) => { registered.push(definition); return () => {} } },
    workspaceRegistry: {
      create: async (path, title) => ({
        get title() { return title },
        setTitle: () => {},
        attachSession: async () => {},
      }),
    },
    sessionTitle: {
      get: (session) => titles.get(String(session?.id)),
      rename: async (session, title) => { titles.set(String(session?.id), title) },
    },
  })[name],
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
  port: 4213,
  host: '127.0.0.1',
  auth: { type: 'bearer', tokenEnv: 'NUNCIA_TEST_TOKEN' },
  chatelaine: { workspace: HOUSE, directiveSweepMs: 60 },
  authority: { enabled: true, nodeName: 'dirnode', peers: [] },
  persistenceRoot: STATE,
})

const chatelaineSession = created.find((entry) => entry.id.startsWith('a2a-chatelaine-'))
// The sweep is a timer; give it a couple of intervals.
await new Promise((resolve) => setTimeout(resolve, 400))
const lapseNotices = deliveries.filter((entry) => entry.text.includes('[directive]') && entry.text.includes('expired'))
check('the chatelaine hears about a lapse', lapseNotices.length === 1, JSON.stringify(deliveries.map((d) => d.text.slice(0, 60))))
check('the lapse notice does not wake the chatelaine', lapseNotices[0]?.wake === false)
check('the lapse notice names the rule', lapseNotices[0]?.text.includes('Old policy that lapsed.'))
check('the lapse notice lands in the chatelaine session', lapseNotices[0]?.sessionId === chatelaineSession?.id)

const post = await fetch('http://127.0.0.1:4213/a2a', {
  method: 'POST',
  headers: { authorization: 'Bearer dir-token-123', 'content-type': 'application/json', connection: 'close' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'SendMessage',
    params: { message: { messageId: 'd1', role: 'user', parts: [{ kind: 'text', text: 'print a page' }] }, metadata: {} },
  }),
})
const json = await post.json()
check('a task still runs with directives loaded', (json?.result?.task ?? json?.result)?.status?.state === 'TASK_STATE_COMPLETED', JSON.stringify(json?.result?.task?.status))
const operatorId = created.map((entry) => entry.id).find((id) => id.startsWith('a2a-op-'))
const operatorBriefDelivery = deliveries.find((entry) => entry.sessionId === operatorId && entry.text.startsWith('[operator brief]'))
check('a new operator is briefed under the directive in force', operatorBriefDelivery?.text.includes('Printer booked until 18:00'), operatorBriefDelivery?.text?.slice(0, 200))
check('a new operator is not briefed under a lapsed one', operatorBriefDelivery?.text.includes('Old policy that lapsed.') !== true)

console.log(failures === 0 ? '\nALL DIRECTIVES PASS' : `\nDIRECTIVE FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)
