/**
 * P3.0 end-to-end: the auth posture of a raw install.
 *
 * The operator's rule (2026-10-20): the endpoint serves, but only to requests
 * that carry a valid bearer. A client without one gets an invalid-auth notice
 * and never reaches a session or an agent. A raw install with no configured
 * token used to be wide open — that is what this file proves is gone.
 *
 * Run: node tests/test-p3-auth.mjs   (exit 0 = all pass)
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../lib/index.js'

const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-p3-'))
const STATE = mkdtempSync(join(tmpdir(), 'nuncia-p3-state-'))
const PORT = 4211

const listeners = {}
const disposers = []
const created = []
const services = {
  agentDefaultModel: { currentSelection: () => ({ provider: 'p3-provider', model: 'p3-model' }) },
}

function makeAgent(id) {
  const agent = {
    session: { id },
    inject: () => {},
    followup: () => {},
    cancel: () => {},
    whenIdle: async () => {},
  }
  return agent
}

const fakeCtx = {
  get: (name) => services[name],
  logger: { info: () => {}, error: (m) => console.error('[logger.error]', m), warn: (m) => console.error('[logger.warn]', m) },
  on: (name, handler) => { (listeners[name] ??= []).push(handler) },
  effect: (fn) => { disposers.push(fn()) },
  agents: {
    create: async (options) => {
      const id = String(options.sessionId)
      created.push(id)
      return { agent: makeAgent(id), dispose: async () => {} }
    },
  },
}

// A RAW install: no auth block at all, no authority layer, no token anywhere.
await apply(fakeCtx, {
  path: '/a2a',
  agentCardPath: '/.well-known/agent.json',
  adminPath: '/a2a/admin',
  port: PORT,
  host: '127.0.0.1',
  chatelaine: { workspace: HOUSE, stateDir: STATE },
})

let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

// The generated token is persisted where the human can read it.
const tokenFile = join(STATE, 'bearer.token')
let generated = ''
try {
  generated = readFileSync(tokenFile, 'utf8').trim()
} catch {
  // leave empty; the check below reports it
}
check('a raw install generates and persists a bearer', generated.length >= 32, `len=${generated.length}`)

// 1. The endpoint SERVES — but only to a request with the right bearer.
const noAuth = await fetch(`http://127.0.0.1:${PORT}/a2a`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', connection: 'close' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message: { messageId: 'm1', role: 'user', parts: [{ kind: 'text', text: 'hi' }] }, metadata: {} } }),
})
check('a request without a bearer is refused', noAuth.status === 401, `status=${noAuth.status}`)
const notice = await noAuth.json()
check('the refusal carries an invalid-auth notice', notice.error === 'unauthorized' && typeof notice.detail === 'string', JSON.stringify(notice))
check('no session was created by the refused request', created.length === 0, `created=${created.length}`)

const wrongAuth = await fetch(`http://127.0.0.1:${PORT}/a2a`, {
  method: 'POST',
  headers: { authorization: 'Bearer not-the-token', 'content-type': 'application/json', connection: 'close' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'SendMessage' }),
})
check('a request with a wrong bearer is refused', wrongAuth.status === 401, `status=${wrongAuth.status}`)

// 2. The card is auth-gated too (a discovery surface is not a free surface).
const cardNoAuth = await fetch(`http://127.0.0.1:${PORT}/.well-known/agent.json`, { headers: { connection: 'close' } })
check('the card without a bearer is refused', cardNoAuth.status === 401, `status=${cardNoAuth.status}`)
const cardResp = await fetch(`http://127.0.0.1:${PORT}/.well-known/agent.json`, { headers: { authorization: `Bearer ${generated}`, connection: 'close' } })
const card = await cardResp.json()
check('the card with a bearer is served', cardResp.status === 200, `status=${cardResp.status}`)
const nodeExt = (card.capabilities?.extensions ?? []).find((ext) => ext.uri === 'https://nuncia.local/a2a/node')
check('the card carries the minimal node fields', nodeExt?.params?.name !== undefined && nodeExt?.params?.platform !== undefined && nodeExt?.params?.announcement !== undefined, JSON.stringify(nodeExt?.params))

// 3. The admin surface is guarded as well.
const adminNoAuth = await fetch(`http://127.0.0.1:${PORT}/a2a/admin/status`, { headers: { connection: 'close' } })
check('the admin surface without a bearer is refused', adminNoAuth.status === 401, `status=${adminNoAuth.status}`)

// 4. With the bearer, everything works and the identity is reported.
const status = await (await fetch(`http://127.0.0.1:${PORT}/a2a/admin/status`, { headers: { authorization: `Bearer ${generated}`, connection: 'close' } })).json()
check('the status reports the identity', status.identity?.name !== undefined && status.identity?.authSource === 'generated', JSON.stringify(status.identity))
check('the status reports the announcement field', typeof status.identity?.announcement === 'string')

// 5. The announcement can be set (loopback) and is then visible on the card.
const put = await fetch(`http://127.0.0.1:${PORT}/a2a/admin/announcement`, {
  method: 'PUT',
  headers: { authorization: `Bearer ${generated}`, 'content-type': 'application/json', connection: 'close' },
  body: JSON.stringify({ announcement: 'Reindexing the house rules' }),
})
check('the announcement can be set', put.status === 200, `status=${put.status}`)
const card2 = await (await fetch(`http://127.0.0.1:${PORT}/.well-known/agent.json`, { headers: { authorization: `Bearer ${generated}`, connection: 'close' } })).json()
const nodeExt2 = (card2.capabilities?.extensions ?? []).find((ext) => ext.uri === 'https://nuncia.local/a2a/node')
check('the announcement shows on the card', nodeExt2?.params?.announcement === 'Reindexing the house rules', JSON.stringify(nodeExt2?.params?.announcement))

console.log(failures === 0 ? 'ALL P3-AUTH PASS' : `P3-AUTH FAILURES: ${failures}`)
// NOTE: no exit-hook disposal — firing server.close() during process exit trips
// a libuv close-during-close assertion on win32 (the same trip we hit in smoke
// v1). The OS reclaims the port when the process dies.
process.exit(failures === 0 ? 0 : 1)
