/**
 * End-to-end authority test over real HTTP.
 *
 * Boots the plugin in standalone mode with the authority layer enabled and a
 * fake DSH context (same simulation as test-smoke.mjs), then proves the P1
 * inbound loop: an envelope from a paired peer is honored, a replayed one is
 * tolerated, and a tampered one fails down to `peer` while raising exactly one
 * security event — plus the admin mint/revoke surface.
 *
 * Two nodes are simulated with ONE pairing secret (that is the pairing model):
 * this node is `phone`, the peer is `desk`. Outbound envelopes (mint) point
 * origin=phone/target=desk; inbound ones point origin=desk/target=phone.
 *
 * Run: node test-authority-http.mjs   (exit 0 = all pass)
 */

import { createEnvelope, deriveAuthorityKey, verifyEnvelope } from './lib/authority.js'
import { apply, isLoopbackRequest } from './lib/index.js'

const SECRET = 'authority-test-secret-0123456789'
process.env.NUNCIA_TEST_TOKEN = 'authority-token-123'
process.env.NUNCIA_TEST_SECRET = SECRET

const BASE = 'http://127.0.0.1:4201'
const TOKEN = 'authority-token-123'
const AUTH = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', connection: 'close' }

const created = []
const listeners = {}
const injected = []
const services = {
  agentDefaultModel: { currentSelection: () => ({ provider: 'test-provider', model: 'test-model' }) },
}
const fakeCtx = {
  get: (name) => services[name],
  logger: { info: () => {}, error: (m) => console.error('[logger.error]', m), warn: () => {} },
  on: (name, handler) => { (listeners[name] ??= []).push(handler) },
  effect: (fn) => { fn() },
  emit: () => {},
  agents: {
    create: async (opts) => {
      created.push(opts)
      let pendingTurn
      const agent = {
        session: { id: String(opts.sessionId) },
        followup: () => {
          pendingTurn = new Promise((resolve) => {
            setTimeout(() => {
              for (const h of listeners['session/event'] ?? []) {
                h(agent.session, { type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'ok' }] } } })
              }
              for (const h of listeners['session/event'] ?? []) {
                h(agent.session, { type: 'turn/end', data: { reason: { kind: 'stop' } } })
              }
              resolve()
            }, 40)
          })
        },
        cancel: () => {},
        inject: (message) => { injected.push(message) },
        whenIdle: async () => { if (pendingTurn) await pendingTurn },
      }
      return { agent, dispose: async () => {} }
    },
  },
}

await apply(fakeCtx, {
  path: '/a2a',
  agentCardPath: '/.well-known/agent.json',
  adminPath: '/a2a/admin',
  port: 4201,
  host: '127.0.0.1',
  auth: { type: 'bearer', tokenEnv: 'NUNCIA_TEST_TOKEN' },
  authority: {
    enabled: true,
    nodeName: 'phone',
    pairingSecretEnv: 'NUNCIA_TEST_SECRET',
    peers: ['desk'],
    maxWindowMs: 10 * 60 * 1000,
    noticeSweepMs: 150,
  },
})

const KEY = deriveAuthorityKey(SECRET)

let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

const status = async () => (await fetch(`${BASE}/a2a/admin/status`, { headers: AUTH })).json()
const send = async (text, metadata, id) => {
  const res = await fetch(`${BASE}/a2a`, {
    method: 'POST',
    headers: AUTH,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id,
      method: 'SendMessage',
      params: { message: { messageId: `m-${id}`, role: 'user', parts: [{ kind: 'text', text }] }, metadata },
    }),
  })
  const body = await res.json()
  return { res, body, task: body?.result?.task ?? body?.result }
}

// 1. authority is enabled and reports itself
const s0 = await status()
check('authority enabled', s0.authority.enabled === true && s0.authority.nodeName === 'phone', JSON.stringify(s0.authority))
check('no grants yet', s0.authority.grants.length === 0)

// 2. mint an OUTBOUND grant (origin=phone -> target=desk)
const mintRes = await fetch(`${BASE}/a2a/admin/mint`, {
  method: 'POST',
  headers: AUTH,
  body: JSON.stringify({ level: 'intent', ttlMs: 60_000, scope: 'housekeeping', target: 'desk' }),
})
const minted = await mintRes.json()
check('mint 201', mintRes.status === 201, `status=${mintRes.status}`)
check('mint returns signed envelope', minted.ok === true && typeof minted.grant?.envelope?.sig === 'string')
check('mint grant shape', minted.grant?.level === 'intent' && minted.grant?.origin === 'phone' && minted.grant?.target === 'desk')

// The minted envelope must be acceptable to the PEER's gate (desk receiving phone).
const peerView = verifyEnvelope(minted.grant.envelope, {
  key: KEY,
  now: Date.now(),
  expectOrigin: 'phone',
  expectTarget: 'desk',
})
check('minted envelope verifies for the peer', peerView.ok === true, JSON.stringify(peerView))

// 3. mint validation errors are 400, not crashes
const badMint = await fetch(`${BASE}/a2a/admin/mint`, {
  method: 'POST',
  headers: AUTH,
  body: JSON.stringify({ level: 'housekeeper', target: 'desk' }),
})
check('invalid level rejected', badMint.status === 400)

const longMint = await fetch(`${BASE}/a2a/admin/mint`, {
  method: 'POST',
  headers: AUTH,
  body: JSON.stringify({ target: 'desk', ttlMs: 60 * 60 * 1000 }),
})
check('over-max window rejected', longMint.status === 400)

// 4. an INBOUND envelope (origin=desk -> target=phone) is honored as intent
const now = Date.now()
const inbound = createEnvelope(
  {
    level: 'intent',
    scope: 'housekeeping',
    origin: 'desk',
    target: 'phone',
    iat: now,
    exp: now + 60_000,
    jti: 'inbound-jti-000001',
  },
  KEY,
)
const good = await send('with intent', { authority: inbound }, 2)
check('granted send completed', good.task?.status?.state === 'TASK_STATE_COMPLETED', `state=${good.task?.status?.state}`)

const s1 = await status()
const goodTask = s1.tasks.find((t) => t.authority !== null)
check('task recorded as intent', goodTask?.authority?.level === 'intent', JSON.stringify(goodTask))
check('task recorded scope', goodTask?.authority?.scope === 'housekeeping')
check('no rejections yet', s1.authorityRejected === 0, `rejected=${s1.authorityRejected}`)

// The chatelaine is told a window opened — facts and a time bound, no grant bytes.
const noticeTexts = () => injected.map((m) => m.content?.[0]?.text ?? '')
const grantedNotice = noticeTexts().find((t) => t.includes('verified user intent'))
check('intent notice injected', grantedNotice !== undefined && grantedNotice.includes('peer "desk"'), grantedNotice?.split('\n')[0])
check('intent notice has no grant material', grantedNotice !== undefined && !/\bsig\b|jti|envelope/i.test(grantedNotice))
// The v4 session format REFUSES the retired `kind: 'plugin'` wrapper and the
// rejected write fails the whole turn (seen live on the AVD: a rejected
// envelope turned into a failed task). Producer-owned kind or nothing.
const noticeSources = () => injected.map((m) => m.source?.kind)
check('notice source is producer-owned', noticeSources().every((k) => k === 'plugin:dsh-nuncia'), JSON.stringify(noticeSources()))

// 5. same-link replay is tolerated (a retrying client is not an attacker)
const replay = await send('replay', { authority: inbound }, 3)
check('same-link replay tolerated', replay.task?.status?.state === 'TASK_STATE_COMPLETED')
const sReplay = await status()
check('replay not counted as rejection', sReplay.authorityRejected === 0)

// 6. a tampered envelope fails down to peer and raises one event
const tampered = { ...inbound, scope: 'everything' }
const bad = await send('tampered', { authority: tampered }, 4)
check('tampered send still completes as peer', bad.task?.status?.state === 'TASK_STATE_COMPLETED')

const s2 = await status()
const peerTask = s2.tasks.find((t) => t.authority === null)
check('tampered task treated as peer', peerTask !== undefined, JSON.stringify(s2.tasks))
check('rejection counted', s2.authorityRejected === 1, `rejected=${s2.authorityRejected}`)
check('security event recorded', s2.authority.securityEvents[0]?.reason === 'signature', JSON.stringify(s2.authority.securityEvents[0]))
check('security event names the task', s2.authority.securityEvents[0]?.detail?.taskId === peerTask?.taskId)

// 6b. an envelope minted for the peer must not be honored inbound (no bounce/transitivity)
const s3before = await status()
const bounced = await send('bounced', { authority: minted.grant.envelope }, 5)
check('bounced envelope completes as peer', bounced.task?.status?.state === 'TASK_STATE_COMPLETED')
const s3 = await status()
check('bounced envelope rejected', s3.authorityRejected === s3before.authorityRejected + 1, `rejected=${s3.authorityRejected}`)
check('bounced reason is target', s3.authority.securityEvents[0]?.reason === 'target-mismatch', JSON.stringify(s3.authority.securityEvents[0]))

// 6c. a rejected claim is announced to the agent (fail down, notify loud)
const rejectionNotice = noticeTexts().find((t) => t.includes('did not verify'))
check('rejection notice injected', rejectionNotice !== undefined, rejectionNotice?.split('\n')[0])

// 6d. a lapsed window is announced even when no further message arrives
const shortIat = Date.now()
const shortLived = createEnvelope(
  { level: 'intent', origin: 'desk', target: 'phone', iat: shortIat, exp: shortIat + 900, jti: 'inbound-jti-short1' },
  KEY,
)
const shortSend = await send('short window', { authority: shortLived }, 6)
check('short-window send accepted', shortSend.task?.status?.state === 'TASK_STATE_COMPLETED')
await new Promise((resolve) => setTimeout(resolve, 1600))
const lapseNotice = noticeTexts().find((t) => t.includes('window from peer "desk" has ended'))
check('expiry notice injected without a new message', lapseNotice !== undefined, lapseNotice?.split('\n')[0])
check('expiry notice drops the peer to peer', lapseNotice !== undefined && /arrive as "peer"/.test(lapseNotice))

// 7. revoke ends the local window
const revokeRes = await fetch(`${BASE}/a2a/admin/revoke`, {
  method: 'POST',
  headers: AUTH,
  body: JSON.stringify({ id: minted.grant.id }),
})
const revoked = await revokeRes.json()
check('revoke ok', revokeRes.status === 200 && revoked.revoked === true)

const s4 = await status()
check('grant gone after revoke', s4.authority.grants.length === 0)

// 8. minting requires the bearer token
const unauthorized = await fetch(`${BASE}/a2a/admin/mint`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', connection: 'close' },
  body: JSON.stringify({ target: 'desk' }),
})
check('mint requires auth', unauthorized.status === 401)

// 9. loopback predicate (the guard behind "minting is your own act")
check('loopback detected', isLoopbackRequest({ socket: { remoteAddress: '127.0.0.1' } }) === true)
check('ipv6 loopback detected', isLoopbackRequest({ socket: { remoteAddress: '::1' } }) === true)
check('lan address rejected', isLoopbackRequest({ socket: { remoteAddress: '192.168.1.20' } }) === false)
check('missing socket rejected', isLoopbackRequest({}) === false)

console.log(failures === 0 ? 'ALL AUTHORITY PASS' : `AUTHORITY FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)
