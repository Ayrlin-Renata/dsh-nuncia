/**
 * End-to-end authority test over real HTTP — v2 (per-node Ed25519 keys).
 *
 * Boots the plugin in standalone mode with the authority layer enabled and a
 * fake DSH context (same simulation as test-smoke.mjs), then proves the inbound
 * loop against a *real* second identity:
 *
 *   - this node is `phone` (its key is generated into a scratch dir),
 *   - the paired peer is `desk` (its key pair is created here),
 *   - a third node `ghost` exists but is NOT in the peer registry.
 *
 * The properties that matter:
 *
 *   1. A v2 envelope signed by desk verifies as `intent`.
 *   2. A tampered envelope fails down to `peer` with exactly one security event.
 *   3. A *valid* envelope cannot be minted by anyone else — `ghost` signing
 *      with its own key while claiming origin=desk is rejected (signature /
 *      kid mismatch), which is the whole reason for the asymmetric redesign.
 *   4. This node's own grant bounced back is not authority (no transitivity).
 *   5. Admin mint/revoke and the loopback guard still behave.
 *
 * Run: node tests/test-authority-http.mjs   (exit 0 = all pass)
 */

import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  createEnvelope,
  createEnvelopeV2,
  deriveAuthorityKey,
  verifyEnvelope,
  verifyEnvelopeV2,
} from '../lib/authority.js'
import { describeNodeKey } from '../lib/keys.js'
import { apply, isLoopbackRequest } from '../lib/index.js'

const STATE = mkdtempSync(join(tmpdir(), 'nuncia-authhttp-'))
const SECRET = 'authority-test-secret-0123456789'
process.env.NUNCIA_TEST_TOKEN = 'authority-token-123'
process.env.NUNCIA_TEST_SECRET = SECRET

const BASE = 'http://127.0.0.1:4201'
const TOKEN = 'authority-token-123'
const AUTH = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', connection: 'close' }

// -- identities --------------------------------------------------------------
const desk = describeNodeKey(generateKeyPairSync('ed25519').privateKey)
const ghost = describeNodeKey(generateKeyPairSync('ed25519').privateKey)

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
  persistenceRoot: STATE,
  authority: {
    enabled: true,
    nodeName: 'phone',
    pairingSecretEnv: 'NUNCIA_TEST_SECRET',
    // The peer's PUBLIC key is the only thing needed to verify it. `ghost` is
    // deliberately absent.
    peers: [{ name: 'desk', publicKey: desk.publicKeyText, kid: desk.kid }],
    maxWindowMs: 10 * 60 * 1000,
    noticeSweepMs: 150,
  },
})

const LEGACY_KEY = deriveAuthorityKey(SECRET)

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

// 1. authority is enabled and reports its identity
const s0 = await status()
check('authority enabled', s0.authority.enabled === true && s0.authority.nodeName === 'phone', JSON.stringify(s0.authority.enabled))
check('envelope version is 2', s0.authority.envelopeVersion === 2, String(s0.authority.envelopeVersion))
const phone = s0.authority.identity
check('node identity exposes kid + public key', typeof phone?.kid === 'string' && typeof phone?.publicKey === 'string', JSON.stringify(phone))
check('private key never appears in status', !JSON.stringify(s0.authority).includes('"privateKey"'))
check('no grants yet', s0.authority.grants.length === 0)

// 2. mint an OUTBOUND grant (origin=phone -> target=desk)
const mintRes = await fetch(`${BASE}/a2a/admin/mint`, {
  method: 'POST',
  headers: AUTH,
  body: JSON.stringify({ level: 'intent', ttlMs: 60_000, scope: 'housekeeping', target: 'desk' }),
})
const minted = await mintRes.json()
const mintedEnvelope = minted.grant?.envelope
check('mint 201', mintRes.status === 201, `status=${mintRes.status}`)
check('mint returns a v2 envelope', mintedEnvelope?.v === 2 && mintedEnvelope?.kid === phone?.kid, JSON.stringify({ v: mintedEnvelope?.v, kid: mintedEnvelope?.kid }))
check('mint grant shape', minted.grant?.level === 'intent' && minted.grant?.origin === 'phone' && minted.grant?.target === 'desk')

// The minted envelope must verify for the PEER with this node's *public* key.
const peerView = verifyEnvelopeV2(mintedEnvelope, {
  publicKey: phone.publicKey,
  now: Date.now(),
  expectOrigin: 'phone',
  expectTarget: 'desk',
})
check('minted envelope verifies with the public key', peerView.ok === true, JSON.stringify(peerView))
// ...and a different key cannot.
const wrongKeyView = verifyEnvelopeV2(mintedEnvelope, { publicKey: desk.publicKeyText, now: Date.now() })
check('minted envelope does not verify with a foreign key', wrongKeyView.ok === false, String(wrongKeyView.reason))

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

// 4. an INBOUND envelope signed by desk is honored as intent
const now = Date.now()
const inbound = createEnvelopeV2(
  {
    level: 'intent',
    scope: 'housekeeping',
    origin: 'desk',
    target: 'phone',
    iat: now,
    exp: now + 60_000,
    jti: 'inbound-jti-000001',
  },
  { privateKey: desk.privateKey, kid: desk.kid },
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

// 6. THE asymmetry test: ghost holds no key we trust, and even signing with its
// own key while claiming desk's identity cannot produce our notion of "desk".
const ghostClaimsDesk = createEnvelopeV2(
  { level: 'intent', scope: 'everything', origin: 'desk', target: 'phone', iat: Date.now(), exp: Date.now() + 60_000, jti: 'ghost-jti-000001' },
  { privateKey: ghost.privateKey, kid: desk.kid },
)
const ghostSend = await send('ghost claims desk', { authority: ghostClaimsDesk }, 4)
check('impersonated origin still completes as peer', ghostSend.task?.status?.state === 'TASK_STATE_COMPLETED', `state=${ghostSend.task?.status?.state}`)
const sGhost = await status()
check('impersonation counted as rejection', sGhost.authorityRejected === 1, `rejected=${sGhost.authorityRejected}`)
check('impersonation rejected on signature', sGhost.authority.securityEvents[0]?.reason === 'signature', JSON.stringify(sGhost.authority.securityEvents[0]))

// 6b. an unknown origin with a valid-looking key is refused outright
const stranger = createEnvelopeV2(
  { level: 'intent', origin: 'stranger', target: 'phone', iat: Date.now(), exp: Date.now() + 60_000, jti: 'stranger-jti-01' },
  { privateKey: ghost.privateKey, kid: ghost.kid },
)
await send('stranger', { authority: stranger }, 5)
const sStranger = await status()
check('unknown origin rejected', sStranger.authority.securityEvents[0]?.reason === 'unknown-origin', JSON.stringify(sStranger.authority.securityEvents[0]))

// 6c. a tampered envelope fails down to peer and raises one event
const tampered = { ...inbound, scope: 'everything' }
const bad = await send('tampered', { authority: tampered }, 6)
check('tampered send still completes as peer', bad.task?.status?.state === 'TASK_STATE_COMPLETED')
const s2 = await status()
check('tampered task treated as peer', s2.tasks.some((t) => t.authority === null))
check('security event recorded', s2.authority.securityEvents[0]?.reason === 'signature', JSON.stringify(s2.authority.securityEvents[0]))
check('security event names the task', typeof s2.authority.securityEvents[0]?.detail?.taskId === 'string')

// 6d. this node's own grant bounced back is not authority (no transitivity)
const before = (await status()).authorityRejected
const bounced = await send('bounced', { authority: mintedEnvelope }, 7)
check('bounced envelope completes as peer', bounced.task?.status?.state === 'TASK_STATE_COMPLETED')
const s3 = await status()
check('bounced envelope rejected', s3.authorityRejected === before + 1, `rejected=${s3.authorityRejected}`)
check('bounced reason is self-claim', s3.authority.securityEvents[0]?.reason === 'origin-mismatch', JSON.stringify(s3.authority.securityEvents[0]))

// 6e. a rejected claim is announced to the agent (fail down, notify loud)
const rejectionNotice = noticeTexts().find((t) => t.includes('did not verify'))
check('rejection notice injected', rejectionNotice !== undefined, rejectionNotice?.split('\n')[0])

// 6f. legacy v1 is still accepted while allowV1 is on (migration window)
const legacy = createEnvelope(
  { level: 'intent', origin: 'desk', target: 'phone', iat: Date.now(), exp: Date.now() + 60_000, jti: 'legacy-jti-0001' },
  LEGACY_KEY,
)
const legacySend = await send('legacy v1', { authority: legacy }, 8)
check('legacy v1 accepted during migration', legacySend.task?.status?.state === 'TASK_STATE_COMPLETED')
const sLegacy = await status()
check('legacy v1 honored as intent', sLegacy.tasks.some((t) => t.authority?.level === 'intent' && t.authority?.origin === 'desk'))

// 6g. a lapsed window is announced even when no further message arrives
const shortIat = Date.now()
const shortLived = createEnvelopeV2(
  { level: 'intent', origin: 'desk', target: 'phone', iat: shortIat, exp: shortIat + 900, jti: 'inbound-jti-short1' },
  { privateKey: desk.privateKey, kid: desk.kid },
)
const shortSend = await send('short window', { authority: shortLived }, 9)
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
