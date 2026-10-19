import { apply } from './lib/index.js'
// Every probe sends `connection: close` so the server closes sockets after
// each response — pooled keep-alive sockets at process exit otherwise trip a
// libuv close-during-close assertion on win32 (the crash seen in smoke v1).
//
// Run from this directory: `node test-smoke.mjs` (exit 0 = all pass).
// The host needs node_modules prepared: `npm install` (pulls @a2a-js/sdk +
// schemastery) plus ambient links for @deepseek-ai/dsh-llm and dsh-session —
// see README install notes; on a real DSH host those resolve from the tree.

// Smoke test for the standalone (webServer-less) path of dsh-nuncia.
// fakeCtx fully stubs the DSH surface the port uses: the session-event and
// approval listeners are CAPTURED so the fake agent can simulate a real
// session producing assistant messages and a terminal turn — that is what
// publishes the A2A task's terminal status and lets message/send resolve.

const created = []
const listeners = {}       // event name -> [handler]
const disposers = []       // effect disposers retained, NOT fired eagerly
const fakeCtx = {
  get: () => undefined,    // no webServer / agentPresets / sessionPersistence
  logger: { error: (m) => console.error('[logger.error]', m), warn: (m) => console.error('[logger.warn]', m) },
  on: (name, handler) => { (listeners[name] ??= []).push(handler) },
  effect: (fn, name) => { const d = fn(); disposers.push([name, d]); },
  agents: {
    create: async (opts) => {
      created.push(opts)
      let pendingTurn = undefined
      const fakeAgent = {
        session: { id: String(opts.sessionId) },
        followup: (_message) => {
          // Simulate the DSH session pipeline: a committed assistant message,
          // then a normal turn end. whenIdle resolves only AFTER the turn
          // (like the real agent loop), which is what lets the session/event
          // handler — not the executor fallback — publish completion and
          // count it in the metrics.
          pendingTurn = new Promise((resolve) => {
            setTimeout(() => {
              const session = fakeAgent.session
              for (const h of listeners['session/event'] ?? []) {
                h(session, { type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'smoke reply' }] } } })
              }
              for (const h of listeners['session/event'] ?? []) {
                h(session, { type: 'turn/end', data: { reason: { kind: 'stop' } } })
              }
              resolve()
            }, 60)
          })
        },
        cancel: (_c) => {},
        whenIdle: async () => { if (pendingTurn) await pendingTurn },
      }
      return { agent: fakeAgent, dispose: async (_opts) => { void _opts } }
    },
  },
}

process.env.NUNCIA_TEST_TOKEN = 'smoke-token-123'
await apply(fakeCtx, {
  path: '/a2a',
  agentCardPath: '/.well-known/agent.json',
  adminPath: '/a2a/admin',
  port: 4199,
  host: '127.0.0.1',
  auth: { type: 'bearer', tokenEnv: 'NUNCIA_TEST_TOKEN' },
})

const TOKEN = 'smoke-token-123'
// NOTE: no exit-hook disposal — firing server.close() during process exit
// trips a libuv assertion on win32 (close-during-close). The OS reclaims the
// port when the process dies.
let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

// 1. AgentCard
const card = await (await fetch('http://127.0.0.1:4199/.well-known/agent.json', { headers: { connection: 'close' } })).json()
check('agent card', card.name === 'DeepSeek Harness Agent' && card.supportedInterfaces[0].protocolVersion === '1.0', `${card.name} @ ${card.supportedInterfaces[0].url}`)

// 2. no/wrong token -> 401
const bad = await fetch('http://127.0.0.1:4199/a2a', { method: 'POST', headers: { authorization: 'Bearer wrong', connection: 'close' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage' }) })
check('bad token 401', bad.status === 401)

// 3. admin status (authed)
const metrics = await (await fetch('http://127.0.0.1:4199/a2a/admin/status', { headers: { authorization: `Bearer ${TOKEN}`, connection: 'close' } })).json()
check('admin status', metrics.enabled === true && metrics.requests >= 2)

// 4. SendMessage -> executor creates agent, task completes via simulated session events
const res = await fetch('http://127.0.0.1:4199/a2a', {
  method: 'POST',
  headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', connection: 'close' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'SendMessage', params: { message: { messageId: 'm1', role: 'user', parts: [{ kind: 'text', text: 'smoke hi' }] }, metadata: {} } }),
})
const json = await res.json()
// SDK v1.3 wraps the task: result.task.status (v0.3-compat envelope)
const task = json?.result?.task ?? json?.result
check('send 200', res.status === 200)
check('task completed', task?.status?.state === 'TASK_STATE_COMPLETED', `state=${task?.status?.state}`)
check('agent created from task', created.length === 1, `meta=${JSON.stringify(created[0]?.meta)}`)

// 5. counters advanced
const m2 = await (await fetch('http://127.0.0.1:4199/a2a/admin/status', { headers: { authorization: `Bearer ${TOKEN}`, connection: 'close' } })).json()
check('metrics advanced', m2.totalTasks === 1 && m2.completedTasks === 1, JSON.stringify({ tasks: m2.totalTasks, done: m2.completedTasks }))

console.log(failures === 0 ? 'ALL SMOKE PASS' : `SMOKE FAILURES: ${failures}`)
process.exit(failures === 0 ? 0 : 1)

