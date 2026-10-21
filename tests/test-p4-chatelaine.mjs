/**
 * P4.1 acceptance: the chatelaine is a session the HUMAN can find and open.
 *
 * What is being proved, and why each part matters:
 *
 *  1. It is created at BOOT, not lazily on the first report. The old behaviour
 *     left a node with no chatelaine at all until something reported — and then
 *     only an id with no session behind it.
 *  2. It lives in its OWN directory (`<workspace>/chatelaine`). DSH labels a
 *     session by the basename of its workspace path, so this is what makes it a
 *     `Chatelaine` row instead of an anonymous `housekeeping` one.
 *  3. It is ATTACHED to a workspace record. A session in no record is not
 *     listed at all (`workspace.sessionIds` is what the client groups by).
 *  4. It is BRIEFED and WOKEN — one followup turn — so the thread exists and
 *     the model knows it is the chatelaine rather than an operator.
 *  5. A reload does not create a second session and does not re-brief.
 *  6. `new` cuts over to a fresh session while keeping the old id as
 *     `previousSessionId`, so a handoff can be pasted in by hand.
 */
import { existsSync, mkdtempSync } from 'node:fs'
import { readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CHATELAINE_SUBDIR, createChatelaineRuntime } from '../lib/chatelaine.js'

const HOUSE = mkdtempSync(join(tmpdir(), 'nuncia-p41-'))
const STATE = join(HOUSE, '.nuncia')
// The brief embeds a snapshot of the rules at brief time (the chatelaine's
// tool scope may not include fs tools), so give it content to embed.
const RULES_MARKER = 'RULE-1-chatelaine-brief-snapshot'
writeFileSync(join(HOUSE, 'HOUSE-RULES.md'), `# House rules\n${RULES_MARKER}\n`, 'utf8')
const deliveries = []
const created = []
const attached = []
const workspaces = []
const existing = new Set()
const live = new Map()

const textOf = (message) => (message?.content ?? [])
  .map((block) => (block?.type === 'text' ? block.text : ''))
  .filter(Boolean)
  .join('\n')

function agentFor(id, cwd) {
  return {
    // The header is what DSH's workspace registry reads (and what pins the
    // session to a directory), so the fake must carry it too.
    session: { id, header: { id, cwd } },
    inject: (message) => { deliveries.push({ sessionId: id, kind: 'inject', text: textOf(message) }) },
    followup: (message) => { deliveries.push({ sessionId: id, kind: 'followup', text: textOf(message) }) },
    steer: () => {},
    cancel: () => {},
    whenIdle: async () => {},
  }
}

const sessionCwd = new Map()

const agents = {
  create: async (options) => {
    const id = String(options.sessionId)
    if (existing.has(id)) throw new Error(`session ${id} already exists`)
    // The directory must exist BEFORE the session: DSH resolves the session's
    // cwd when it runs, so a session created ahead of its directory fails its
    // first turn with "working-directory: directory does not exist".
    if (options.meta?.cwd !== undefined && !existsSync(options.meta.cwd)) {
      throw new Error(`working-directory: directory does not exist: "${options.meta.cwd}"`)
    }
    created.push({ id, options })
    existing.add(id)
    sessionCwd.set(id, options.meta?.cwd)
    const agent = agentFor(id, options.meta?.cwd)
    live.set(id, agent)
    return { agent, dispose: async () => { live.delete(id) } }
  },
  get: (id) => live.get(String(id)),
  resume: async ({ resumeSessionId }) => {
    const id = String(resumeSessionId)
    // Strict on purpose: a session that was never created cannot be resumed.
    // The permissive fake in the older harnesses hid exactly this bug.
    if (!existing.has(id)) throw new Error(`no such session ${id}`)
    if (!live.has(id)) live.set(id, agentFor(id, sessionCwd.get(id)))
    return { agent: live.get(id), dispose: async () => { live.delete(id) } }
  },
}

const ctx = {
  agents,
  logger: { info: () => {}, warn: (m) => console.error('[warn]', m), debug: () => {} },
  get: (name) => (name === 'workspaceRegistry' ? registry : undefined),
}

const registry = {
  create: async (path, title) => {
    workspaces.push({ path, title })
    return {
      title,
      setTitle: async (next) => { workspaces.push({ path, title: next, retitled: true }) },
      attachSession: async (sessionId) => { attached.push(String(sessionId)) },
    }
  },
}

const options = {
  ctx,
  config: { chatelaine: {} },
  workspace: HOUSE,
  stateDir: STATE,
  nodeName: 'testnode',
  logger: ctx.logger,
}

const chatelaine = createChatelaineRuntime(options)

let failures = 0
const check = (name, cond, detail = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!cond) failures++
}

// --- 1. boot ---------------------------------------------------------------
const first = await chatelaine.ensure()
check('boot created a chatelaine session', first.ok === true && first.created === true, JSON.stringify(first))
check('the id is tagged', String(first.sessionId).startsWith('a2a-chatelaine-'), first.sessionId)
const chatelaineCwd = join(HOUSE, CHATELAINE_SUBDIR)
check('it lives in its own directory', created[0]?.options?.meta?.cwd === chatelaineCwd, created[0]?.options?.meta?.cwd)
check('its cwd basename is "chatelaine"', chatelaineCwd.split(/[\\/]/).pop() === 'chatelaine', chatelaineCwd)

// --- 2. visible ------------------------------------------------------------
const ws = workspaces.find((entry) => entry.path === chatelaineCwd)
check('a workspace record exists at its directory', ws !== undefined, JSON.stringify(workspaces))
check('that workspace is titled Chatelaine', ws?.title === 'Chatelaine', ws?.title)
check('the session is attached to it', attached.includes(String(first.sessionId)), JSON.stringify(attached))

// --- 3. briefed and woken --------------------------------------------------
const brief = deliveries.find((delivery) => delivery.text.startsWith('[chatelaine brief]'))
check('the brief was delivered', brief !== undefined, deliveries.map((d) => d.text.slice(0, 30)).join(' | '))
check('the brief wakes it (followup, not a silent inject)', brief?.kind === 'followup', brief?.kind)
check('the brief says it is the chatelaine, not an operator', /You are the chatelaine of node "testnode"/.test(brief?.text ?? ''), brief?.text?.split('\n')[0])
check("the brief tells it its own name (the human's name book)", /Your name is testnode/.test(brief?.text ?? ''), brief?.text?.split('\n')[1])
check('the brief names the house rules', (brief?.text ?? '').includes(join(HOUSE, 'HOUSE-RULES.md')))
check('the brief embeds a snapshot of the rules', (brief?.text ?? '').includes(RULES_MARKER))

const state = JSON.parse(readFileSync(join(STATE, 'chatelaine.json'), 'utf8'))
check('the state records the brief', state.briefVersion === 2 && typeof state.briefedAt === 'string', JSON.stringify(state))

// --- 4. a reload does not churn --------------------------------------------
const createdBefore = created.length
const deliveredBefore = deliveries.length
const again = await chatelaine.ensure()
check('a reload keeps the same session', again.sessionId === first.sessionId, `${again.sessionId} vs ${first.sessionId}`)
check('a reload creates nothing', created.length === createdBefore, `created=${created.length - createdBefore}`)
check('a reload does not re-brief', deliveries.length === deliveredBefore, `deliveries=${deliveries.length - deliveredBefore}`)
check('a reload re-attaches (visibility is not one-shot)', attached.filter((id) => id === String(first.sessionId)).length >= 2, `attached=${attached.length}`)

// --- 5. cut over to a new session -----------------------------------------
const moved = await chatelaine.newSession()
check('new creates a different session', moved.ok === true && moved.sessionId !== first.sessionId, JSON.stringify(moved))
check('new records the thread it replaced', moved.previousSessionId === first.sessionId, moved.previousSessionId)
const movedBreath = deliveries.find((delivery) => delivery.sessionId === moved.sessionId && delivery.text.startsWith('[chatelaine brief]'))
check('the new session is briefed too', movedBreath !== undefined)
const movedState = JSON.parse(readFileSync(join(STATE, 'chatelaine.json'), 'utf8'))
check('the new id is persisted', movedState.sessionId === moved.sessionId, movedState.sessionId)
check('the old id is kept for fallback', movedState.previousSessionId === first.sessionId, movedState.previousSessionId)

// --- 6. describe() is what /status reports -------------------------------
const described = await chatelaine.describe()
check('describe reports the current session', described.sessionId === moved.sessionId, described.sessionId)
check('describe reports the brief as current', described.briefCurrent === true && described.briefVersion === 2, JSON.stringify(described))
check('describe reports where it lives', described.cwd === chatelaineCwd && described.workspaceTitle === 'Chatelaine', JSON.stringify({ cwd: described.cwd, title: described.workspaceTitle }))

// --- 7. a chatelaine left in an old directory is relocated ----------------
// A v4 session's cwd is in its header and DSH's workspace registry validates
// header.cwd against the workspace path, so a session created in the operators'
// directory can NEVER be attached to the Chatelaine workspace. Boot must notice
// and cut over, or that node keeps an invisible chatelaine forever.
const legacyId = 'a2a-chatelaine-legacy-0000000000000000'
await agents.create({ sessionId: legacyId, meta: { cwd: HOUSE } })
await live.get(legacyId)?.dispose?.()
live.delete(legacyId)
writeFileSync(join(STATE, 'chatelaine.json'), JSON.stringify({
  version: 1,
  sessionId: legacyId,
  adoptedAt: new Date().toISOString(),
  briefVersion: 2,
  briefedAt: new Date().toISOString(),
}), 'utf8')

const relocated = createChatelaineRuntime(options)
const after = await relocated.ensure()
check('a session in the wrong directory is relocated', after.sessionId !== legacyId && after.relocatedFrom === legacyId, JSON.stringify(after))
check('the relocated session lives in the chatelaine directory', created.find((entry) => entry.id === after.sessionId)?.options?.meta?.cwd === chatelaineCwd, created.find((entry) => entry.id === after.sessionId)?.options?.meta?.cwd)
const relocatedState = JSON.parse(readFileSync(join(STATE, 'chatelaine.json'), 'utf8'))
check('the old thread is kept as previousSessionId', relocatedState.previousSessionId === legacyId, relocatedState.previousSessionId)
check('the relocated session is attached', attached.includes(String(after.sessionId)))

console.log(failures === 0 ? 'ALL P4 CHATELAINE PASS' : `P4 CHATELAINE FAILURES: ${failures}`)
process.exitCode = failures === 0 ? 0 : 1
