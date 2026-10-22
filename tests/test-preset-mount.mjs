/**
 * Preset mounting, on BOTH paths.
 *
 * DSH does not mount an Agent preset by itself: `meta.agentPreset` only records
 * a label in the session header, and the caller supplies a `setup(agentCtx)`
 * callback that the agent loop runs before the session publishes. The canonical
 * DSH caller (`dsh-api-session-controller` → `composeAgent` / `resumeObserved`)
 * passes the same callback to `agents.create` AND `agents.resume`.
 *
 * This runtime disposes the create-time handle on purpose and keeps only the
 * session id, so every later delivery goes through `agents.resume`. When the
 * resume call omitted `setup`, the session came back with NO preset — no
 * tool-fs/bash/pwsh/web/delegation, only the profile-realm plugins. That was
 * the live "179 tools instead of 209" scope defect: the chatelaine believed it
 * had `standard` (the projection said so) and had none of its tools.
 *
 * The checks below are deliberately split across four contexts (mounted,
 * unset, unavailable, unknown) because each one was a plausible way for this to
 * regress silently again.
 */
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createChatelaineRuntime } from '../lib/chatelaine.js'

let pass = 0
let fail = 0
const failures = []
function check(name, condition, detail) {
  if (condition) { pass += 1; return }
  fail += 1
  failures.push(name)
  console.error(`FAIL ${name}${detail === undefined ? '' : ` — ${detail}`}`)
}

const textOf = (message) => (message?.content ?? [])
  .map((block) => (block?.type === 'text' ? block.text : ''))
  .filter(Boolean)
  .join('\n')

/**
 * Build one isolated runtime over a fake agents service.
 * @param {{preset?: string, presets?: 'mounted'|'unavailable', resolveThrows?: boolean}} spec
 */
function harness(spec) {
  const house = mkdtempSync(join(tmpdir(), 'nuncia-preset-'))
  writeFileSync(join(house, 'HOUSE-RULES.md'), '# House rules\n', 'utf8')
  const created = []
  const resumed = []
  const mounts = []
  const warnings = []
  const existing = new Set()
  const live = new Map()
  const deliveries = []

  const agentFor = (id, cwd) => ({
    id,
    session: { id, header: { id, cwd } },
    inject: (message) => { deliveries.push({ sessionId: id, text: textOf(message) }) },
    followup: (message) => { deliveries.push({ sessionId: id, text: textOf(message) }) },
    steer: () => {},
    cancel: () => {},
    whenIdle: async () => {},
  })

  const agents = {
    create: async (options) => {
      const id = String(options.sessionId)
      created.push({ id, setup: options.setup, meta: options.meta })
      existing.add(id)
      // The loop runs the callback BEFORE publishing; do the same, so a setup
      // that throws fails creation here exactly as it would in DSH.
      await options.setup?.(agentFor(id, options.meta?.cwd))
      live.set(id, agentFor(id, options.meta?.cwd))
      return { agent: live.get(id), dispose: async () => { live.delete(id) } }
    },
    get: (id) => live.get(String(id)),
    resume: async (options) => {
      const id = String(options.resumeSessionId)
      if (!existing.has(id)) throw new Error(`no such session ${id}`)
      resumed.push({ id, setup: options.setup })
      const agent = live.get(id) ?? agentFor(id, undefined)
      // Same contract as create: the callback runs before the agent publishes.
      await options.setup?.(agent)
      live.set(id, agent)
      return { agent, dispose: async () => { live.delete(id) } }
    },
  }

  const presets = spec.presets === 'unavailable'
    ? undefined
    : {
        resolve: async (id) => {
          if (spec.resolveThrows === true) {
            const error = new Error(`Unknown agent preset: ${id}`)
            error.code = 'agent-preset/not-found'
            throw error
          }
          // DSH resolve() may normalise (e.g. undefined → the default id), so a
          // value that differs from the request proves we use the ANSWER.
          return { id: id === 'alias' ? 'standard' : id }
        },
        mount: async (agentCtx, id) => { mounts.push({ id, agentCtx }) },
      }

  const ctx = {
    agents,
    logger: { info: () => {}, debug: () => {}, warn: (m) => warnings.push(String(m)) },
    get: (name) => (name === 'agentPresets' ? presets : undefined),
  }

  const config = {}
  if (spec.preset !== undefined) config.chatelaine = { preset: spec.preset }
  const runtime = createChatelaineRuntime({
    ctx,
    config,
    workspace: house,
    stateDir: join(house, '.nuncia'),
    nodeName: 'testnode',
    logger: ctx.logger,
    // presetId is the RUNTIME option (index.js resolves it from
    // chatelaine.preset ?? agentPreset); the runtime itself does not read the
    // config for it.
    ...(spec.preset === undefined ? {} : { presetId: spec.preset }),
  })
  return { runtime, created, resumed, mounts, warnings, deliveries, live, existing }
}

// --- 1. the create path mounts the resolved preset --------------------------
{
  const h = harness({ preset: 'alias' })
  const first = await h.runtime.ensure()
  check('boot created the chatelaine session', first?.ok === true && first.created === true, JSON.stringify(first))
  check('create passed a setup callback', typeof h.created[0]?.setup === 'function')
  check('create mounted the RESOLVED preset id (not the alias)',
    h.mounts.length > 0 && h.mounts.every((m) => m.id === 'standard'),
    JSON.stringify(h.mounts.map((m) => m.id)))
  check('the mount received the agent context, not the host one',
    h.mounts[0]?.agentCtx !== undefined && h.mounts[0].agentCtx !== h.created[0],
    'agentCtx missing')
}

// --- 2. the RESUME path mounts it too (the defect this file exists for) -----
{
  const h = harness({ preset: 'standard' })
  await h.runtime.ensure()
  // A process restart is the honest simulation: this runtime keeps only the
  // session id, so after any reload there is no live handle and the next
  // delivery MUST go through agents.resume.
  h.live.clear()
  const mountsBefore = h.mounts.length
  const resumesBefore = h.resumed.length
  const delivered = await h.runtime.report('operator says hello')
  check('the report was delivered', delivered.delivered === true, JSON.stringify(delivered))
  check('delivery went through resume (no live handle)',
    h.resumed.length === resumesBefore + 1, JSON.stringify(h.resumed.map((r) => r.id)))
  check('resume passed a setup callback — the 179-vs-209 defect',
    typeof h.resumed.at(-1)?.setup === 'function',
    'resume() was called without setup, so the resumed session loses its preset')
  check('resume mounted the preset again', h.mounts.length === mountsBefore + 1,
    `mounts ${mountsBefore} -> ${h.mounts.length}`)
  check('every mount used the canonical id',
    h.mounts.every((m) => m.id === 'standard'), JSON.stringify(h.mounts.map((m) => m.id)))
}

// --- 3. no configured preset means no setup and no bogus mount --------------
{
  const h = harness({})
  await h.runtime.ensure()
  check('without a preset, create passes no setup', h.created[0]?.setup === undefined)
  await h.runtime.report('hello')
  check('without a preset, resume passes no setup', h.resumed[0]?.setup === undefined)
  check('without a preset nothing is mounted', h.mounts.length === 0)
}

// --- 4. an unavailable preset service warns ONCE instead of running silent --
{
  const h = harness({ preset: 'standard', presets: 'unavailable' })
  await h.runtime.ensure()
  const delivered = await h.runtime.report('hello')
  await h.runtime.report('again')
  check('an unavailable preset service does not break delivery', delivered.delivered === true, JSON.stringify(delivered))
  const presetWarnings = h.warnings.filter((w) => /agentPresets is unavailable/.test(w))
  check('the missing preset service is reported once, not per delivery',
    presetWarnings.length === 1, JSON.stringify(h.warnings))
  check('the warning says what the session loses',
    presetWarnings[0] !== undefined && /only profile-level tools/.test(presetWarnings[0]),
    presetWarnings[0])
}

// --- 5. an unknown preset id surfaces a real resolution error ---------------
{
  const h = harness({ preset: 'nope', resolveThrows: true })
  const first = await h.runtime.ensure()
  // Creation fails at setup (mount is part of create), and the runtime reports
  // that instead of adopting a session it cannot configure.
  check('an unknown preset fails creation rather than adopting a crippled session',
    first === undefined || first.ok === false, JSON.stringify(first))
  check('the failure names the preset', h.warnings.some((w) => /Unknown agent preset: nope/.test(w)), JSON.stringify(h.warnings))
  check('nothing was mounted for an unknown preset', h.mounts.length === 0)
}

if (fail === 0) {
  console.log(`ALL PRESET MOUNT PASS (${pass} checks)`)
  process.exit(0)
}
console.error(`PRESET MOUNT FAILURES: ${fail} of ${pass + fail}`)
process.exit(1)
