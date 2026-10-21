#!/usr/bin/env node
/**
 * Inspect or replace the chatelaine session over the plugin's admin API.
 *
 * The chatelaine is a real DSH session: the human finds it in the UI under the
 * `Chatelaine` workspace and talks to it there. This CLI is for the two things
 * the UI cannot do — tell you where the thread actually is, and cut over to a
 * fresh one so a handoff (a context export) can be pasted in by hand.
 *
 * The admin API is loopback-only and bearer-guarded, so this runs on the same
 * machine as the harness.
 *
 *   nuncia-chatelaine.js show
 *   nuncia-chatelaine.js new
 *
 * Resolution mirrors the other bins: --url / $NUNCIA_ADMIN_URL, then
 * --token / $NUNCIA_ADMIN_TOKEN, then the vault (when a passphrase is present).
 */
import { DEFAULT_SECRETS_FILE, readSecretsFile, resolvePassphrase } from '../lib/secrets.js'
import { expandHome } from '../lib/house.js'

const DEFAULT_URL = 'http://127.0.0.1:4123/a2a/admin'

/** @param {string[]} argv */
function parse(argv) {
  const flags = {}
  const rest = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) flags[a.slice(2)] = argv[++i]
    else rest.push(a)
  }
  return { command: rest[0] ?? 'show', flags }
}

/** @param {Record<string, string>} flags */
async function resolveAdminToken(flags) {
  const direct = flags.token ?? process.env.NUNCIA_ADMIN_TOKEN
  if (direct !== undefined && direct !== '') return direct
  try {
    const file = expandHome(flags.file ?? process.env.NUNCIA_SECRETS_FILE ?? DEFAULT_SECRETS_FILE)
    const passphrase = resolvePassphrase({
      ...(flags['key-env'] === undefined ? {} : { keyEnv: flags['key-env'] }),
      ...(flags['key-file'] === undefined ? {} : { keyFile: flags['key-file'] }),
    })
    if (passphrase === undefined) return undefined
    const values = readSecretsFile(file, passphrase)
    return values.NUNCIA_ADMIN_TOKEN
  } catch {
    return undefined
  }
}

async function main() {
  const { command, flags } = parse(process.argv.slice(2))
  const base = (flags.url ?? process.env.NUNCIA_ADMIN_URL ?? DEFAULT_URL).replace(/\/$/, '')
  const token = await resolveAdminToken(flags)
  if (token === undefined) {
    console.error('nuncia-chatelaine: no admin token (set NUNCIA_ADMIN_TOKEN, pass --token, or unlock the vault)')
    process.exitCode = 2
    return
  }
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' }

  if (command === 'show') {
    const res = await fetch(`${base}/chatelaine`, { headers })
    const body = await res.json().catch(() => ({}))
    if (!res.ok) {
      console.error(`nuncia-chatelaine: ${res.status} ${JSON.stringify(body)}`)
      process.exitCode = 1
      return
    }
    const c = body.chatelaine ?? {}
    console.log(`session:     ${c.sessionId ?? '(none)'}`)
    console.log(`previous:    ${c.previousSessionId ?? '(none)'}`)
    console.log(`directory:   ${c.cwd ?? '?'}`)
    console.log(`workspace:   ${c.workspaceTitle ?? '?'}`)
    console.log(`brief:       ${c.briefCurrent ? `v${c.briefVersion} (current)` : `v${c.briefVersion ?? 'none'} (stale)`}`)
    console.log(`briefed at:  ${c.briefedAt ?? 'never'}`)
    console.log(`rules:       ${c.rulesPath ?? '?'}`)
    console.log('')
    console.log('Find it in DSH under the workspace above; open that session to talk to it.')
    return
  }

  if (command === 'new') {
    const res = await fetch(`${base}/chatelaine/new`, { method: 'POST', headers })
    const body = await res.json().catch(() => ({}))
    if (!res.ok) {
      console.error(`nuncia-chatelaine: ${res.status} ${JSON.stringify(body)}`)
      process.exitCode = 1
      return
    }
    console.log(`new chatelaine session: ${body.sessionId}`)
    if (body.previousSessionId) console.log(`previous thread kept:   ${body.previousSessionId}`)
    console.log('')
    console.log('It has been briefed. Open it in DSH and paste the handoff into that thread.')
    return
  }

  console.error(`nuncia-chatelaine: unknown command "${command}" (expected: show, new)`)
  process.exitCode = 2
}

await main()
