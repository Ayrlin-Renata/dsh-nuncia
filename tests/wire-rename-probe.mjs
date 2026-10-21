// One-shot cross-node acceptance probe: vienzie (AVD) -> sylviana (desktop).
// Mints a real v2 envelope with the AVD node key and POSTs it over the wire.
// Run on the device from $HOME/.sylvia/dsh-nuncia after sourcing desk-token.env.
import { readFileSync, rmSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { parsePrivateKey } from './lib/keys.js'
import { createSigner } from './lib/authority.js'

// Node key on the device: install.sh seeds it at stateDir/nuncia-node.key
// ($HOME/.sylvia/nuncia-node.key); the profile copy (.sylvia/dsh-nuncia/) is a
// symlink created by the plugin install, not the live identity.
const priv = parsePrivateKey(readFileSync(process.env.HOME + '/.sylvia/nuncia-node.key', 'utf8'))
const signer = createSigner({ privateKey: priv })
const now = Date.now()
const env = signer.createEnvelope({ level: 'intent', origin: 'vienzie', target: 'sylviana', iat: now, exp: now + 5 * 60 * 1000, jti: randomUUID() })

const body = {
  jsonrpc: '2.0',
  id: 1,
  method: 'SendMessage',
  params: {
    message: {
      messageId: randomUUID(),
      role: 'user',
      parts: [{ kind: 'text', text: 'Cross-node acceptance test after the peer rename. Reply with exactly: RENAME WIRE OK' }],
    },
    metadata: { authority: env },
  },
}

const res = await fetch('http://127.0.0.1:14399/a2a', {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: 'Bearer ' + process.env.DESK_TOKEN, connection: 'close' },
  body: JSON.stringify(body),
})
const text = await res.text()
console.log('HTTP', res.status, 'len', text.length)
try {
  const j = JSON.parse(text)
  const task = j.result?.task ?? j.result
  console.log('state=' + (task?.status?.state ?? 'none'))
  const parts = (task?.artifacts ?? []).flatMap((a) => a.parts ?? [])
  console.log('reply=' + parts.map((p) => p?.content?.value ?? p?.text ?? '').join(' ').slice(0, 300))
  if (j.error) console.log('err=' + JSON.stringify(j.error).slice(0, 250))
} catch {
  console.log('raw head: ' + text.slice(0, 400))
}
rmSync(process.env.HOME + '/.sylvia/desk-token.env', { force: true })


