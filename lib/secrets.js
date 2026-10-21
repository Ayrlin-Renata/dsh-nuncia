/**
 * Encrypted secret store (DESIGN §20.12.3).
 *
 * A node's secrets — the pairing secret, the admin token — used to sit in
 * plain text: in a profile patch, in a shell env file, in a config file an
 * agent reads all day. This module moves them into one encrypted file and
 * leaves only the *key* in the environment.
 *
 * **What this buys, honestly.** It is not protection against a local agent:
 * DSH runs `danger-full-access`, so an agent in the same uid can read the key
 * file, run the decryptor, and have the plaintext. That residual is accepted
 * in §20.6. What it *does* buy:
 *
 *  - **Accidental disclosure stops.** Grepping the repo, reading a config
 *    file, or copying a patch to a chat channel no longer leaks a usable
 *    secret. Only the ciphertext leaves the process.
 *  - **A tripwire.** Obtaining the key is now a *deliberate, separate act*,
 *    and every decryption is recorded in `secrets-access.log`. The env file
 *    says so in a comment. An agent instructed to "find the key" is visible
 *    in that log — which is the point of the whole scheme.
 *  - **Rotation without rewriting configs.** One file changes; the profile
 *    patch keeps naming the same env vars.
 *
 * The cipher is AES-256-GCM with a scrypt-derived key: authenticated (a
 * tampered file is refused, not silently mis-decrypted) and standard, so the
 * format is inspectable rather than bespoke.
 *
 * @module dsh-nuncia/secrets
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { expandHome } from './house.js'

/** Envelope format version. */
export const SECRETS_VERSION = 1

/** scrypt cost parameters. N=2^15 costs ~100 ms on a phone — once per boot. */
export const SCRYPT_PARAMS = Object.freeze({ N: 32768, r: 8, p: 1, keyLength: 32 })

/** AES-GCM nonce length. */
export const IV_BYTES = 12

/** Salt length for the scrypt derivation. */
export const SALT_BYTES = 16

/** Default secret file location. */
export const DEFAULT_SECRETS_FILE = '~/.sylvia/secrets.enc'

/** Default environment variable holding the passphrase. */
export const DEFAULT_SECRETS_KEY_ENV = 'SYLVIA_SECRET_KEY'

/** Default audit log path (relative to the state dir). */
export const DEFAULT_AUDIT_FILE = 'secrets-access.log'

/**
 * Derive the encryption key from a passphrase.
 * @param {string} passphrase
 * @param {Buffer} salt
 * @returns {Buffer}
 */
export function deriveKey(passphrase, salt) {
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw new Error('dsh-nuncia: a secret passphrase is required')
  }
  // scrypt's default maxmem (32 MB) is exactly the cost this asks for, so
  // give it headroom rather than letting it throw at the boundary.
  return scryptSync(passphrase, salt, SCRYPT_PARAMS.keyLength, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: 64 * 1024 * 1024,
  })
}

/**
 * Encrypt a map of secrets into a storable envelope.
 * @param {Record<string, string>} values
 * @param {string} passphrase
 * @returns {{version:number, kdf:object, cipher:string, iv:string, tag:string, data:string}}
 */
export function encryptSecrets(values, passphrase) {
  const salt = randomBytes(SALT_BYTES)
  const iv = randomBytes(IV_BYTES)
  const key = deriveKey(passphrase, salt)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const plaintext = Buffer.from(JSON.stringify(values ?? {}), 'utf8')
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  return {
    version: SECRETS_VERSION,
    kdf: {
      name: 'scrypt',
      N: SCRYPT_PARAMS.N,
      r: SCRYPT_PARAMS.r,
      p: SCRYPT_PARAMS.p,
      salt: salt.toString('base64url'),
    },
    cipher: 'aes-256-gcm',
    iv: iv.toString('base64url'),
    tag: tag.toString('base64url'),
    data: data.toString('base64url'),
  }
}

/**
 * Decrypt an envelope back into a map of secrets.
 * @param {any} envelope
 * @param {string} passphrase
 * @returns {Record<string, string>}
 */
export function decryptSecrets(envelope, passphrase) {
  if (envelope === null || typeof envelope !== 'object') {
    throw new Error('dsh-nuncia: the secrets file is not a valid envelope')
  }
  if (envelope.version !== SECRETS_VERSION) {
    throw new Error(`dsh-nuncia: unsupported secrets format version ${String(envelope.version)}`)
  }
  if (envelope.cipher !== 'aes-256-gcm') {
    throw new Error(`dsh-nuncia: unsupported secrets cipher ${String(envelope.cipher)}`)
  }
  const kdf = envelope.kdf
  if (kdf?.name !== 'scrypt') {
    throw new Error(`dsh-nuncia: unsupported key derivation ${String(kdf?.name)}`)
  }
  let key
  try {
    key = deriveKey(passphrase, Buffer.from(String(kdf.salt), 'base64url'))
  } catch (error) {
    throw new Error(`dsh-nuncia: cannot derive the secrets key — ${error instanceof Error ? error.message : String(error)}`)
  }
  let plaintext
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(String(envelope.iv), 'base64url'))
    decipher.setAuthTag(Buffer.from(String(envelope.tag), 'base64url'))
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(String(envelope.data), 'base64url')),
      decipher.final(),
    ])
  } catch {
    // A wrong key and a tampered file are indistinguishable here, and both
    // mean the same thing to the operator: this passphrase does not open
    // this file.
    throw new Error('dsh-nuncia: the secret key does not open this secrets file (wrong key, or the file was changed)')
  }
  let parsed
  try {
    parsed = JSON.parse(plaintext.toString('utf8'))
  } catch {
    throw new Error('dsh-nuncia: the secrets file did not decrypt to a JSON map')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('dsh-nuncia: the secrets file did not decrypt to a JSON map')
  }
  return parsed
}

/**
 * Write the encrypted secret map to disk (atomic, 0600).
 * @param {string} file
 * @param {Record<string, string>} values
 * @param {string} passphrase
 * @returns {{file: string, envelope: any}}
 */
export function writeSecretsFile(file, values, passphrase) {
  const path = expandHome(file)
  const envelope = encryptSecrets(values, passphrase)
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.${process.pid}.tmp`
  writeFileSync(temporary, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 })
  renameSync(temporary, path)
  return { file: path, envelope }
}

/**
 * Read and decrypt the secret map from disk.
 * @param {string} file
 * @param {string} passphrase
 * @returns {Record<string, string>}
 */
export function readSecretsFile(file, passphrase) {
  const path = expandHome(file)
  let raw
  try {
    raw = readFileSync(path, 'utf8')
  } catch (error) {
    throw new Error(`dsh-nuncia: cannot read the secrets file ${path} — ${error instanceof Error ? error.message : String(error)}`)
  }
  let envelope
  try {
    envelope = JSON.parse(raw)
  } catch {
    throw new Error(`dsh-nuncia: the secrets file ${path} is not valid JSON`)
  }
  return decryptSecrets(envelope, passphrase)
}

/**
 * Record that the secrets were decrypted. This is the tripwire: a line here
 * means something opened the vault, with a timestamp and a pid. An agent told
 * to "go find the key" leaves a trail.
 * @param {string} logFile
 * @param {{source: string, values?: string[], reason?: string}} detail
 */
export function recordSecretAccess(logFile, detail) {
  try {
    const path = expandHome(logFile)
    mkdirSync(dirname(path), { recursive: true })
    const names = Array.isArray(detail?.values) ? detail.values.join(',') : ''
    appendFileSync(
      path,
      `${new Date().toISOString()} pid=${process.pid} source=${detail?.source ?? 'unknown'} secrets=[${names}]${detail?.reason === undefined ? '' : ` reason=${detail.reason}`}\n`,
      { mode: 0o600 },
    )
  } catch {
    // The audit trail must never break the thing it is auditing.
  }
}

/**
 * Read the most recent audit lines (newest first).
 * @param {string} logFile
 * @param {number} [limit]
 * @returns {string[]}
 */
export function readSecretAccess(logFile, limit = 20) {
  try {
    const raw = readFileSync(expandHome(logFile), 'utf8')
    return raw.split('\n').filter((line) => line.trim() !== '').slice(-limit).reverse()
  } catch {
    return []
  }
}

/**
 * Resolve the passphrase for the secrets file: the environment first, then an
 * explicit file. The environment is preferred because it is the deliberate
 * act (the launcher's `set -a; . sylvia.env`).
 * @param {{envName?: string, keyFile?: string, env?: Record<string, string|undefined>}} options
 * @returns {{passphrase: string|undefined, source: string}}
 */
export function resolvePassphrase(options = {}) {
  const env = options.env ?? process.env
  const envName = options.envName ?? DEFAULT_SECRETS_KEY_ENV
  const fromEnv = env[envName]
  if (typeof fromEnv === 'string' && fromEnv !== '') return { passphrase: fromEnv, source: `env:${envName}` }
  if (options.keyFile !== undefined) {
    try {
      const raw = readFileSync(expandHome(options.keyFile), 'utf8').trim()
      if (raw !== '') return { passphrase: raw, source: `file:${expandHome(options.keyFile)}` }
    } catch {
      // fall through: no key anywhere
    }
  }
  return { passphrase: undefined, source: 'none' }
}

/**
 * The default secret file path for a state directory.
 * @param {string} stateDir
 * @returns {string}
 */
export function secretsFileFor(stateDir) {
  return join(expandHome(stateDir), 'secrets.enc')
}
