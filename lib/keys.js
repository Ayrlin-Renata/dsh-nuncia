/**
 * Per-node identity keys for dsh-nuncia — DESIGN.md §20.1.
 *
 * Each node holds one Ed25519 key pair. The private key never leaves the node;
 * the public key is what peers paste into *their* config. That asymmetry is the
 * whole point: a node that can verify an `intent` envelope holds no ability to
 * mint one, so authority cannot be derived from connectivity (the flaw of the
 * shared-HMAC v1 design, see lib/authority.js).
 *
 * Storage rules, in precedence order:
 *
 *  1. `authority.nodeKey` — inline base64url PKCS8 (fixed-environment hosts:
 *     containers, emulator images, config-management installs).
 *  2. `NUNCIA_NODE_KEY` — same value from the environment (keeps it out of a
 *     world-readable patch file).
 *  3. `authority.nodeKeyFile` (default `<stateDir>/nuncia-node.key`) — PEM or
 *     base64url PKCS8, mode 0600. Created on first boot when absent.
 *
 * A key file that exists but cannot be parsed is a **fatal** error: silently
 * generating a replacement would rotate the node's identity and invalidate
 * every peer's pinned key, turning a config mistake into a security event.
 *
 * @module dsh-nuncia/keys
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

import { exportPublicKey, fingerprintOf, keyIdOf } from './authority.js'

/** Environment fallback for `authority.nodeKey`. */
export const NODE_KEY_ENV = 'NUNCIA_NODE_KEY'

/** Default file name under the plugin state directory. */
export const DEFAULT_KEY_FILE = 'nuncia-node.key'

/**
 * Import an Ed25519 private key from PEM or single-line base64url PKCS8.
 * @param {unknown} value
 * @returns {import('node:crypto').KeyObject|undefined}
 */
export function parsePrivateKey(value) {
	if (value === null || value === undefined) return undefined
	if (typeof value === 'object' && typeof (/** @type {any} */ (value).asymmetricKeyType) === 'string') {
		const key = /** @type {import('node:crypto').KeyObject} */ (value)
		return key.type === 'private' && key.asymmetricKeyType === 'ed25519' ? key : undefined
	}
	if (typeof value !== 'string') return undefined
	const text = value.trim()
	if (text.length === 0) return undefined
	try {
		const key = text.includes('-----BEGIN')
			? createPrivateKey(text)
			: createPrivateKey({ key: Buffer.from(text, 'base64url'), format: 'der', type: 'pkcs8' })
		return key.asymmetricKeyType === 'ed25519' ? key : undefined
	} catch {
		return undefined
	}
}

/**
 * Serialize a private key as single-line base64url PKCS8 (the `nodeKey` form).
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {string}
 */
export function exportPrivateKey(privateKey) {
	return Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })).toString('base64url')
}

/**
 * File mode of a path, or `undefined` when it does not exist.
 * @param {string} path
 * @returns {number|undefined}
 */
function modeOf(path) {
	try {
		return statSync(path).mode & 0o777
	} catch {
		return undefined
	}
}

/**
 * Describe key material the way an operator needs to see it: a short id for
 * matching config entries, and a fingerprint for out-of-band comparison.
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {{privateKey:object, publicKey:object, kid:string, fingerprint:string, publicKeyText:string}}
 */
export function describeNodeKey(privateKey) {
	if (!privateKey || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
		throw new TypeError('describeNodeKey requires an Ed25519 private key')
	}
	const publicKey = createPublicKey(privateKey)
	return {
		privateKey,
		publicKey,
		kid: keyIdOf(publicKey),
		fingerprint: fingerprintOf(publicKey),
		publicKeyText: exportPublicKey(publicKey),
	}
}

/**
 * Load this node's key pair, generating and persisting one on first boot.
 *
 * @param {object} [options]
 * @param {string} [options.file]            key file path (default `<stateDir>/nuncia-node.key`)
 * @param {string} [options.inline]          base64url/PEM PKCS8 from config
 * @param {string} [options.env]             environment blob holding an inline key
 * @param {(message:string)=>void} [options.onWarn]
 * @returns {{privateKey:object, publicKey:object, kid:string, fingerprint:string, publicKeyText:string, source:'config'|'env'|'file'|'generated', file:string|undefined}}
 */
export function loadOrCreateNodeKey(options = {}) {
	const onWarn = options.onWarn ?? (() => {})
	const file = options.file === undefined ? undefined : resolve(options.file)

	const inline = options.inline ?? options.env ?? process.env[NODE_KEY_ENV]
	if (typeof inline === 'string' && inline.trim().length > 0) {
		const key = parsePrivateKey(inline)
		if (key === undefined) {
			throw new Error('authority.nodeKey is set but is not an Ed25519 private key (expected base64url PKCS8 or PEM)')
		}
		const described = describeNodeKey(key)
		return {
			...described,
			source: options.inline !== undefined ? 'config' : 'env',
			file,
		}
	}

	if (file === undefined) {
		// In-memory identity: usable, but peers cannot pin it across restarts.
		onWarn('no nodeKey/nodeKeyFile configured — generating an ephemeral identity that will not survive a restart')
		const { privateKey } = generateKeyPairSync('ed25519')
		return { ...describeNodeKey(privateKey), source: 'generated', file: undefined }
	}

	let text
	try {
		text = readFileSync(file, 'utf8')
	} catch (error) {
		if (/** @type {any} */ (error)?.code !== 'ENOENT') {
			throw new Error(`cannot read node key ${file}: ${error instanceof Error ? error.message : String(error)}`)
		}
	}

	if (text !== undefined) {
		const key = parsePrivateKey(text)
		if (key === undefined) {
			throw new Error(
				`node key ${file} exists but is not a readable Ed25519 private key. ` +
					'Refusing to overwrite it: replace or remove the file deliberately (every peer pins the old key).',
			)
		}
		const mode = modeOf(file)
		if (mode !== undefined && (mode & 0o077) !== 0) {
			try {
				chmodSync(file, 0o600)
				onWarn(`node key ${file} was mode ${mode.toString(8)}; tightened to 600`)
			} catch {
				onWarn(`node key ${file} is mode ${mode.toString(8)} and could not be tightened — move it to a private directory`)
			}
		}
		return { ...describeNodeKey(key), source: 'file', file }
	}

	const { privateKey } = generateKeyPairSync('ed25519')
	mkdirSync(dirname(file), { recursive: true })
	const temporary = `${file}.tmp`
	writeFileSync(temporary, exportPrivateKey(privateKey), { mode: 0o600 })
	renameSync(temporary, file)
	const described = describeNodeKey(privateKey)
	onWarn(`generated a new node identity at ${file} — publish its public key to peers before they connect`)
	return { ...described, source: 'generated', file }
}
