/**
 * Outbound A2A client for dsh-nuncia — DESIGN.md §20.1 rule 3.
 *
 * Outbound traffic is where authority is *asserted*, so the plugin — not the
 * agent — does the asserting:
 *
 *  - A message is sent with `metadata.authority` **iff** a live grant exists
 *    for that peer (minted earlier through the admin endpoint or an approved
 *    `request_user_intent`). The agent never handles envelope bytes, which is
 *    what "structural non-acquisition" (§20.2) means in practice.
 *  - Responses are never trusted to carry authority. A response that does
 *    claim `intent`/`override` is treated as `peer` and reported as a security
 *    event — a hallucination or a confused relay cannot launder authority by
 *    answering.
 *  - Relays forget: this client re-sends the caller's own live grant (or
 *    none), never the envelope from an inbound message.
 *
 * Dependency-free apart from the platform `fetch`, so it is testable against a
 * throwaway HTTP server.
 *
 * @module dsh-nuncia/outbound
 */

import { randomUUID } from 'node:crypto'

/**
 * @typedef {object} OutboundResult
 * @property {string} peer
 * @property {string} taskId
 * @property {string} [contextId] the exchange id (echoed when the send carried one)
 * @property {string} state      e.g. TASK_STATE_COMPLETED
 * @property {string} text       concatenated assistant text from artifacts
 * @property {boolean} carriedAuthority whether this message asserted authority
 */

/**
 * Pull the plain-text answer out of an A2A Task-ish payload.
 * Handles both the SDK's `{content:{$case:'text',value}}` parts and plain
 * `{text}` parts so a version drift does not silently yield "".
 * @param {any} task
 * @returns {string}
 */
export function extractTaskText(task) {
	if (task === null || typeof task !== 'object') return ''
	const artifacts = Array.isArray(task.artifacts) ? task.artifacts : []
	const chunks = []
	for (const artifact of artifacts) {
		const parts = Array.isArray(artifact?.parts) ? artifact.parts : []
		for (const part of parts) {
			const value = part?.content?.$case === 'text' ? part.content.value : part?.text
			if (typeof value === 'string' && value.length > 0) chunks.push(value)
		}
	}
	return chunks.join('\n')
}

/**
 * Find an authority claim anywhere in a response. Only presence matters here:
 * the claim is never applied, it is reported.
 * @param {any} value
 * @returns {boolean}
 */
export function carriesAuthorityClaim(value) {
	if (value === null || typeof value !== 'object') return false
	if (Array.isArray(value)) return value.some(carriesAuthorityClaim)
	const authority = /** @type {Record<string, any>} */ (value).authority
	if (authority !== null && typeof authority === 'object' && typeof authority.level === 'string') {
		return true
	}
	return Object.values(value).some(carriesAuthorityClaim)
}

/**
 * Create the outbound client.
 *
 * @param {object} options
 * @param {Map<string,string>} options.peers        peer name -> base URL (no trailing path)
 * @param {string} options.token                    bearer token for peers (derived from the pairing secret)
 * @param {(peer:string)=>object|undefined} options.envelopeFor  live grant lookup
 * @param {(event:{kind:string, reason:string, detail?:object})=>void} [options.onSecurityEvent]
 * @param {typeof fetch} [options.fetchImpl]
 * @param {number} [options.timeoutMs]
 * @param {string} [options.path]                   JSON-RPC path on the peer (default /a2a)
 */
export function createOutboundClient(options) {
	const {
		peers,
		token,
		envelopeFor,
		onSecurityEvent = () => {},
		fetchImpl = fetch,
		timeoutMs = 60_000,
		path = '/a2a',
	} = options

	/**
	 * Send one message to a paired peer.
	 *
	 * @param {{peer:string, text:string, contextId?:string, taskId?:string}} request
	 * @returns {Promise<OutboundResult>}
	 */
	async function send(request) {
		const peer = request.peer
		const base = peers.get(peer)
		if (base === undefined) {
			throw new Error(`unknown peer "${peer}" — add it to authority.peerUrls as "name=url"`)
		}

		const envelope = envelopeFor(peer)
		const metadata = {
			...(envelope === undefined ? {} : { authority: envelope }),
		}
		const body = {
			jsonrpc: '2.0',
			id: randomUUID(),
			method: 'SendMessage',
			params: {
				message: {
					messageId: randomUUID(),
					role: 'user',
					parts: [{ kind: 'text', text: request.text }],
				},
				...(request.contextId === undefined ? {} : { contextId: request.contextId }),
				...(request.taskId === undefined ? {} : { taskId: request.taskId }),
				metadata,
			},
		}

		const response = await fetchImpl(`${base.replace(/\/+$/, '')}${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${token}`,
				// Peers restart often (every harness restart mints a new token),
				// and these calls are rare: a fresh connection is cheaper than a
				// pooled socket that outlived the peer. It also keeps shutdown
				// deterministic — no keep-alive socket left in a closing state.
				connection: 'close',
			},
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(timeoutMs),
		})

		if (!response.ok) {
			const detail = await response.text().catch(() => '')
			throw new Error(`peer "${peer}" answered ${response.status}${detail ? `: ${detail.slice(0, 300)}` : ''}`)
		}

		const payload = await response.json()
		if (payload?.error !== undefined) {
			throw new Error(`peer "${peer}" returned JSON-RPC error: ${JSON.stringify(payload.error).slice(0, 300)}`)
		}

		const task = payload?.result?.task ?? payload?.result
		if (carriesAuthorityClaim(payload?.result)) {
			// §20.1 rule 3: responses carry no authority. Accept the answer as
			// peer-level and report the claim; never act on it.
			onSecurityEvent({
				kind: 'authority-in-response',
				reason: 'response-carried-authority',
				detail: { peer, taskId: typeof task?.id === 'string' ? task.id : undefined },
			})
		}

		return {
			peer,
			taskId: typeof task?.id === 'string' ? task.id : '',
			// Carry the exchange id back to the caller: quoting a contextId in a
			// follow-up send is how a continued message lands on the SAME remote
			// operator instead of opening a fresh one.
			...(request.contextId === undefined
				? {}
				: { contextId: typeof task?.contextId === 'string' ? task.contextId : request.contextId }),
			state: typeof task?.status?.state === 'string' ? task.status.state : 'TASK_STATE_UNKNOWN',
			text: extractTaskText(task),
			carriedAuthority: envelope !== undefined,
		}
	}

	return { send }
}

/**
 * Parse `"name=url"` peer entries (config-friendly: an array of strings keeps
 * the schemastery config flat and reviewable).
 * @param {string[]} entries
 * @returns {Map<string,string>}
 */
export function parsePeerUrls(entries = []) {
	const peers = new Map()
	for (const entry of entries) {
		const at = entry.indexOf('=')
		if (at <= 0) continue
		const name = entry.slice(0, at).trim()
		const url = entry.slice(at + 1).trim()
		if (name.length === 0 || url.length === 0) continue
		peers.set(name, url)
	}
	return peers
}
