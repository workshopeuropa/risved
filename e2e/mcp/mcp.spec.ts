import { test, expect, type APIRequestContext } from '@playwright/test'
import { createClient } from '@libsql/client'
import { createServer } from 'node:http'
import { createHash, randomBytes } from 'node:crypto'
import { McpPage } from './mcp-page'
import { base32 } from '@better-auth/utils/base32'
import { createOTP } from '@better-auth/utils/otp'
import packageJson from '../../package.json' with { type: 'json' }

const headers = { Accept: 'application/json, text/event-stream' }
let callback = ''
let recoveryCodes: string[] = []
const callbackServer = createServer((_request, response) => response.end('Connection complete'))

/** Send an authenticated stateless MCP request. */
function rpc(request: APIRequestContext, key: string, method: string, params = {}) {
	return request.post('/mcp', {
		headers: { ...headers, Authorization: `Bearer ${key}` },
		data: { jsonrpc: '2.0', id: 1, method, params }
	})
}

test.beforeAll(async ({ request }) => {
	await new Promise<void>(resolve => callbackServer.listen(0, '127.0.0.1', resolve))
	const address = callbackServer.address() as { port: number }
	callback = `http://127.0.0.1:${address.port}/callback`
	const response = await request.post('/api/auth/sign-up/email', {
		data: { name: 'MCP E2E', email: 'mcp-e2e@example.test', password: 'mcp-e2e-password-123' }
	})
	expect(response.ok()).toBeTruthy()
	const db = createClient({ url: process.env.MCP_TEST_DATABASE! })
	await db.execute(
		"INSERT OR REPLACE INTO settings(key,value) VALUES ('onboarding_complete','true')"
	)
	db.close()
	const duplicate = await request.post('/api/auth/sign-up/email',{headers:{Origin:'http://localhost:5188'},data:{name:'Uninvited',email:'uninvited@example.test',password:'uninvited-password-123'}})
	expect(duplicate.status()).toBe(403)
	expect((await duplicate.json()).code).toBe('ADMIN_REGISTRATION_CLOSED')
	expect((await request.get('/api/auth/list-sessions')).status()).toBe(403)
	expect((await request.post('/api/auth/oauth2/consent',{headers:{Origin:'http://localhost:5188'},data:{accept:true,consent_code:'invalid'}})).status()).toBe(403)
	const enabled = await request.post('/api/auth/two-factor/enable', {
		headers: { Origin: 'http://localhost:5188' },
		data: { password: 'mcp-e2e-password-123' }
	})
	expect(enabled.ok(), await enabled.text()).toBeTruthy()
	const setup = await enabled.json()
	recoveryCodes = setup.backupCodes
	const encoded = new URL(setup.totpURI).searchParams.get('secret')!
	const secret = new TextDecoder().decode(base32.decode(encoded))
	const verified = await request.post('/api/auth/two-factor/verify-totp', {
		headers: { Origin: 'http://localhost:5188' },
		data: { code: await createOTP(secret).totp() }
	})
	expect(verified.ok(), await verified.text()).toBeTruthy()
})

test.afterAll(async () => {
	await new Promise<void>(resolve => callbackServer.close(() => resolve()))
})

test('creates a key, completes a handshake, hides the key after reload and revokes access', async ({
	page,
	request
}, testInfo) => {
	const ui = new McpPage(page)
	const errors: string[] = []
	page.on('pageerror', error => errors.push(error.message))
	await ui.signIn(recoveryCodes[0])
	await page.goto('/security?next='+encodeURIComponent('/\n/attacker.example'))
	await expect(page.getByRole('link',{name:'Continue to admin',exact:true})).toHaveAttribute('href','/')
	const key = await ui.createKey()
	const init = await rpc(request, key, 'initialize', {
		protocolVersion: '2025-06-18',
		capabilities: {},
		clientInfo: { name: 'release-test', version: '1' }
	})
	expect(init.status()).toBe(200)
	expect((await init.json()).result.serverInfo).toMatchObject({
		name: 'risved',
		version: packageJson.version
	})
	const tools = await rpc(request, key, 'tools/list')
	expect((await tools.json()).result.tools).toHaveLength(7)
	const projects = await rpc(request, key, 'tools/call', { name: 'list_projects', arguments: {} })
	expect((await projects.json()).result.structuredContent).toEqual({ projects: [] })
	await page.reload()
	await expect(page.getByTestId('mcp-key-value')).toHaveCount(0)
	const section = page.getByTestId('mcp-keys-section')
	await section.screenshot({ path: testInfo.outputPath('mcp-settings.png') })
	await section.getByRole('button', { name: 'Revoke', exact: true }).click()
	await expect(section.getByText('No access keys.', { exact: true })).toBeVisible()
	expect((await rpc(request, key, 'tools/list')).status()).toBe(401)
	expect(errors).toEqual([])
})

test('discovers OAuth, requires approval, exchanges an S256 code and rejects code reuse', async ({
	page,
	request
}, testInfo) => {
	const anonymous = await request.post('/mcp', {
		headers,
		data: { jsonrpc: '2.0', id: 1, method: 'tools/list' }
	})
	expect(anonymous.status()).toBe(401)
	expect(anonymous.headers()['www-authenticate']).toContain('oauth-protected-resource')
	const discovery = await request.get('/.well-known/oauth-authorization-server')
	expect(discovery.status()).toBe(200)
	const metadata = await discovery.json()
	const registration = await request.post(metadata.registration_endpoint, {
		data: {
			client_name: 'Release verification',
			redirect_uris: [callback],
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code'],
			response_types: ['code']
		}
	})
	expect(registration.ok()).toBeTruthy()
	const client = await registration.json()
	const verifier = randomBytes(32).toString('base64url')
	const params = new URLSearchParams({
		client_id: client.client_id,
		redirect_uri: callback,
		response_type: 'code',
		scope: 'openid',
		state: 'release-test-state',
		code_challenge: createHash('sha256').update(verifier).digest('base64url'),
		code_challenge_method: 'S256'
	})
	await page.goto(metadata.authorization_endpoint + '?' + params)
	await page.getByLabel('Email', { exact: true }).fill('mcp-e2e@example.test')
	await page.getByLabel('Password', { exact: true }).fill('mcp-e2e-password-123')
	await page.getByRole('button', { name: 'Sign in', exact: true }).click()
	await new McpPage(page).verifyMfa(recoveryCodes[1])
	await expect(page.getByRole('heading', { name: 'Connect Release verification?' })).toBeVisible()
	await page.screenshot({ path: testInfo.outputPath('mcp-consent.png') })
	await page.getByRole('button', { name: 'Allow access', exact: true }).click()
	await expect(page).toHaveURL(/\/callback\?code=/)
	const authorized = new URL(page.url())
	expect(authorized.searchParams.get('state')).toBe('release-test-state')
	const form = {
		grant_type: 'authorization_code',
		client_id: client.client_id,
		redirect_uri: callback,
		code: authorized.searchParams.get('code')!,
		code_verifier: verifier
	}
	expect(
		(
			await page.request.post('/settings?/createMcpKey', {
				headers: { Origin: 'https://attacker.test' },
				form: { label: 'forbidden' }
			})
		).status()
	).toBe(403)
	expect(
		(
			await page.request.post('/oauth/consent', {
				headers: { Origin: 'https://attacker.test' },
				form: { code: 'invalid', decision: 'allow' }
			})
		).status()
	).toBe(403)
	const token = await request.post(metadata.token_endpoint, { form })
	expect(token.ok(), await token.text()).toBeTruthy()
	const access = await token.json()
	expect((await rpc(request, access.access_token, 'tools/list')).status()).toBe(200)
	expect((await request.post(metadata.token_endpoint, { form })).ok()).toBeFalsy()
	params.set('state', 'denied-state')
	await page.goto(metadata.authorization_endpoint + '?' + params)
	await page.getByRole('button', { name: 'Deny', exact: true }).click()
	await expect(page).toHaveURL(/error=access_denied/)
	params.delete('code_challenge')
	params.delete('code_challenge_method')
	await page.goto(metadata.authorization_endpoint + '?' + params)
	await expect(page).toHaveURL(/error=invalid_request/)
})

test('requires MFA after a passkey sign-in before opening the dashboard',async({page,context})=> {
  const ui=new McpPage(page)
  await ui.signIn(recoveryCodes[2])
  const cdp=await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}})
  await page.goto('/settings')
  await page.getByTestId('passkey-name-input').fill('Isolated MFA passkey')
  await page.getByTestId('register-passkey-btn').click()
  await expect(page.getByText('Passkey registered',{exact:true})).toBeVisible()
  await page.request.post('/api/auth/sign-out',{headers:{Origin:'http://localhost:5188'}})
  await page.goto('/login')
  await page.getByRole('button',{name:'Sign in with passkey',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Verify your identity',exact:true})).toBeVisible()
  expect((await page.request.get('/api/auth/get-session')).status()).toBe(200)
  const primary=await page.request.get('/api/auth/get-session')
  expect(await primary.json()).toBeNull()
  await ui.verifyMfa(recoveryCodes[3])
  await expect(page).toHaveURL(/\/projects$/)
  await cdp.detach()
})
