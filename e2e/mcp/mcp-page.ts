import { expect, type Page } from '@playwright/test'

export class McpPage {
	constructor(readonly page: Page) {}

	/** Sign in with the isolated fixture administrator. */
	async signIn(recoveryCode: string) {
		await this.page.goto('/login')
		await this.page.getByLabel('Email', { exact: true }).fill('mcp-e2e@example.test')
		await this.page.getByLabel('Password', { exact: true }).fill('mcp-e2e-password-123')
		await this.page.getByRole('button', { name: 'Sign in', exact: true }).click()
		await this.page.getByRole('heading',{name:'Verify your identity',exact:true}).waitFor()
		await this.page.screenshot({path:'/tmp/risved-mfa-challenge.png'})
		await this.page.setViewportSize({width:320,height:812})
		expect(await this.page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true)
		await this.page.screenshot({path:'/tmp/risved-mfa-mobile.png'})
		await this.page.setViewportSize({width:1280,height:900})
		await this.verifyMfa(recoveryCode)
		await expect(this.page).toHaveURL(/\/projects$/)
	}

	/** Complete the human-admin challenge with a disposable fixture recovery code. */
	async verifyMfa(recoveryCode: string) {
		await this.page.getByRole('button', { name: 'Use a recovery code', exact: true }).click()
		await this.page.getByLabel('Recovery code', { exact: true }).fill(recoveryCode)
		await this.page.getByRole('button', { name: 'Verify and continue', exact: true }).click()
	}

	/** Mint a bearer key through the settings form. */
	async createKey() {
		await this.page.goto('/settings')
		const section = this.page.getByTestId('mcp-keys-section')
		await section.getByLabel('Key label').fill('MCP E2E')
		await section.getByRole('button', { name: 'Create key', exact: true }).click()
		const value = this.page.getByTestId('mcp-key-value')
		await expect(value).toBeVisible()
		return (await value.innerText()).trim()
	}
}
