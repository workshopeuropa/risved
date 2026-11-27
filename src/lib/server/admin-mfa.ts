import { APIError, createAuthMiddleware, getSessionFromCtx } from 'better-auth/api'
import { twoFactor } from 'better-auth/plugins'
import { adminMfaVerified, adminSecurityEvent, takeMfaAttempt, confirmAdminMfa } from './admin-mfa-store'
export { adminMfaVerified, adminSecurityEvent, takeMfaAttempt, confirmAdminMfa, cleanMfaSecurityLogs } from './admin-mfa-store'
import { isFirstRun } from './auth-utils'

const challengePaths = ['/sign-in/email-otp','/passkey/verify-authentication']
const verificationPaths = ['/two-factor/verify-totp','/two-factor/verify-backup-code']
const sensitivePaths = ['/change-email','/change-password','/set-password','/update-user','/delete-user','/link-social','/unlink-account','/revoke-sessions','/list-sessions','/revoke-session','/revoke-other-sessions','/list-accounts','/get-access-token','/refresh-token','/email-otp/request-email-change','/email-otp/change-email','/two-factor/get-totp-uri','/two-factor/generate-backup-codes','/two-factor/view-backup-codes','/passkey/generate-register-options','/passkey/verify-registration','/passkey/delete-passkey','/passkey/update-passkey','/oauth2/authorize','/oauth2/consent']

/** Reuse the native second-factor challenge for passkey sign-ins too. */
export function administratorTwoFactor() {
  const plugin = twoFactor({issuer:'Risved',skipVerificationOnEnable:false,backupCodeOptions:{storeBackupCodes:'encrypted'}})
  // Apply the native challenge to passwordless sign-in too. The upstream
  // default matcher currently covers only credential-based sign-in paths.
  const nativeMatcher = plugin.hooks.after[0].matcher
  plugin.hooks.after[0].matcher = context => nativeMatcher(context) || challengePaths.includes(context.path || '')
  return plugin
}

/** Protect identity changes and record only successful second-factor proofs. */
export function administratorAuthHooks() {
  return {
    before:createAuthMiddleware(async ctx => {
      const path = ctx.path || ''
      if (path === '/mcp/authorize' && ctx.query) ctx.query.prompt = 'consent'
      if (path === '/sign-up/email' && !await isFirstRun()) throw new APIError('FORBIDDEN',{message:'Administrator registration is closed after initial setup.',code:'ADMIN_REGISTRATION_CLOSED'})
      if (!path.startsWith('/admin/') && !path.startsWith('/two-factor/') && !sensitivePaths.includes(path) && path !== '/mcp/authorize') return
      const session = await getSessionFromCtx(ctx)
      let user = session?.user
      if (!user && verificationPaths.includes(path)) {
        const cookie = ctx.context.createAuthCookie('two_factor')
        const challenge = await ctx.getSignedCookie(cookie.name,ctx.context.secret)
        const pending = challenge ? await ctx.context.internalAdapter.findVerificationValue(challenge) : null
        user = pending ? (await ctx.context.internalAdapter.findUserById(pending.value)) ?? undefined : undefined
      }
      if (!user) return
      if (verificationPaths.includes(path)) {
        if (!await takeMfaAttempt(user.id)) throw new APIError('TOO_MANY_REQUESTS',{message:'Too many verification attempts. Wait a few minutes before trying again.',code:'MFA_RATE_LIMITED'})
        return
      }
      if (path === '/two-factor/disable') throw new APIError('FORBIDDEN',{message:'Administrators must keep multi-factor authentication enabled.',code:'ADMIN_MFA_REQUIRED'})
      if (path === '/two-factor/enable' && !user.twoFactorEnabled) {
        if (!session || Date.now()-new Date(session.session.createdAt).getTime()>15*60000) throw new APIError('FORBIDDEN',{message:'Sign in again before setting up your authenticator.',code:'FRESH_LOGIN_REQUIRED'})
        return
      }
      if (!session || !user.twoFactorEnabled || !await adminMfaVerified(user.id,session.session.id)) throw new APIError('FORBIDDEN',{message:'Verify your authenticator before continuing.',code:'ADMIN_MFA_REQUIRED'})
    }),
    after:createAuthMiddleware(async ctx => {
      if (!verificationPaths.includes(ctx.path || '')) return
      const result = ctx.context.returned as {token?:unknown}|null
      if (typeof result?.token !== 'string') {
        await adminSecurityEvent('mfa_verification_rejected',null)
        return
      }
      const session = ctx.context.newSession || await ctx.context.internalAdapter.findSession(result.token)
      if (!session || !session.user.twoFactorEnabled) return
      const recovery=ctx.path === '/two-factor/verify-backup-code'
      if (!await confirmAdminMfa(session.session,String(ctx.body?.code || ''),recovery)) throw new APIError('UNAUTHORIZED',{message:recovery ? 'That recovery code has already been used.' : 'Wait for a new authenticator code and try again.',code:'MFA_CODE_ALREADY_USED'})
    })
  }
}
