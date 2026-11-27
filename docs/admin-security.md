# Administrator MFA

All human administrators must verify an authenticator code after primary sign-in. Password and passkey sign-in both continue to `/security`. Existing browser sessions cannot open the dashboard or mutate protected settings until they have verified a second factor. Registration through the authentication API closes after the first administrator has been created.

## Enrollment

Sign in again if the primary session is more than 15 minutes old, then open `/security`. Confirm the current account password, scan the locally generated QR code in an authenticator app, save the ten recovery codes privately, and verify a current six-digit code. The setup key and codes are displayed only during enrollment and should not be pasted into support messages or screenshots.

Verification is tied to the specific session and lasts at most 12 hours, bounded by the session expiry. A newly signed-in browser needs a new proof. An old session is not trusted just because the account subsequently enrolled. Administrators cannot disable MFA through the normal authentication API. Verification has a persistent per-account attempt budget and replay protection. Recovery codes are single-use.

## Recovery and incident response

Use a saved recovery code after primary sign-in if the authenticator is unavailable. Treat recovery codes like passwords. Once signed in with a recovery code, native authenticator-management endpoints still require the verified session and the account password where required by Better Auth.

If both the authenticator and all recovery codes are lost, recovery requires the operator's verified access to the host and database. There is deliberately no unauthenticated email reset endpoint. Before manual recovery, verify the administrator's identity independently, record the reason, create and validate a consistent database recovery copy, revoke the administrator's browser sessions and MFA session proofs, and assess machine keys separately. Never clear the MFA requirement while leaving old sessions active. Complete fresh enrollment before restoring access. Record the action without secrets.

## Machine access and host access

MCP bearer keys, OAuth and the deployment API remain separate machine authentication mechanisms. Human MFA does not automatically add MFA to SSH or the cloud provider's console. Restrict those separately. OAuth consent requires verified human access; PKCE token exchange retains its narrowly scoped form-origin exception. The form-origin guard remains first in the server-hook sequence.

## Deployment and evidence

Apply the `0011_admin_mfa` database migration before starting the new server. The production container's startup command runs migrations before the application. The migration adds native TOTP storage, per-session proof, replay/rate-limit tables and an audit table without replacing project or account data. Make a consistent database recovery copy before upgrading production.

MFA audit events record time, event name and optionally user ID, excluding codes, passwords, tokens and IP addresses. Cleanup follows the configured `log_retention_days`, defaulting to 30 days. This does not change Docker/proxy/host log retention or establish tamper-proof centralized logging.

Run the MFA/store unit tests, login and form-origin tests, type checking, and `bun run test:mcp` before releasing changes to these controls. The production-built MCP browser suite covers second-factor challenges, recovery login, MCP key lifecycle, OAuth consent, S256 token exchange, code reuse rejection, and cross-origin settings/consent rejection. These technical checks do not constitute an organizational incident-response exercise or prove that host backups are enabled.
