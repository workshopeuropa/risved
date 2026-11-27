import { createHmac } from 'node:crypto'
import { sql } from 'drizzle-orm'
import { env } from '$env/dynamic/private'
import { db } from './db'

const lifetime = 12*3600000

/** Check the second-factor proof for this particular browser session. */
export async function adminMfaVerified(userId:string,sessionId:string,now=Date.now()) {
  return Boolean((await db.all(sql`SELECT 1 FROM admin_mfa_sessions WHERE session_id=${sessionId} AND user_id=${userId} AND expires_at>${now}`)).length)
}

/** Store security events without credentials, codes, tokens or IP addresses. */
export async function adminSecurityEvent(event:string,userId:string|null) {
  await db.run(sql`INSERT INTO admin_security_log VALUES (${crypto.randomUUID()},${Date.now()},${event},${userId})`)
}

/** Persist a per-account verification budget shared by all processes. */
export async function takeMfaAttempt(userId:string,now=Date.now()) {
  return db.transaction(async tx=> {
    const delay = 3*60000
    const row = (await tx.all<{available_at:number}>(sql`SELECT available_at FROM admin_mfa_limits WHERE user_id=${userId}`))[0]
    if (row && row.available_at>now+4*delay) return false
    await tx.run(sql`INSERT INTO admin_mfa_limits VALUES (${userId},${Math.max(now,row?.available_at ?? now)+delay}) ON CONFLICT(user_id) DO UPDATE SET available_at=excluded.available_at`)
    return true
  })
}

/** Bind successful verification to its session and reject replayed TOTP codes. */
export async function confirmAdminMfa(session:{id:string,userId:string,expiresAt:Date},code:string,recovery:boolean,now=Date.now()) {
  return db.transaction(async tx=> {
    await tx.run(sql`DELETE FROM admin_mfa_codes WHERE expires_at<=${now} OR NOT EXISTS (SELECT 1 FROM "user" WHERE "user".id=admin_mfa_codes.user_id)`)
    {
      if (!env.BETTER_AUTH_SECRET) throw new Error('BETTER_AUTH_SECRET must be configured')
      const digest = createHmac('sha256',env.BETTER_AUTH_SECRET).update(`${session.userId}:${recovery ? 'recovery' : 'totp'}:${code}`).digest('hex')
      if ((await tx.all(sql`SELECT 1 FROM admin_mfa_codes WHERE user_id=${session.userId} AND code_hash=${digest}`)).length) return false
      await tx.run(sql`INSERT INTO admin_mfa_codes VALUES (${session.userId},${digest},${recovery ? Number.MAX_SAFE_INTEGER : now+90000})`)
    }
    await tx.run(sql`INSERT INTO admin_mfa_sessions VALUES (${session.id},${session.userId},${now},${Math.min(new Date(session.expiresAt).getTime(),now+lifetime)}) ON CONFLICT(session_id) DO UPDATE SET verified_at=excluded.verified_at,expires_at=excluded.expires_at`)
    await tx.run(sql`INSERT INTO admin_security_log VALUES (${crypto.randomUUID()},${now},${recovery ? 'mfa_recovery_verified' : 'mfa_totp_verified'},${session.userId})`)
    return true
  })
}

/** Prune MFA diagnostics using the configured Risved log-retention period. */
export async function cleanMfaSecurityLogs(days:number,now=Date.now()) {
  const cutoff=now-days*86400000
  await db.run(sql`DELETE FROM admin_security_log WHERE recorded_at<${cutoff}`)
  await db.run(sql`DELETE FROM admin_mfa_sessions WHERE expires_at<=${now}`)
  await db.run(sql`DELETE FROM admin_mfa_codes WHERE expires_at<=${now} OR NOT EXISTS (SELECT 1 FROM "user" WHERE "user".id=admin_mfa_codes.user_id)`)
  await db.run(sql`DELETE FROM admin_mfa_limits WHERE available_at<${cutoff}`)
}
