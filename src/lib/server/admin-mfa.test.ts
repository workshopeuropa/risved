import { afterAll, beforeAll, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { sql } from 'drizzle-orm'

vi.mock('$env/dynamic/private', () => ({env:{BETTER_AUTH_SECRET:'isolated-security-test-secret'}}))
vi.mock('./db', async () => {
  const {createClient} = await import('@libsql/client')
  const {drizzle} = await import('drizzle-orm/libsql')
  const {mkdtempSync} = await import('node:fs')
  const {tmpdir} = await import('node:os')
  return {db:drizzle(createClient({url:`file:${mkdtempSync(tmpdir()+'/risved-mfa-unit-')}/test.db`}))}
})

import { db } from './db'
import { adminMfaVerified, confirmAdminMfa, takeMfaAttempt, cleanMfaSecurityLogs, administratorTwoFactor } from './admin-mfa'

const now=1795777200000
const session={id:'session-new',userId:'admin',expiresAt:new Date(now+86400000)}

beforeAll(async()=> {
  await db.run(sql`PRAGMA foreign_keys=ON`)
  const journal=JSON.parse(readFileSync('drizzle/meta/_journal.json','utf8'))
  for (const entry of journal.entries) await db.$client.executeMultiple(readFileSync(`drizzle/${entry.tag}.sql`,'utf8'))
  await db.run(sql`INSERT INTO user (id,name,email,email_verified,created_at,updated_at) VALUES ('admin','Admin','admin@example.test',1,${now},${now})`)
  await db.run(sql`INSERT INTO session (id,expires_at,token,created_at,updated_at,user_id) VALUES ('session-new',${now+86400000},'fixture-token',${now},${now},'admin')`)
})

afterAll(()=>db.$client.close())

it('binds second-factor verification to one session, rejects replay and expires the proof',async()=> {
  expect(await adminMfaVerified('admin','session-new',now)).toBe(false)
  await confirmAdminMfa(session,'123456',false,now)
  expect(await adminMfaVerified('admin','session-new',now)).toBe(true)
  expect(await adminMfaVerified('admin','old-session',now)).toBe(false)
  expect(await adminMfaVerified('someone-else','session-new',now)).toBe(false)
  expect(await confirmAdminMfa(session,'123456',false,now+1)).toBe(false)
  expect(await adminMfaVerified('admin','session-new',now+12*3600000)).toBe(false)
  await confirmAdminMfa(session,'fixture-recovery-code',true,now+2)
  expect(await confirmAdminMfa(session,'fixture-recovery-code',true,now+3)).toBe(false)
  const logs=await db.all<{event:string}>(sql`SELECT event FROM admin_security_log`)
  expect(logs.map(row=>row.event)).toEqual(['mfa_totp_verified','mfa_recovery_verified'])
  expect(JSON.stringify(await db.all(sql`SELECT * FROM admin_mfa_codes`))).not.toContain('fixture-recovery-code')
})

it('persists a shared five-attempt budget and replenishes gradually',async()=> {
  for (let attempt=0;attempt<5;attempt++) expect(await takeMfaAttempt('rate-fixture',now)).toBe(true)
  expect(await takeMfaAttempt('rate-fixture',now)).toBe(false)
  expect(await takeMfaAttempt('rate-fixture',now+180000)).toBe(true)
  expect(await takeMfaAttempt('rate-fixture',now+180000)).toBe(false)
})

it('prunes proofs and diagnostics with log retention and session revocation',async()=> {
  await cleanMfaSecurityLogs(30,now+31*86400000)
  expect(await db.all(sql`SELECT * FROM admin_security_log`)).toHaveLength(0)
  expect(await db.all(sql`SELECT * FROM admin_mfa_sessions`)).toHaveLength(0)
  await confirmAdminMfa(session,'654321',false,now)
  await db.run(sql`DELETE FROM session WHERE id='session-new'`)
  expect(await adminMfaVerified('admin','session-new',now)).toBe(false)
})

it('adds native challenges to passkey sign-in while retaining credential sign-in',()=> {
  const plugin=administratorTwoFactor()
  const matcher=plugin.hooks.after[0].matcher
  for (const path of ['/sign-in/email','/passkey/verify-authentication']) expect(matcher({path} as Parameters<typeof matcher>[0])).toBe(true)
})
