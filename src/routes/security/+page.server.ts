import { eq, and } from 'drizzle-orm'
import { db } from '$lib/server/db'
import { account } from '$lib/server/db/auth.schema'
import type { PageServerLoad } from './$types'

export const load:PageServerLoad = async ({locals,url,setHeaders}) => {
  setHeaders({'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer'})
  const password = locals.user ? await db.select({id:account.id}).from(account).where(and(eq(account.userId,locals.user.id),eq(account.providerId,'credential'))).limit(1) : []
  const next=url.searchParams.get('next') || '/'
  return {needsSetup:Boolean(locals.user && !locals.user.twoFactorEnabled),verified:Boolean(locals.adminMfaVerified),signedIn:Boolean(locals.user),passwordRequired:Boolean(password.length),next:next.startsWith('/') && !next.startsWith('//') && !next.includes('\\') && new URL(next,url.origin).origin === url.origin ? next : '/'}
}
