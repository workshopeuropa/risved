<script lang="ts">
  import { resolve } from '$app/paths'
  import { authClient } from '$lib/auth-client'
    let { data } = $props()
  let password = $state('')
  let code = $state('')
  let recovery = $state(false)
  let busy = $state(false)
  let message = $state('')
  let uri = $state('')
  let qr = $state('')
  let backupCodes = $state<string[]>([])
  let savedCodes = $state(false)
  let secret = $derived(uri ? new URL(uri).searchParams.get('secret') || '' : '')

  async function enable(event:SubmitEvent) {
    event.preventDefault()
    busy = true
    message = ''
    try {
      const result = await authClient.twoFactor.enable({password})
      password = ''
      if (result.error) { message = result.error.message || 'Could not set up your authenticator. Sign in again and retry.'
        return }
      if (result.data?.totpURI) {
        uri = result.data.totpURI
        backupCodes = result.data.backupCodes || []
        savedCodes = false
        const {toDataURL} = await import('qrcode')
        qr = await toDataURL(uri,{errorCorrectionLevel:'M',margin:2,width:256})
      }
    } catch { message = 'Could not set up your authenticator. Please try again.' }
    finally { busy = false }
  }

  async function verify(event:SubmitEvent) {
    event.preventDefault()
    busy = true
    message = ''
    try {
      const client = authClient
      const result = recovery
        ? await client.twoFactor.verifyBackupCode({code:code.trim(),trustDevice:false})
        : await client.twoFactor.verifyTotp({code:code.trim(),trustDevice:false})
      code = ''
      if (result.error) message = result.error.message || 'That code could not be verified. Try a new code.'
      else {
        uri = ''
        qr = ''
        backupCodes = []
        window.location.assign(data.next)
      }
    } catch { message = 'Verification could not be completed. Please try again.' }
    finally { busy = false }
  }

  function downloadCodes() {
    const blob = new Blob([`$Risved recovery codes\nStore these privately. Each code works once.\n\n${backupCodes.join('\n')}\n`],{type:'text/plain'})
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'risved-recovery-codes.txt'
    link.click()
    URL.revokeObjectURL(url)
  }
</script>

<svelte:head><title>Administrator security · Risved</title><meta name="robots" content="noindex, nofollow" /></svelte:head>
<section>
  <h1>{data.verified ? 'Administrator security' : data.needsSetup ? 'Set up your authenticator' : 'Verify your identity'}</h1>
  {#if data.verified}
    <p>Your authenticator is enabled and this administrator session is verified. Verification lasts up to 12 hours and is required again after a new sign-in.</p>
    <a class="button" href={resolve(data.next as "/")}>Continue to admin</a>
  {:else if data.needsSetup && !uri}
    <p>Administrator access requires a code from an authenticator app in addition to your normal sign-in.</p>
    <form onsubmit={enable}>
      {#if data.passwordRequired}<label>Current password<input type="password" bind:value={password} autocomplete="current-password" required /></label>{/if}
      <button type="submit" disabled={busy}>{busy ? 'Preparing…' : 'Set up authenticator'}</button>
    </form>
  {:else}
    {#if uri}
      <p>Scan this code in your authenticator app. The QR code is generated on your device.</p>
      {#if qr}<img src={qr} alt="Authenticator setup QR code" />{/if}
      <details><summary>Enter a setup key manually</summary><code>{secret}</code></details>
      <aside aria-label="Recovery codes">
        <h2>Save your recovery codes</h2>
        <p>Each code works once if you lose access to your authenticator. Store them privately, away from your sign-in details.</p>
        <ul>{#each backupCodes as backup (backup)}<li><code>{backup}</code></li>{/each}</ul>
        <button type="button" onclick={downloadCodes}>Download recovery codes</button>
        <label class="confirmation"><input type="checkbox" bind:checked={savedCodes} /> I have saved my recovery codes</label>
      </aside>
    {:else}<p>{recovery ? 'Enter one of your saved recovery codes. Each code works only once.' : 'Enter the current six-digit code from your authenticator app.'}</p>{/if}
    <form onsubmit={verify}>
      <label>{recovery ? 'Recovery code' : 'Authenticator code'}<input bind:value={code} inputmode={recovery ? 'text' : 'numeric'} autocomplete="one-time-code" pattern={recovery ? undefined : '[0-9]{6}'} maxlength={recovery ? 100 : 6} required /></label>
      <button type="submit" disabled={busy || Boolean(uri && !savedCodes)}>{busy ? 'Verifying…' : 'Verify and continue'}</button>
    </form>
    {#if !uri}<button type="button" onclick={()=> { recovery=!recovery
      code=''
      message='' }}>{recovery ? 'Use authenticator code' : 'Use a recovery code'}</button>{/if}
  {/if}
  {#if message}<p role="alert">{message}</p>{/if}
  <p><a href={resolve('/login?reauth=1')}>Sign in again</a></p>
</section>

<style>
  section { width: min(100%, 36rem); margin: auto; padding: 3rem 1.5rem; }
  h1 { font-size: 2rem; line-height: 1.1; text-wrap: balance; margin-bottom: 1rem; }
  p { color: var(--color-text-1); line-height: 1.55; }
  form { display: grid; gap: 1rem; margin-block: 1.5rem; }
  label { display: grid; gap: .5rem; font-size: .875rem; font-weight: 700; }
  input { width: 100%; min-height: 2.75rem; padding: .625rem .75rem; background: var(--color-bg-1); color: var(--color-text-0); border: 1px solid var(--color-border); border-radius: var(--radius-md); font: inherit; font-size: 1rem; caret-color: var(--color-accent); }
  button, .button { display: inline-flex; align-items: center; justify-content: center; min-height: 2.75rem; padding: .625rem 1rem; border: 1px solid var(--color-border); border-radius: var(--radius-md); font: inherit; font-weight: 700; color: var(--color-text-0); background: transparent; cursor: pointer; text-align: center; }
  button[type="submit"], .button { background: var(--color-accent); color: var(--color-bg-0); border-color: transparent; text-decoration: none; }
  button:hover:not(:disabled) { background: var(--color-bg-2); }
  button[type="submit"]:hover:not(:disabled), .button:hover { background: var(--color-accent-dim); }
  button:disabled { opacity: .5; cursor: not-allowed; }
  :is(button, input, a, summary):focus-visible { outline: .125rem solid var(--color-accent); outline-offset: .25rem; }
  a { color: var(--color-accent); text-underline-offset: .2em; }
  section > p:last-child { margin-top: 1.5rem; font-size: .875rem; }
  p[role="alert"] { margin-top: 1rem; color: var(--color-failed); }
  img { display: block; width: 16rem; max-width: 100%; height: auto; background: white; margin-block: 1.5rem; }
  aside { padding: 1.25rem; background: var(--color-bg-1); border-radius: var(--radius-lg); margin-block: 1.5rem; }
  h2 { font-family: var(--font-sans); font-size: 1.125rem; margin-bottom: .75rem; }
  aside p { font-size: .875rem; }
  ul { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: .5rem; padding: 0; margin-block: 1rem; list-style: none; }
  code { overflow-wrap: anywhere; font-family: var(--font-mono); font-size: .875rem; }
  .confirmation { display: flex; align-items: start; gap: .625rem; margin-top: 1rem; }
  .confirmation input { width: 1.125rem; min-height: auto; height: 1.125rem; flex-shrink: 0; accent-color: var(--color-accent); }
  summary { cursor: pointer; }
  .button { margin-top: 1.5rem; }
</style>
