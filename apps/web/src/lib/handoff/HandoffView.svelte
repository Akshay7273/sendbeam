<!--
  V20-PR06: verified text/link handoff receiver view.

  The handoff payload is rendered with literal text bindings only — no HTML
  execution, no automatic linkification, no automatic opening, no clipboard
  surveillance. Copy, Save, and Open are all deliberate button clicks:
  - Copy writes the payload to the clipboard exactly once, inside the click handler.
  - Save downloads the payload as a .txt file, inside the click handler.
  - Open only appears for links that validate as http/https with a host, and opens
    the validated URL in a new window with noopener/noreferrer, inside the click handler.
-->
<script lang="ts">
  import type { TransferOutcome } from '../session/transfer.js';

  let { handoff }: { handoff: NonNullable<TransferOutcome['handoff']> } = $props();

  const MAX_PREVIEW_CHARS = 4000;

  /** Re-validate the payload on the receiver: the digest proves the sender sent
   *  these bytes, not that they are a safe link. Open is offered only for
   *  whitespace-free http(s) URLs with a host. */
  function validateLink(text: string): URL | null {
    const trimmed = text.trim();
    if (trimmed.length === 0 || /\s/.test(trimmed)) return null;
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (!url.hostname) return null;
    return url;
  }

  let copyState = $state<'idle' | 'copied' | 'failed'>('idle');

  async function copyText(): Promise<void> {
    try {
      await navigator.clipboard.writeText(handoff.text);
      copyState = 'copied';
    } catch {
      copyState = 'failed';
    }
  }

  function saveText(): void {
    const blob = new Blob([handoff.text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement('a');
      a.href = url;
      a.download = handoff.contentKind === 'link' ? 'link.txt' : 'text.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    }
  }

  function openLink(url: URL): void {
    // Deliberate receiver action only: opened from the click handler, never
    // automatically, with no opener relationship back to this app.
    window.open(url.toString(), '_blank', 'noopener,noreferrer');
  }

  const isLink = $derived(handoff.contentKind === 'link');
  const validUrl = $derived(isLink ? validateLink(handoff.text) : null);
  const preview = $derived(
    handoff.text.length > MAX_PREVIEW_CHARS
      ? `${handoff.text.slice(0, MAX_PREVIEW_CHARS)}…`
      : handoff.text,
  );
</script>

<div class="handoff">
  <p class="muted">
    Received
    <strong>{isLink ? 'a link' : 'a text note'}</strong> — verified.
  </p>
  <div class="handoff-body" aria-live="polite">{preview}</div>
  {#if isLink && !validUrl}
    <p class="warn">This link was not in a valid http(s) format, so it cannot be opened.</p>
  {/if}
  <div class="handoff-actions">
    <button class="primary" onclick={copyText}>
      {copyState === 'copied'
        ? 'Copied'
        : copyState === 'failed'
          ? 'Copy failed — select the text'
          : 'Copy'}
    </button>
    <button class="ghost" onclick={saveText}>Save</button>
    {#if validUrl}
      <button class="ghost" onclick={() => openLink(validUrl)}>Open</button>
    {/if}
  </div>
  <p class="hint muted">Nothing was opened, copied, or saved automatically.</p>
</div>

<style>
  .handoff {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    width: 100%;
  }
  .handoff-body {
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 16rem;
    overflow: auto;
    padding: 0.75rem 0.9rem;
    border: 1px solid var(--line, #26314a);
    border-radius: 0.6rem;
    background: rgba(255, 255, 255, 0.03);
    font-size: 0.95rem;
    line-height: 1.5;
  }
  .handoff-actions {
    display: flex;
    gap: 0.6rem;
    flex-wrap: wrap;
  }
  .warn {
    color: var(--warn, #f0b429);
    font-size: 0.9rem;
  }
  .hint {
    font-size: 0.85rem;
  }
</style>
