<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getWailsBridge,
    isWailsV3Available,
    type TransferCenterJobDetail,
    type TransferCenterSnapshot,
  } from '../wails/wails-adapter.js';
  import {
    humanBytes,
    isLiveState,
    isTerminalState,
    stateLabel,
    stateTone,
  } from './transfer-center.js';

  const bridge = getWailsBridge();
  const desktop = isWailsV3Available() && bridge !== null;

  let snapshot = $state<TransferCenterSnapshot | null>(null);
  let loading = $state(false);
  let errorMessage = $state('');
  let expandedJobId = $state<string | null>(null);
  let detail = $state<TransferCenterJobDetail | null>(null);
  let detailLoading = $state(false);
  let actionMessage = $state('');
  let prunePreview = $state<string[] | null>(null);
  let pruning = $state(false);

  async function refresh() {
    if (!bridge) return;
    loading = true;
    errorMessage = '';
    try {
      snapshot = await bridge.transfer.transferCenterList();
    } catch (e) {
      errorMessage = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function toggleDetail(jobId: string) {
    if (expandedJobId === jobId) {
      expandedJobId = null;
      detail = null;
      return;
    }
    if (!bridge) return;
    expandedJobId = jobId;
    detail = null;
    detailLoading = true;
    try {
      detail = await bridge.transfer.transferCenterShow(jobId);
    } catch (e) {
      errorMessage = e instanceof Error ? e.message : String(e);
      expandedJobId = null;
    } finally {
      detailLoading = false;
    }
  }

  async function runAction(jobId: string, kind: 'cancel' | 'retry' | 'forget') {
    if (!bridge) return;
    actionMessage = '';
    errorMessage = '';
    try {
      if (kind === 'cancel') await bridge.transfer.transferCenterCancel(jobId);
      else if (kind === 'retry') await bridge.transfer.transferCenterRetry(jobId, []);
      else await bridge.transfer.transferCenterForget(jobId);
      expandedJobId = null;
      detail = null;
      await refresh();
      actionMessage =
        kind === 'cancel'
          ? 'Transfer cancelled.'
          : kind === 'retry'
            ? 'Failed targets re-queued.'
            : 'History forgotten.';
    } catch (e) {
      errorMessage = e instanceof Error ? e.message : String(e);
    }
  }

  async function previewPrune() {
    if (!bridge) return;
    pruning = true;
    errorMessage = '';
    try {
      const rep = await bridge.transfer.transferCenterPrune(0, true);
      prunePreview = rep.pruned;
    } catch (e) {
      errorMessage = e instanceof Error ? e.message : String(e);
    } finally {
      pruning = false;
    }
  }

  async function confirmPrune() {
    if (!bridge) return;
    pruning = true;
    errorMessage = '';
    try {
      const rep = await bridge.transfer.transferCenterPrune(0, false);
      prunePreview = null;
      actionMessage =
        rep.pruned.length === 0
          ? 'Nothing to prune.'
          : `Pruned ${rep.pruned.length} old transfer${rep.pruned.length === 1 ? '' : 's'}.`;
      await refresh();
    } catch (e) {
      errorMessage = e instanceof Error ? e.message : String(e);
    } finally {
      pruning = false;
    }
  }

  function retryAtLabel(iso?: string): string {
    if (!iso) return '';
    const t = new Date(iso);
    return Number.isNaN(t.getTime()) ? '' : t.toLocaleString();
  }

  onMount(() => {
    if (desktop) void refresh();
  });
</script>

<div class="tc">
  {#if !desktop}
    <div class="tc-empty">
      <h3>Transfer Center lives in the desktop app</h3>
      <p>
        The browser keeps no local outbox: queued and interrupted transfers are managed by the
        SendBeam desktop app or the <code>sendbeam outbox</code> CLI commands. This screen lights up when
        you open it in the desktop app.
      </p>
    </div>
  {:else}
    <div class="tc-toolbar">
      <button class="ghost" onclick={refresh} disabled={loading}>
        {loading ? 'Refreshing…' : 'Refresh'}
      </button>
      {#if prunePreview === null}
        <button class="ghost" onclick={previewPrune} disabled={pruning}>Prune old history…</button>
      {:else}
        <span class="muted">
          {prunePreview.length === 0
            ? 'Nothing past retention.'
            : `${prunePreview.length} transfer${prunePreview.length === 1 ? '' : 's'} past retention.`}
        </span>
        {#if prunePreview.length > 0}
          <button class="danger" onclick={confirmPrune} disabled={pruning}>
            {pruning ? 'Pruning…' : `Prune ${prunePreview.length}`}
          </button>
        {/if}
        <button class="ghost" onclick={() => (prunePreview = null)}>Cancel</button>
      {/if}
    </div>

    {#if errorMessage}
      <p class="tc-error" role="alert">{errorMessage}</p>
    {/if}
    {#if actionMessage}
      <p class="tc-ok" role="status">{actionMessage}</p>
    {/if}

    {#if snapshot === null && !loading}
      <p class="muted">No transfer data yet.</p>
    {:else if snapshot !== null}
      {#each snapshot.groups as group (group.state)}
        {#if group.jobs.length > 0}
          <section class="tc-group">
            <h3>
              <span class="tc-dot tone-{stateTone(group.state)}"></span>
              {stateLabel(group.state)}
              <span class="muted">({group.jobs.length})</span>
            </h3>
            {#each group.jobs as job (job.jobId)}
              <article class="tc-job">
                <button
                  class="tc-jobhead"
                  onclick={() => toggleDetail(job.jobId)}
                  aria-expanded={expandedJobId === job.jobId}
                >
                  <span class="tc-id">{job.shortJobId}</span>
                  <span class="muted">
                    {job.files} file{job.files === 1 ? '' : 's'} · {humanBytes(job.totalSize)} ·
                    {job.delivered}/{job.failed}/{job.recipients} delivered/failed/targets
                  </span>
                  {#if job.needsAttention}<span class="tc-flag">needs attention</span>{/if}
                  <span class="tc-caret">{expandedJobId === job.jobId ? '▾' : '▸'}</span>
                </button>
                {#if expandedJobId === job.jobId}
                  <div class="tc-detail">
                    {#if detailLoading}
                      <p class="muted">Loading…</p>
                    {:else if detail}
                      {@const d = detail}
                      {#if d.lastError}
                        <p class="tc-error">{d.lastError}</p>
                      {/if}
                      {#if d.nextRetryAt}
                        <p class="muted">Next retry: {retryAtLabel(d.nextRetryAt)}</p>
                      {/if}
                      {#if d.expiresAt}
                        <p class="muted">Expires: {retryAtLabel(d.expiresAt)}</p>
                      {/if}
                      {#if d.fileList.length > 0}
                        <p class="muted">
                          Files: {d.fileList
                            .slice(0, 5)
                            .map((f) => f.name)
                            .join(', ')}{d.fileList.length > 5
                            ? ` (+${d.fileList.length - 5} more)`
                            : ''}
                        </p>
                      {/if}
                      <ul class="tc-targets">
                        {#each d.attempts as a (a.deviceId)}
                          <li>
                            <span class="tc-dot tone-{stateTone(a.state)}"></span>
                            <strong>{a.label || a.shortDeviceId}</strong>
                            <span class="muted">
                              {stateLabel(a.state)} · try {a.attempts}/{a.maxAttempts}
                              {#if a.bytesTransferred}· {humanBytes(a.bytesTransferred)} sent{/if}
                            </span>
                            {#if a.lastError}<span class="tc-err">{a.lastError}</span>{/if}
                            {#if a.state === 'queued' && a.nextRetryAt}
                              <span class="muted">retry {retryAtLabel(a.nextRetryAt)}</span>
                            {/if}
                          </li>
                        {/each}
                      </ul>
                      <div class="tc-actions">
                        {#if isLiveState(d.state)}
                          <button class="ghost" onclick={() => runAction(d.jobId, 'cancel')}
                            >Cancel transfer</button
                          >
                        {/if}
                        {#if d.failed > 0}
                          <button class="ghost" onclick={() => runAction(d.jobId, 'retry')}
                            >Retry failed targets</button
                          >
                        {/if}
                        {#if isTerminalState(d.state)}
                          <button class="ghost danger" onclick={() => runAction(d.jobId, 'forget')}
                            >Forget history</button
                          >
                        {/if}
                      </div>
                    {/if}
                  </div>
                {/if}
              </article>
            {/each}
          </section>
        {/if}
      {/each}
      {#if snapshot.summary.total === 0}
        <p class="muted">No transfers yet. Queue one with <code>sendbeam outbox enqueue</code>.</p>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .tc {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .tc-toolbar {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-wrap: wrap;
  }
  .tc-empty {
    border: 1px dashed var(--border, #3a3a3a);
    border-radius: 12px;
    padding: 1.5rem;
  }
  .tc-group h3 {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0.25rem 0 0.5rem;
    font-size: 1rem;
  }
  .tc-dot {
    width: 0.6rem;
    height: 0.6rem;
    border-radius: 50%;
    display: inline-block;
    background: #888;
  }
  .tone-ok {
    background: #34c77b;
  }
  .tone-warn {
    background: #e0a23c;
  }
  .tone-bad {
    background: #e05252;
  }
  .tone-info {
    background: #4aa8ff;
  }
  .tone-muted {
    background: #888;
  }
  .tc-job {
    border: 1px solid var(--border, #2e2e2e);
    border-radius: 10px;
    margin-bottom: 0.5rem;
    overflow: hidden;
  }
  .tc-jobhead {
    width: 100%;
    display: flex;
    gap: 0.75rem;
    align-items: center;
    background: none;
    border: none;
    padding: 0.6rem 0.8rem;
    cursor: pointer;
    color: inherit;
    text-align: left;
  }
  .tc-id {
    font-family: ui-monospace, monospace;
    font-weight: 600;
  }
  .tc-flag {
    font-size: 0.75rem;
    color: #e0a23c;
    border: 1px solid #e0a23c;
    border-radius: 999px;
    padding: 0.05rem 0.5rem;
  }
  .tc-caret {
    margin-left: auto;
    color: #888;
  }
  .tc-detail {
    border-top: 1px solid var(--border, #2e2e2e);
    padding: 0.6rem 0.8rem;
  }
  .tc-targets {
    list-style: none;
    margin: 0.5rem 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .tc-targets li {
    display: flex;
    gap: 0.5rem;
    align-items: baseline;
    flex-wrap: wrap;
  }
  .tc-err {
    color: #e05252;
    font-size: 0.85rem;
  }
  .tc-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: 0.5rem;
  }
  .tc-error {
    color: #e05252;
  }
  .tc-ok {
    color: #34c77b;
  }
  .muted {
    color: #999;
    font-size: 0.9rem;
  }
  .ghost {
    cursor: pointer;
  }
  .danger {
    color: #e05252;
  }
  code {
    font-family: ui-monospace, monospace;
  }
</style>
